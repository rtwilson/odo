package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"example.org/odo/internal/proxy"
	"example.org/odo/internal/resources"
)

// grantCookieCoordinator owns one jar manager and shares the handoff's Store.
// It has no routes or transport. Every operation validates DNS outside the
// resource guard, then keeps fresh snapshot publication, grant authorization
// and jar access inside that guard. No authorization decision is cached.
// All resource writers must use this same Store instance.
type grantCookieCoordinator struct {
	handoff *handoffSecurity
	jars    *proxy.UpstreamCookieJars
	now     func() time.Time
}

func newGrantCookieCoordinator(h *handoffSecurity) (*grantCookieCoordinator, error) {
	if h == nil || h.server == nil || h.server.store == nil || h.state == nil {
		return nil, proxy.ErrCookieAuthorization
	}
	jars, err := proxy.NewUpstreamCookieJars(h.config)
	if err != nil {
		return nil, err
	}
	return &grantCookieCoordinator{handoff: h, jars: jars, now: time.Now}, nil
}

// grantCookieExchange deliberately keeps the raw manager exchange private so
// callers cannot store a response without the resource guard and DNS check.
// Like the underlying exchange, its target exists only for this in-flight pair.
type grantCookieExchange struct {
	coordinator *grantCookieCoordinator
	exchange    *proxy.UpstreamCookieExchange
	target      url.URL
}

func (c *grantCookieCoordinator) prepareRequest(request *http.Request, token, authority string) (*http.Request, *grantCookieExchange, error) {
	if request == nil || request.URL == nil {
		return nil, nil, proxy.ErrCookieAuthorization
	}
	target := *request.URL
	upstream := request.Clone(request.Context())
	upstream.URL = &target
	if err := c.validateTarget(request.Context(), &target); err != nil {
		return nil, nil, err
	}
	var prepared *http.Request
	var exchange *proxy.UpstreamCookieExchange
	err := c.handoff.server.store.WithResourceAccess(func() error {
		var err error
		prepared, exchange, err = c.jars.PrepareRequest(upstream, func(ctx context.Context, actual *url.URL, method string) (proxy.CookieAuthorization, error) {
			// This callback is retained by the manager for response validation;
			// it captures credentials/binding only, never a resource snapshot,
			// resource decision or previously observed generation.
			return c.authorize(ctx, token, authority, actual, method)
		})
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return prepared, &grantCookieExchange{coordinator: c, exchange: exchange, target: target}, nil
}

// storeResponse must succeed before any response headers/body are forwarded.
// Strip cookie headers on the wrapper's failure paths too, including DNS errors.
func (e *grantCookieExchange) storeResponse(ctx context.Context, response *http.Response) error {
	if response == nil {
		return proxy.ErrCookieAuthorization
	}
	defer func() {
		for name := range response.Header {
			if strings.EqualFold(name, "Set-Cookie") || strings.EqualFold(name, "Set-Cookie2") {
				delete(response.Header, name)
			}
		}
	}()
	if e == nil || e.coordinator == nil || e.exchange == nil {
		return proxy.ErrCookieAuthorization
	}
	c := e.coordinator
	if err := c.validateTarget(ctx, &e.target); err != nil {
		return err
	}
	return c.handoff.server.store.WithResourceAccess(func() error {
		return e.exchange.StoreResponse(ctx, response)
	})
}

func (c *grantCookieCoordinator) validateTarget(ctx context.Context, target *url.URL) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if target == nil || target.Scheme != "https" || c.handoff.server.ipLookup == nil {
		return proxy.ErrCookieAuthorization
	}
	validated, err := proxy.ValidateTargetURL(ctx, target.String(), c.handoff.server.ipLookup)
	// The caller must construct a canonical upstream URL. Never validate one
	// normalized target and then prepare a different request URL.
	if err != nil || validated == nil || *validated != *target {
		return proxy.ErrCookieAuthorization
	}
	return nil
}

// authorize is called only by the private manager exchanges inside the Store
// resource guard, after validateTarget. It does no DNS/network work. Parent
// validity is read live; as in handoff validation, a concurrent revocation after
// that read may finish the current operation, but the next operation rechecks.
func (c *grantCookieCoordinator) authorize(ctx context.Context, token, authority string, target *url.URL, method string) (proxy.CookieAuthorization, error) {
	if err := ctx.Err(); err != nil {
		return proxy.CookieAuthorization{}, err
	}
	snapshot, err := c.handoff.server.store.ResourceSnapshot()
	if err != nil {
		c.jars.InvalidatePolicies()
		return proxy.CookieAuthorization{}, errors.New("cookie resource snapshot unavailable")
	}
	active := make([]resources.Resource, 0, len(snapshot.Resources))
	for _, item := range snapshot.Resources {
		if item.Status == "active" {
			active = append(active, item)
		}
	}
	if err := c.jars.ReplacePolicySnapshot(snapshot.Revision, active); err != nil {
		// Even a stale publication (which the manager rejects without clearing
		// newer state) makes this coordinator unavailable until a valid read.
		c.jars.InvalidatePolicies()
		return proxy.CookieAuthorization{}, err
	}
	grant, parent, err := c.handoff.grantParent(token, authority, c.now())
	if err != nil {
		if grant.binding.parentSessionID != "" {
			c.jars.RetireParent(grant.binding.parentSessionID)
		}
		return proxy.CookieAuthorization{}, err
	}
	if target == nil || target.Scheme != "https" || target.Hostname() != grant.binding.hostname {
		return proxy.CookieAuthorization{}, proxy.ErrCookieAuthorization
	}
	result := resources.TestURL(target.String(), snapshot.Resources)
	if !result.Allowed || result.Action != "proxy" || result.ResourceID == "" || !resources.MethodAllowed(result, method) {
		return proxy.CookieAuthorization{}, proxy.ErrCookieAuthorization
	}
	now := c.now()
	validated, err := grantParentAuthorization(parent, result.ResourceID, now)
	if err != nil || !now.Before(grant.expires) {
		c.jars.RetireParent(grant.binding.parentSessionID)
		return proxy.CookieAuthorization{}, proxy.ErrCookieAuthorization
	}
	generation, err := c.jars.PolicyGeneration(result.ResourceID)
	if err != nil {
		c.jars.InvalidatePolicies()
		return proxy.CookieAuthorization{}, err
	}
	if result.AnonymousRuleMatched {
		// An explicitly public winning rule is cookieless even with a grant.
		// This grant-bound coordinator never falls back here after grant failure.
		return proxy.CookieAuthorization{Anonymous: true, ResourceID: result.ResourceID, PolicyGeneration: generation}, nil
	}
	expires := validated.parentExpires
	if grant.expires.Before(expires) {
		expires = grant.expires
	}
	return proxy.CookieAuthorization{
		ParentSessionID: validated.parentSessionID, ParentSessionHash: validated.parentSessionHash,
		ParentExpires: expires, ResourceID: validated.resourceID, PolicyGeneration: generation,
	}, nil
}
