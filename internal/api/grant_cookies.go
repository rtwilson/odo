package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"example.org/odo/internal/db"
	"example.org/odo/internal/proxy"
	"example.org/odo/internal/resources"
)

// grantCookieCoordinator owns one jar manager and shares the handoff's Store.
// The experimental handoff runtime constructs exactly one and uses it for vendor
// content delivery (handoff_delivery.go); it has no transport itself. Every operation validates DNS outside the
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
	// Never carry server-request fields upstream: a browser request's Host is the
	// proxy authority, and net/http clients reject a set RequestURI.
	upstream.Host, upstream.RequestURI = "", ""
	if err := c.validateTarget(request.Context(), &target); err != nil {
		return nil, nil, err
	}
	var prepared *http.Request
	var exchange *proxy.UpstreamCookieExchange
	// Capture only the prepare-time parent. The manager retains this authorizer
	// for response checks, so later calls must not write shared state.
	var active atomic.Pointer[db.Session]
	err := c.handoff.server.store.WithResourceAccess(func() error {
		var err error
		prepared, exchange, err = c.jars.PrepareRequest(upstream, func(ctx context.Context, actual *url.URL, method string) (proxy.CookieAuthorization, error) {
			// This callback is retained by the manager for response validation;
			// it captures credentials/binding only, never a resource snapshot,
			// resource decision or previously observed generation.
			auth, parent, err := c.authorizeParent(ctx, token, authority, actual, method)
			if err == nil {
				active.CompareAndSwap(nil, &parent)
			}
			return auth, err
		})
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	if err := c.recordActivity(active.Load()); err != nil {
		return nil, nil, err
	}
	return prepared, &grantCookieExchange{coordinator: c, exchange: exchange, target: target}, nil
}

// recordActivity keeps an actively proxied patron's central session from idling
// out, using the central session touch throttle. It runs after the resource
// guard and only for a parent this request just validated, so it can never
// revive an expired, idle or revoked session. Failure fails the request closed,
// as a failed central touch does.
func (c *grantCookieCoordinator) recordActivity(parent *db.Session) error {
	if parent == nil || parent.ID == "" {
		return proxy.ErrCookieAuthorization
	}
	// Match central touches and TouchSession itself, which use the wall clock.
	seen, err := time.Parse(time.RFC3339, parent.LastSeenAt)
	if err == nil && time.Now().UTC().Sub(seen) < sessionTouchInterval() {
		return nil
	}
	if err := c.handoff.server.store.TouchSession(parent.ID); err != nil {
		return errors.New("record proxied session activity failed")
	}
	return nil
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
	if err != nil {
		// DNS failure or an unsafe address: never authorized, but reported as an
		// upstream problem rather than a policy denial. No address is retained.
		return errVendorTargetUnsafe
	}
	// The caller must construct a canonical upstream URL. Never validate one
	// normalized target and then prepare a different request URL.
	if validated == nil || *validated != *target {
		return proxy.ErrCookieAuthorization
	}
	return nil
}

// errVendorTargetUnsafe means the target failed DNS or IP safety validation.
var errVendorTargetUnsafe = errors.New("vendor target failed DNS or address safety validation")

// authorize is called only by the private manager exchanges inside the Store
// resource guard, after validateTarget. It does no DNS/network work and no
// database writes; prepareRequest records parent activity after the guard.
// Parent validity is read live; as in handoff validation, a concurrent
// revocation after that read may finish the current operation, but the next
// operation rechecks.
func (c *grantCookieCoordinator) authorize(ctx context.Context, token, authority string, target *url.URL, method string) (proxy.CookieAuthorization, error) {
	auth, _, err := c.authorizeParent(ctx, token, authority, target, method)
	return auth, err
}

// authorizeParent also returns the validated parent session (zero on failure)
// so the caller can record patron activity outside the resource guard.
func (c *grantCookieCoordinator) authorizeParent(ctx context.Context, token, authority string, target *url.URL, method string) (proxy.CookieAuthorization, db.Session, error) {
	if err := ctx.Err(); err != nil {
		return proxy.CookieAuthorization{}, db.Session{}, err
	}
	// One instant for the whole decision, so grant lookup and deadline checks
	// cannot disagree about whether the grant is still live.
	now := c.now()
	snapshot, err := c.handoff.server.store.ResourceSnapshot()
	if err != nil {
		c.jars.InvalidatePolicies()
		return proxy.CookieAuthorization{}, db.Session{}, errors.New("cookie resource snapshot unavailable")
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
		return proxy.CookieAuthorization{}, db.Session{}, err
	}
	grant, parent, err := c.handoff.grantParent(token, authority, now)
	if err != nil {
		if grant.binding.parentSessionID != "" {
			c.jars.RetireParent(grant.binding.parentSessionID)
		}
		return proxy.CookieAuthorization{}, db.Session{}, err
	}
	if target == nil || target.Scheme != "https" || target.Hostname() != grant.binding.hostname {
		return proxy.CookieAuthorization{}, db.Session{}, proxy.ErrCookieAuthorization
	}
	result := resources.TestURL(target.String(), snapshot.Resources)
	if !result.Allowed || result.Action != "proxy" || result.ResourceID == "" || !resources.MethodAllowed(result, method) {
		return proxy.CookieAuthorization{}, db.Session{}, proxy.ErrCookieAuthorization
	}
	if !now.Before(grant.expires) {
		// A single grant ending is not parent invalidity: deny only, leaving the
		// parent's jars for its other live grants and resources.
		return proxy.CookieAuthorization{}, db.Session{}, proxy.ErrCookieAuthorization
	}
	validated, err := grantParentAuthorization(parent, result.ResourceID, now)
	if err != nil {
		c.jars.RetireParent(grant.binding.parentSessionID)
		return proxy.CookieAuthorization{}, db.Session{}, proxy.ErrCookieAuthorization
	}
	generation, err := c.jars.PolicyGeneration(result.ResourceID)
	if err != nil {
		c.jars.InvalidatePolicies()
		return proxy.CookieAuthorization{}, db.Session{}, err
	}
	if result.AnonymousRuleMatched {
		// An explicitly public winning rule is cookieless even with a grant.
		// This grant-bound coordinator never falls back here after grant failure.
		return proxy.CookieAuthorization{Anonymous: true, ResourceID: result.ResourceID, PolicyGeneration: generation}, parent, nil
	}
	// The jar deadline is the parent's idle/absolute deadline, not the grant's
	// fixed TTL: the manager's 30-minute inactivity timeout ends idle jars, and
	// a patron's later handoff (new grant) keeps an active jar's cookies.
	return proxy.CookieAuthorization{
		ParentSessionID: validated.parentSessionID, ParentSessionHash: validated.parentSessionHash,
		ParentExpires: validated.parentExpires, ResourceID: validated.resourceID, PolicyGeneration: generation,
	}, parent, nil
}
