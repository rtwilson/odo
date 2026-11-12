package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"example.org/odo/internal/resources"
	"golang.org/x/net/publicsuffix"
)

// These limits apply only to the future vendor-mode store, not SessionStore.
const (
	UpstreamMaxJars          = 256
	UpstreamMaxJarsPerParent = 32
	UpstreamMaxCookies       = 64
	UpstreamMaxCookieBytes   = 64 * 1024
	UpstreamMaxCookieSize    = 4 * 1024
	UpstreamMaxPolicies      = 1024
	UpstreamMaxCookieDomains = 64
	UpstreamJarIdleTimeout   = 30 * time.Minute
)

var (
	ErrCookieAuthorization = errors.New("upstream cookie authorization denied")
	ErrCookiePolicy        = errors.New("upstream cookie policy is unavailable or unsupported")
)

// CookieJarCapacityError is suitable for mapping to a generic HTTP 503 before
// fetching. It deliberately contains no patron, resource, or cookie identifiers.
type CookieJarCapacityError struct{}

func (*CookieJarCapacityError) Error() string { return "upstream cookie capacity exhausted" }

// CookieAuthorization must come from a fresh server-side parent/session and
// actual-target policy check, never browser selectors or a grant alone. The
// deadline must include parent absolute/idle expiry. Anonymous means the current
// request matched an authorized anonymous exception, even if a grant is present.
type CookieAuthorization struct {
	ParentSessionID   string
	ParentSessionHash string
	ParentExpires     time.Time
	ResourceID        string
	PolicyGeneration  uint64
	Anonymous         bool
}

// CookieAuthorizer rechecks live session/account/grant eligibility, current
// winning resource, method and target authorization on each call. Database or
// policy errors must be returned, not interpreted as anonymous access. It is a
// trusted integration boundary, not an authentication implementation or cache.
type CookieAuthorizer func(context.Context, *url.URL, string) (CookieAuthorization, error)

type upstreamJarKey struct {
	parent, hash, resource string
	generation             uint64
}

type upstreamCookiePolicy struct {
	enabled    bool
	domains    []string
	generation uint64
	// routing fingerprints the resource's domain rules, so a change to where
	// the resource may reach also retires its jars.
	routing string
}

type upstreamResourceJar struct {
	cookies             []upstreamCookie
	expires, lastAccess time.Time
}

// UpstreamCookieJars is a bounded process-memory manager used by the internal
// grant coordinator, not HTTP routes or the existing path/query proxy. Only cookie origin
// host/path metadata is retained; request URLs and credentials are not stored.
type UpstreamCookieJars struct {
	mu         sync.Mutex
	deployment []string
	policies   map[string]upstreamCookiePolicy
	jars       map[upstreamJarKey]*upstreamResourceJar
	generation uint64
	ready      bool
	// Once revisioned snapshots are used, unversioned installation is disabled.
	policyRevision    int64
	versionedPolicies bool
	now               func() time.Time
}

func NewUpstreamCookieJars(deployment HostRoutingConfig) (*UpstreamCookieJars, error) {
	if deployment.CentralHostname() == "" || deployment.ProxyBaseDomain() == "" {
		return nil, ErrCookiePolicy
	}
	return &UpstreamCookieJars{
		deployment: []string{deployment.CentralHostname(), deployment.ProxyBaseDomain()},
		policies:   make(map[string]upstreamCookiePolicy), jars: make(map[upstreamJarKey]*upstreamResourceJar), now: time.Now,
	}, nil
}

// ReplacePolicies installs a complete trusted active-resource snapshot. Call it
// after EVERY committed resource change, including disable/remove/reversion,
// before allowing requests using that snapshot. Unchanged policies keep jars;
// changed/removed policies retire all their jars. Request authorization must use
// PolicyGeneration from the SAME snapshot. Invalid snapshots disable the entire
// store and discard jars until a valid snapshot is installed.
// Once ReplacePolicySnapshot is used, this unversioned entry point is rejected.
func (m *UpstreamCookieJars) ReplacePolicies(active []resources.Resource) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.versionedPolicies {
		return ErrCookiePolicy
	}
	return m.replacePoliciesLocked(active, false, false)
}

// ReplacePolicySnapshot installs active policies from one trusted database
// snapshot. The next consecutive revision keeps jars of resources whose cookie
// policy and domain rules are unchanged, so editing one resource (or only its
// name) does not sign every patron out of every vendor. A revision that skips
// ahead may hide an intermediate change and reversion, so it renews ALL
// generations even for identical JSON, permanently retiring those jars. Older revisions
// cannot replace newer state. Invalid policy data clears jars and retains the
// highest revision seen; recovery requires that revision or newer, never legacy
// mode. Rejected stale/unversioned calls leave current valid state intact.
// The future caller must coordinate authorization against this SAME snapshot.
func (m *UpstreamCookieJars) ReplacePolicySnapshot(revision int64, active []resources.Resource) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	versioned := m.versionedPolicies
	m.versionedPolicies = true
	if revision < 0 {
		return m.discardPoliciesLocked(ErrCookiePolicy)
	}
	if versioned && revision < m.policyRevision {
		return ErrCookiePolicy
	}
	renew := !versioned || (revision != m.policyRevision && revision != m.policyRevision+1)
	unchanged := versioned && revision == m.policyRevision && m.ready
	m.policyRevision = revision
	return m.replacePoliciesLocked(active, renew, unchanged)
}

func (m *UpstreamCookieJars) discardPoliciesLocked(err error) error {
	m.ready = false
	for key := range m.jars {
		m.dropJar(key)
	}
	clear(m.policies)
	return err
}

// InvalidatePolicies retires all jars and outstanding exchanges after a trusted
// coordinator's snapshot lookup/publication failure. Keep the revision floor
// and generation counter: recovery must never resurrect retired cookies.
func (m *UpstreamCookieJars) InvalidatePolicies() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.discardPoliciesLocked(ErrCookiePolicy)
}

func (m *UpstreamCookieJars) replacePoliciesLocked(active []resources.Resource, renew, unchanged bool) error {
	failed := func(err error) error {
		return m.discardPoliciesLocked(err)
	}
	if len(active) > UpstreamMaxPolicies {
		return failed(&CookieJarCapacityError{})
	}
	if unchanged && len(active) != len(m.policies) {
		return failed(ErrCookiePolicy)
	}
	policies := make(map[string]upstreamCookiePolicy, len(active))
	for _, resource := range active {
		if resource.ID == "" || len(resource.ID) > 128 || (resource.Status != "" && resource.Status != "active") {
			return failed(ErrCookiePolicy)
		}
		if _, duplicate := policies[resource.ID]; duplicate {
			return failed(ErrCookiePolicy)
		}
		policy, err := m.normalizePolicy(resource.CookiePolicy)
		if err != nil {
			return failed(err)
		}
		old, found := m.policies[resource.ID]
		routing, err := json.Marshal(resource.Domains)
		if err != nil {
			return failed(ErrCookiePolicy)
		}
		policy.routing = string(routing)
		same := found && old.enabled == policy.enabled && slices.Equal(old.domains, policy.domains) && old.routing == policy.routing
		if unchanged && !same {
			return failed(ErrCookiePolicy)
		}
		if same && !renew {
			policy.generation = old.generation
		} else {
			if m.generation == ^uint64(0) {
				return failed(ErrCookiePolicy)
			}
			m.generation++
			policy.generation = m.generation
		}
		policies[strings.Clone(resource.ID)] = policy
	}
	for key := range m.jars {
		if policy, found := policies[key.resource]; !found || policy.generation != key.generation {
			m.dropJar(key)
		}
	}
	m.policies, m.ready = policies, true
	m.cleanupLocked(m.now())
	return nil
}

func (m *UpstreamCookieJars) PolicyGeneration(resourceID string) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	policy, found := m.policies[resourceID]
	if !m.ready || !found {
		return 0, ErrCookiePolicy
	}
	return policy.generation, nil
}

// UpstreamCookieExchange binds one explicitly authorized request/response pair.
// It is not an http.CookieJar: http.Client's implicit cookie/redirect processing
// must not bypass per-request authorization or response-header stripping.
type UpstreamCookieExchange struct {
	manager   *UpstreamCookieJars
	authorize CookieAuthorizer
	target    url.URL
	method    string
	auth      CookieAuthorization
	jar       *upstreamResourceJar
}

// PrepareRequest clones an already constructed upstream request, removes ALL
// browser Cookie headers, reauthorizes its actual URL/method, and reserves jar
// capacity before any fetch. The future caller must use a client with Jar=nil,
// no automatic redirects, and the existing validated-IP transport.
func (m *UpstreamCookieJars) PrepareRequest(request *http.Request, authorize CookieAuthorizer) (*http.Request, *UpstreamCookieExchange, error) {
	if request == nil || request.URL == nil || authorize == nil {
		return nil, nil, ErrCookieAuthorization
	}
	target := *request.URL
	if !m.validTarget(&target) {
		return nil, nil, ErrCookieAuthorization
	}
	auth, err := authorize(request.Context(), cloneCookieURL(target), request.Method)
	if err != nil {
		return nil, nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	m.cleanupLocked(now)
	policy, key, err := m.authorization(auth, now)
	if err != nil {
		return nil, nil, err
	}
	exchange := &UpstreamCookieExchange{manager: m, authorize: authorize, target: target, method: request.Method, auth: auth}
	prepared := request.Clone(request.Context())
	if prepared.Header == nil {
		prepared.Header = make(http.Header)
	}
	removeCookieHeaders(prepared.Header, "Cookie", "Cookie2")
	if auth.Anonymous || !policy.enabled {
		return prepared, exchange, nil
	}
	jar := m.jars[key]
	if jar == nil {
		parents := 0
		for existing := range m.jars {
			// Include different hashes for the same parent ID in the bound.
			if existing.parent == key.parent {
				parents++
			}
		}
		if len(m.jars) >= UpstreamMaxJars || parents >= UpstreamMaxJarsPerParent {
			return nil, nil, &CookieJarCapacityError{}
		}
		jar = &upstreamResourceJar{}
		key.parent, key.hash, key.resource = strings.Clone(key.parent), strings.Clone(key.hash), strings.Clone(key.resource)
		m.jars[key] = jar
	}
	jar.expires, jar.lastAccess = auth.ParentExpires, now
	exchange.jar = jar
	// Enforce the current policy on delivery too, even though a policy
	// generation change has already retired the previous records.
	jar.cookies = slices.DeleteFunc(jar.cookies, func(cookie upstreamCookie) bool {
		return !m.permittedCookie(policy, &cookie.origin, &cookie.cookie)
	})
	standard := cookieJarFor(jar.cookies)
	for _, cookie := range standard.Cookies(&target) {
		prepared.AddCookie(cookie)
	}
	return prepared, exchange, nil
}

// StoreResponse removes upstream Set-Cookie even on failure or anonymous access.
// It reauthorizes before storing and rejects changed parent/resource/generation
// bindings and retired leases. Never copy response headers before this call.
func (e *UpstreamCookieExchange) StoreResponse(ctx context.Context, response *http.Response) error {
	if response == nil {
		return ErrCookieAuthorization
	}
	// Keep raw headers only for this call; parse one at a time under the limits.
	var values []string
	for name, headers := range response.Header {
		if strings.EqualFold(name, "Set-Cookie") {
			for _, value := range headers {
				if len(values) < 4*UpstreamMaxCookies {
					values = append(values, value)
				}
			}
		}
	}
	removeCookieHeaders(response.Header, "Set-Cookie", "Set-Cookie2")
	if e == nil || e.manager == nil || (response.Request != nil && (response.Request.URL == nil || *response.Request.URL != e.target || response.Request.Method != e.method)) {
		return ErrCookieAuthorization
	}
	auth, err := e.authorize(ctx, cloneCookieURL(e.target), e.method)
	if err != nil {
		return err
	}
	m := e.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	m.cleanupLocked(now)
	policy, key, err := m.authorization(auth, now)
	if err != nil {
		return err
	}
	if auth.ParentSessionID != e.auth.ParentSessionID || auth.ParentSessionHash != e.auth.ParentSessionHash || auth.ResourceID != e.auth.ResourceID || auth.PolicyGeneration != e.auth.PolicyGeneration || auth.Anonymous != e.auth.Anonymous {
		return ErrCookieAuthorization
	}
	if auth.Anonymous || !policy.enabled {
		return nil
	}
	jar := m.jars[key]
	if jar == nil || jar != e.jar {
		return ErrCookieAuthorization
	}
	jar.expires, jar.lastAccess = auth.ParentExpires, now
	for _, value := range values {
		// Include a separate metadata bound so huge Path/extension attributes
		// cannot cause unbounded retained state or expensive cookie parsing.
		if len(value) > 2*UpstreamMaxCookieSize {
			continue
		}
		cookie, err := http.ParseSetCookie(value)
		if err != nil {
			continue
		}
		m.storeCookie(jar, policy, &e.target, cookie, now)
	}
	return nil
}

func (m *UpstreamCookieJars) authorization(auth CookieAuthorization, now time.Time) (upstreamCookiePolicy, upstreamJarKey, error) {
	policy, found := m.policies[auth.ResourceID]
	if !m.ready || !found || auth.PolicyGeneration == 0 || auth.PolicyGeneration != policy.generation {
		return upstreamCookiePolicy{}, upstreamJarKey{}, ErrCookieAuthorization
	}
	if auth.Anonymous {
		if auth.ParentSessionID != "" || auth.ParentSessionHash != "" || !auth.ParentExpires.IsZero() {
			return upstreamCookiePolicy{}, upstreamJarKey{}, ErrCookieAuthorization
		}
	} else if auth.ParentSessionID == "" || len(auth.ParentSessionID) > 128 || auth.ParentSessionHash == "" || len(auth.ParentSessionHash) > 128 || !now.Before(auth.ParentExpires) {
		return upstreamCookiePolicy{}, upstreamJarKey{}, ErrCookieAuthorization
	}
	return policy, upstreamJarKey{auth.ParentSessionID, auth.ParentSessionHash, auth.ResourceID, auth.PolicyGeneration}, nil
}

// RetireParent releases contents and invalidates existing exchanges. Fresh
// requests must still revalidate durable revocation; this is NOT a tombstone or
// authorization cache. No unbounded list of revoked parents is retained.
func (m *UpstreamCookieJars) RetireParent(parentID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key := range m.jars {
		if key.parent == parentID {
			m.dropJar(key)
		}
	}
}

// Len reports how many jars are allocated, for bounds and lifecycle checks.
// It exposes no parent, resource or cookie data.
func (m *UpstreamCookieJars) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.jars)
}

// Cleanup can be called by lifecycle maintenance; operations also sweep the
// bounded maps. There is no background goroutine or persistent browsing state.
func (m *UpstreamCookieJars) Cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked(m.now())
}

func (m *UpstreamCookieJars) cleanupLocked(now time.Time) {
	for key, jar := range m.jars {
		if !now.Before(jar.expires) || now.Sub(jar.lastAccess) >= UpstreamJarIdleTimeout {
			m.dropJar(key)
			continue
		}
		jar.cookies = slices.DeleteFunc(jar.cookies, func(cookie upstreamCookie) bool { return !cookie.expires.IsZero() && !now.Before(cookie.expires) })
	}
}

func (m *UpstreamCookieJars) dropJar(key upstreamJarKey) {
	// Outstanding exchanges may hold this pointer. Release contents there too;
	// the absent map entry prevents a late response from repopulating the jar.
	m.jars[key].cookies = nil
	delete(m.jars, key)
}

func cloneCookieURL(target url.URL) *url.URL { return &target }

func removeCookieHeaders(headers http.Header, names ...string) {
	for name := range headers {
		for _, forbidden := range names {
			if strings.EqualFold(name, forbidden) {
				delete(headers, name)
			}
		}
	}
}

// Rebuild from the bounded retained records rather than relying on cookiejar's
// private maps for capacity accounting. Go still implements sending order,
// domain/path/Secure matching and public-suffix protection. No hidden jar or
// expired-cookie metadata accumulates between operations.
func cookieJarFor(cookies []upstreamCookie) *cookiejar.Jar {
	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	for _, stored := range cookies {
		cookie := stored.cookie
		jar.SetCookies(&stored.origin, []*http.Cookie{&cookie})
	}
	return jar
}
