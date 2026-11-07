package proxy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"example.org/odo/internal/resources"
)

type upstreamCookieFixture struct {
	m     *UpstreamCookieJars
	now   time.Time
	items []resources.Resource
}

func newUpstreamCookieFixture(t *testing.T) *upstreamCookieFixture {
	t.Helper()
	config, err := NewHostRoutingConfig("https://login.library.example", "proxy.library.example")
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewUpstreamCookieJars(config)
	if err != nil {
		t.Fatal(err)
	}
	f := &upstreamCookieFixture{m: m, now: time.Now().UTC(), items: []resources.Resource{
		{ID: "a", Status: "active", CookiePolicy: resources.CookiePolicy{Enabled: true}},
		{ID: "b", Status: "active", CookiePolicy: resources.CookiePolicy{Enabled: true}},
	}}
	m.now = func() time.Time { return f.now }
	f.install(t)
	return f
}

func (f *upstreamCookieFixture) install(t *testing.T) {
	t.Helper()
	if err := f.m.ReplacePolicies(f.items); err != nil {
		t.Fatal(err)
	}
}

func (f *upstreamCookieFixture) auth(t *testing.T, parent, resource string) CookieAuthorization {
	t.Helper()
	generation, err := f.m.PolicyGeneration(resource)
	if err != nil {
		t.Fatal(err)
	}
	return CookieAuthorization{ParentSessionID: parent, ParentSessionHash: "verified-hash-" + parent, ParentExpires: f.now.Add(2 * time.Hour), ResourceID: resource, PolicyGeneration: generation}
}

func cookieAuthorization(auth CookieAuthorization) CookieAuthorizer {
	return func(context.Context, *url.URL, string) (CookieAuthorization, error) { return auth, nil }
}

func prepareCookieRequest(t *testing.T, m *UpstreamCookieJars, raw string, authorize CookieAuthorizer) (*http.Request, *UpstreamCookieExchange, error) {
	t.Helper()
	request, err := http.NewRequest("GET", raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Cookie", "central=browser-secret; grant=browser-grant")
	request.Header["cookie"] = []string{"noncanonical=secret"}
	request.Header.Set("Cookie2", "legacy=secret")
	return m.PrepareRequest(request, authorize)
}

func storeCookieResponse(t *testing.T, exchange *UpstreamCookieExchange, cookies ...string) error {
	t.Helper()
	response := &http.Response{Header: http.Header{"Set-Cookie": cookies, "set-cookie": {"noncanonical=blocked; Domain=library.example"}, "Set-Cookie2": {"legacy=blocked"}}}
	err := exchange.StoreResponse(context.Background(), response)
	for name := range response.Header {
		if strings.EqualFold(name, "Set-Cookie") || strings.EqualFold(name, "Set-Cookie2") {
			t.Fatal("upstream cookies were not stripped")
		}
	}
	return err
}

func expectUpstreamCookies(t *testing.T, f *upstreamCookieFixture, auth CookieAuthorization, raw, expected string) {
	t.Helper()
	request, _, err := prepareCookieRequest(t, f.m, raw, cookieAuthorization(auth))
	if err != nil {
		t.Fatal(err)
	}
	if got := request.Header.Get("Cookie"); got != expected || request.Header.Get("Cookie2") != "" {
		t.Fatalf("unexpected upstream cookies: got %q, expected %q", got, expected)
	}
}

func TestUpstreamCookiesSessionResourceAndHashIsolation(t *testing.T) {
	f := newUpstreamCookieFixture(t)
	auth := f.auth(t, "alice-login-1", "a")
	_, exchange, err := prepareCookieRequest(t, f.m, "https://www.vendor.example/", cookieAuthorization(auth))
	if err != nil {
		t.Fatal(err)
	}
	if err := storeCookieResponse(t, exchange, "vendor=private; Path=/; Secure; HttpOnly"); err != nil {
		t.Fatal(err)
	}
	expectUpstreamCookies(t, f, auth, "https://www.vendor.example/", "vendor=private")
	// A programmatically constructed request may legitimately have nil headers.
	target, _ := url.Parse("https://www.vendor.example/")
	prepared, _, err := f.m.PrepareRequest(&http.Request{Method: "GET", URL: target}, cookieAuthorization(auth))
	if err != nil || prepared.Header.Get("Cookie") != "vendor=private" {
		t.Fatalf("nil-header request failed: %v", err)
	}
	for _, other := range []CookieAuthorization{
		f.auth(t, "bob-login-1", "a"),
		f.auth(t, "alice-login-2", "a"),
		f.auth(t, "alice-login-1", "b"),
	} {
		expectUpstreamCookies(t, f, other, "https://www.vendor.example/", "")
	}
	changedHash := auth
	changedHash.ParentSessionHash = "different-verified-hash"
	expectUpstreamCookies(t, f, changedHash, "https://www.vendor.example/", "")
	expectUpstreamCookies(t, f, auth, "https://sibling.vendor.example/", "")
}

func TestUpstreamCookiesDomainPolicyAndStandardMatching(t *testing.T) {
	f := newUpstreamCookieFixture(t)
	f.items[0].CookiePolicy.AllowedCookieDomains = []string{".VENDOR.EXAMPLE"}
	f.install(t)
	auth := f.auth(t, "alice", "a")
	_, exchange, err := prepareCookieRequest(t, f.m, "https://www.vendor.example/books/start", cookieAuthorization(auth))
	if err != nil {
		t.Fatal(err)
	}
	if err := storeCookieResponse(t, exchange,
		"shared=ok; Domain=.vendor.example; Path=/books; Secure",
		"host=ok", // Default path is /books, host-only.
		"bad=blocked; Domain=other.example", "suffix=blocked; Domain=example",
		"wild=blocked; Domain=*.vendor.example", "ip=blocked; Domain=127.0.0.1",
		"deployment=blocked; Domain=library.example", "trailing=blocked; Domain=vendor.example.",
	); err != nil {
		t.Fatal(err)
	}
	expectUpstreamCookies(t, f, auth, "https://www.vendor.example/books/next", "shared=ok; host=ok")
	expectUpstreamCookies(t, f, auth, "https://cdn.vendor.example/books/next", "shared=ok")
	expectUpstreamCookies(t, f, auth, "http://cdn.vendor.example/books/next", "")
	expectUpstreamCookies(t, f, auth, "https://cdn.vendor.example/bookshop", "")
	expectUpstreamCookies(t, f, auth, "https://notvendor.example/books/next", "")
	expectUpstreamCookies(t, f, f.auth(t, "alice", "b"), "https://cdn.vendor.example/books/next", "")
}

func TestUpstreamCookiesEmptyAllowlistIsHostOnly(t *testing.T) {
	f := newUpstreamCookieFixture(t)
	auth := f.auth(t, "alice", "a")
	_, exchange, err := prepareCookieRequest(t, f.m, "https://www.vendor.example/", cookieAuthorization(auth))
	if err != nil {
		t.Fatal(err)
	}
	if err := storeCookieResponse(t, exchange, "domain=no; Domain=www.vendor.example", "host=yes"); err != nil {
		t.Fatal(err)
	}
	expectUpstreamCookies(t, f, auth, "https://www.vendor.example/", "host=yes")
}

func TestUpstreamCookiesInvalidPoliciesFailClosed(t *testing.T) {
	for _, domain := range []string{"com", "co.uk", "github.io", "127.0.0.1", "*.vendor.example", "https://vendor.example", "library.example", "login.library.example", "child.proxy.library.example", "vendor.example:443"} {
		t.Run(domain, func(t *testing.T) {
			f := newUpstreamCookieFixture(t)
			auth := f.auth(t, "alice", "a")
			f.items[0].CookiePolicy.AllowedCookieDomains = []string{domain}
			if err := f.m.ReplacePolicies(f.items); !errors.Is(err, ErrCookiePolicy) {
				t.Fatalf("invalid policy accepted: %v", err)
			}
			if _, _, err := prepareCookieRequest(t, f.m, "https://vendor.example/", cookieAuthorization(auth)); err == nil {
				t.Fatal("old policy remained usable after failed installation")
			}
		})
	}
	f := newUpstreamCookieFixture(t)
	f.items[0].CookiePolicy.JarScope = "parent"
	if err := f.m.ReplacePolicies(f.items); !errors.Is(err, ErrCookiePolicy) {
		t.Fatal("unsupported jar scope accepted")
	}
	if _, err := NewUpstreamCookieJars(HostRoutingConfig{}); err == nil {
		t.Fatal("missing deployment exclusions accepted")
	}
}

func TestUpstreamCookiesDisabledAndAnonymousAreCookieless(t *testing.T) {
	f := newUpstreamCookieFixture(t)
	auth := f.auth(t, "alice", "a")
	_, exchange, _ := prepareCookieRequest(t, f.m, "https://vendor.example/", cookieAuthorization(auth))
	if err := storeCookieResponse(t, exchange, "private=authenticated"); err != nil {
		t.Fatal(err)
	}
	anon := CookieAuthorization{Anonymous: true, ResourceID: "a", PolicyGeneration: auth.PolicyGeneration}
	request, anonymous, err := prepareCookieRequest(t, f.m, "https://vendor.example/", cookieAuthorization(anon))
	if err != nil || request.Header.Get("Cookie") != "" {
		t.Fatalf("anonymous request borrowed a jar: %v", err)
	}
	if err := storeCookieResponse(t, anonymous, "private=anonymous"); err != nil {
		t.Fatal(err)
	}
	expectUpstreamCookies(t, f, auth, "https://vendor.example/", "private=authenticated")
	if len(f.m.jars) != 1 {
		t.Fatal("anonymous request allocated a jar")
	}
	f.items[0].CookiePolicy.Enabled = false
	f.install(t)
	auth = f.auth(t, "alice", "a")
	request, disabled, err := prepareCookieRequest(t, f.m, "https://vendor.example/", cookieAuthorization(auth))
	if err != nil || request.Header.Get("Cookie") != "" {
		t.Fatalf("disabled request carried cookies: %v", err)
	}
	if err := storeCookieResponse(t, disabled, "private=disabled"); err != nil || len(f.m.jars) != 0 {
		t.Fatalf("disabled policy stored state: %v", err)
	}
}

func TestUpstreamCookiesPolicyRetirementAndReversion(t *testing.T) {
	f := newUpstreamCookieFixture(t)
	auth := f.auth(t, "alice", "a")
	_, exchange, _ := prepareCookieRequest(t, f.m, "https://vendor.example/", cookieAuthorization(auth))
	if err := storeCookieResponse(t, exchange, "private=old"); err != nil {
		t.Fatal(err)
	}
	f.install(t) // Unchanged snapshot does not log out upstream.
	expectUpstreamCookies(t, f, auth, "https://vendor.example/", "private=old")
	f.items[0].CookiePolicy.AllowedCookieDomains = []string{"vendor.example"}
	f.install(t)
	if _, _, err := prepareCookieRequest(t, f.m, "https://vendor.example/", cookieAuthorization(auth)); err == nil {
		t.Fatal("stale policy generation accepted")
	}
	if err := storeCookieResponse(t, exchange, "late=old"); err == nil || len(exchange.jar.cookies) != 0 {
		t.Fatal("retired exchange retained or repopulated cookies")
	}
	f.items[0].CookiePolicy.AllowedCookieDomains = nil
	f.install(t)
	reverted := f.auth(t, "alice", "a")
	if reverted.PolicyGeneration == auth.PolicyGeneration {
		t.Fatal("policy reversion reused an old generation")
	}
	expectUpstreamCookies(t, f, reverted, "https://vendor.example/", "")
	f.items = f.items[1:] // Remove resource completely.
	f.install(t)
	if _, _, err := prepareCookieRequest(t, f.m, "https://vendor.example/", cookieAuthorization(reverted)); err == nil {
		t.Fatal("removed resource accepted")
	}
}

func TestUpstreamCookiesReauthorizeAndRetireParent(t *testing.T) {
	for _, cause := range []string{"logout", "revocation", "password", "roles", "disable", "lock", "delete", "database"} {
		t.Run(cause, func(t *testing.T) {
			f := newUpstreamCookieFixture(t)
			auth := f.auth(t, "alice", "a")
			eligible := true
			authorize := func(context.Context, *url.URL, string) (CookieAuthorization, error) {
				if !eligible {
					return CookieAuthorization{}, ErrCookieAuthorization
				}
				return auth, nil
			}
			_, exchange, _ := prepareCookieRequest(t, f.m, "https://vendor.example/", authorize)
			if err := storeCookieResponse(t, exchange, "private=old"); err != nil {
				t.Fatal(err)
			}
			eligible = false // Integration must derive this from live durable state.
			f.m.RetireParent(auth.ParentSessionID)
			if err := storeCookieResponse(t, exchange, "late=old"); err == nil {
				t.Fatal("revoked parent accepted a response")
			}
			if _, _, err := prepareCookieRequest(t, f.m, "https://vendor.example/", authorize); err == nil || len(f.m.jars) != 0 {
				t.Fatal("denied parent allocated a jar")
			}
			eligible = true // Even a caller error cannot revive the old contents.
			if err := storeCookieResponse(t, exchange, "late=old"); err == nil || len(exchange.jar.cookies) != 0 {
				t.Fatal("retired exchange revived")
			}
			expectUpstreamCookies(t, f, auth, "https://vendor.example/", "")
		})
	}
}

func TestUpstreamCookiesAuthorizationChangesFailClosed(t *testing.T) {
	f := newUpstreamCookieFixture(t)
	auth := f.auth(t, "alice", "a")
	authorize := func(_ context.Context, target *url.URL, method string) (CookieAuthorization, error) {
		if target.Hostname() != "vendor.example" || method != "GET" {
			return CookieAuthorization{}, ErrCookieAuthorization
		}
		return auth, nil
	}
	_, exchange, err := prepareCookieRequest(t, f.m, "https://vendor.example/actual?private=search", authorize)
	if err != nil {
		t.Fatal(err)
	}
	auth = f.auth(t, "alice", "b") // Actual winning resource changed midflight.
	if err := storeCookieResponse(t, exchange, "private=wrong-resource"); err == nil {
		t.Fatal("changed winner accepted")
	}
	for _, invalid := range []CookieAuthorization{{}, {ResourceID: "a"}, {Anonymous: true, ResourceID: "a", PolicyGeneration: auth.PolicyGeneration, ParentSessionID: "browser-selector"}} {
		if _, _, err := prepareCookieRequest(t, f.m, "https://vendor.example/", cookieAuthorization(invalid)); err == nil {
			t.Fatal("missing/manipulated authorization accepted")
		}
	}
	if _, _, err := prepareCookieRequest(t, f.m, "https://vendor.example/", nil); err == nil {
		t.Fatal("missing authorizer accepted")
	}
	for _, raw := range []string{"https://login.library.example/", "https://h.proxy.library.example/", "https://127.0.0.1/", "https://com/"} {
		if _, _, err := prepareCookieRequest(t, f.m, raw, cookieAuthorization(f.auth(t, "alice", "a"))); err == nil {
			t.Fatal("invalid or deployment target accepted")
		}
	}
}

func TestUpstreamCookiesCapacityDoesNotEvictLivePatrons(t *testing.T) {
	f := newUpstreamCookieFixture(t)
	for i := 0; i < UpstreamMaxJars; i++ {
		auth := f.auth(t, fmt.Sprintf("parent-%d", i), "a")
		_, exchange, err := prepareCookieRequest(t, f.m, "https://vendor.example/", cookieAuthorization(auth))
		if err != nil {
			t.Fatal(err)
		}
		if err := storeCookieResponse(t, exchange, "kept=yes"); err != nil {
			t.Fatal(err)
		}
	}
	_, _, err := prepareCookieRequest(t, f.m, "https://vendor.example/", cookieAuthorization(f.auth(t, "extra", "a")))
	var capacity *CookieJarCapacityError
	if !errors.As(err, &capacity) || len(f.m.jars) != UpstreamMaxJars {
		t.Fatalf("expected bounded typed capacity error: %v", err)
	}
	expectUpstreamCookies(t, f, f.auth(t, "parent-0", "a"), "https://vendor.example/", "kept=yes")
	f.m.RetireParent("parent-1")
	expectUpstreamCookies(t, f, f.auth(t, "extra", "a"), "https://vendor.example/", "")
}

func TestUpstreamCookiesPerParentAndMetadataCapacity(t *testing.T) {
	f := newUpstreamCookieFixture(t)
	f.items = nil
	for i := 0; i <= UpstreamMaxJarsPerParent; i++ {
		f.items = append(f.items, resources.Resource{ID: fmt.Sprintf("r%d", i), CookiePolicy: resources.CookiePolicy{Enabled: true}})
	}
	f.install(t)
	for i := 0; i < UpstreamMaxJarsPerParent; i++ {
		expectUpstreamCookies(t, f, f.auth(t, "alice", fmt.Sprintf("r%d", i)), "https://vendor.example/", "")
	}
	var capacity *CookieJarCapacityError
	if _, _, err := prepareCookieRequest(t, f.m, "https://vendor.example/", cookieAuthorization(f.auth(t, "alice", "r32"))); !errors.As(err, &capacity) {
		t.Fatalf("expected parent capacity error: %v", err)
	}
	f.items = make([]resources.Resource, UpstreamMaxPolicies+1)
	if err := f.m.ReplacePolicies(f.items); !errors.As(err, &capacity) || len(f.m.jars) != 0 || len(f.m.policies) != 0 {
		t.Fatalf("policy metadata was not bounded: %v", err)
	}
}

func TestUpstreamCookiesCookieBoundsAndReplacement(t *testing.T) {
	f := newUpstreamCookieFixture(t)
	auth := f.auth(t, "alice", "a")
	_, exchange, _ := prepareCookieRequest(t, f.m, "https://vendor.example/", cookieAuthorization(auth))
	if err := storeCookieResponse(t, exchange,
		"oversize="+strings.Repeat("x", UpstreamMaxCookieSize),
		"metadata=value; Path=/"+strings.Repeat("x", 2*UpstreamMaxCookieSize),
	); err != nil || len(exchange.jar.cookies) != 0 {
		t.Fatalf("oversize cookie accepted into empty jar: %v", err)
	}
	var values []string
	for i := 0; i < UpstreamMaxCookies+1; i++ {
		values = append(values, fmt.Sprintf("c%d=value; Path=/", i))
	}
	values = append(values, "oversize="+strings.Repeat("x", UpstreamMaxCookieSize), "metadata=value; Path=/"+strings.Repeat("x", 2*UpstreamMaxCookieSize))
	if err := storeCookieResponse(t, exchange, values...); err != nil || len(exchange.jar.cookies) != UpstreamMaxCookies {
		t.Fatalf("cookie count bound failed: %v", err)
	}
	if err := storeCookieResponse(t, exchange, "c0=replaced; Path=/", "c1=gone; Max-Age=0; Path=/"); err != nil || len(exchange.jar.cookies) != UpstreamMaxCookies-1 {
		t.Fatalf("replacement/deletion at capacity failed: %v", err)
	}
	// Fresh jar exercises the byte limit independently of the count limit.
	f.m.RetireParent("alice")
	_, exchange, _ = prepareCookieRequest(t, f.m, "https://vendor.example/", cookieAuthorization(auth))
	values = nil
	for i := 0; i < 40; i++ {
		values = append(values, fmt.Sprintf("large%d=%s", i, strings.Repeat("v", 4000)))
	}
	if err := storeCookieResponse(t, exchange, values...); err != nil {
		t.Fatal(err)
	}
	bytes := 0
	for _, stored := range exchange.jar.cookies {
		bytes += len(stored.cookie.Name) + len(stored.cookie.Value)
	}
	if bytes > UpstreamMaxCookieBytes || len(exchange.jar.cookies) != 16 {
		t.Fatalf("cookie byte bound failed: bytes=%d count=%d", bytes, len(exchange.jar.cookies))
	}
}

func TestUpstreamCookiesExpiryCleanupAndRestart(t *testing.T) {
	f := newUpstreamCookieFixture(t)
	auth := f.auth(t, "alice", "a")
	_, exchange, _ := prepareCookieRequest(t, f.m, "https://vendor.example/books/", cookieAuthorization(auth))
	if err := storeCookieResponse(t, exchange, "short=yes; Max-Age=1", "past=no; Expires="+f.now.Add(-time.Hour).Format(http.TimeFormat), "session=yes; Path=/"); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(time.Second)
	expectUpstreamCookies(t, f, auth, "https://vendor.example/books/", "session=yes")
	if len(exchange.jar.cookies) != 1 {
		t.Fatal("expired cookie metadata retained")
	}
	f.now = f.now.Add(UpstreamJarIdleTimeout)
	f.m.Cleanup()
	if len(f.m.jars) != 0 || len(exchange.jar.cookies) != 0 {
		t.Fatal("idle cleanup retained jar contents")
	}
	_, exchange, _ = prepareCookieRequest(t, f.m, "https://vendor.example/", cookieAuthorization(auth))
	f.now = auth.ParentExpires
	if _, _, err := prepareCookieRequest(t, f.m, "https://vendor.example/", cookieAuthorization(auth)); err == nil || len(f.m.jars) != 0 {
		t.Fatal("expired parent accepted or retained")
	}
	fresh := newUpstreamCookieFixture(t)
	expectUpstreamCookies(t, fresh, fresh.auth(t, "alice", "a"), "https://vendor.example/", "")
}

func TestUpstreamCookiesConcurrentAccessAndRetirement(t *testing.T) {
	f := newUpstreamCookieFixture(t)
	auth := f.auth(t, "alice", "a")
	var workers sync.WaitGroup
	for i := 0; i < 32; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			for j := 0; j < 10; j++ {
				_, exchange, err := prepareCookieRequest(t, f.m, "https://vendor.example/", cookieAuthorization(auth))
				if err != nil {
					t.Error(err)
					return
				}
				err = storeCookieResponse(t, exchange, fmt.Sprintf("c%d=value; Path=/", i))
				if err != nil && !errors.Is(err, ErrCookieAuthorization) {
					t.Error(err)
				}
				if j%3 == 0 {
					f.m.RetireParent("alice")
				}
			}
		}(i)
	}
	workers.Wait()
	f.m.RetireParent("alice")
	if len(f.m.jars) != 0 {
		t.Fatal("final retirement retained jars")
	}
}

func TestUpstreamCookiesMetadataAndExpirySemantics(t *testing.T) {
	f := newUpstreamCookieFixture(t)
	auth := f.auth(t, "alice", "a")
	_, exchange, _ := prepareCookieRequest(t, f.m, "https://vendor.example/books/start?private=search", cookieAuthorization(auth))
	if err := storeCookieResponse(t, exchange,
		"expires=yes; Path=/; Expires="+f.now.Add(2*time.Second).Format(http.TimeFormat),
		"priority=yes; Path=/; Max-Age=10; Expires="+f.now.Add(-time.Hour).Format(http.TimeFormat),
		"bounded=yes; Path=/; Max-Age=9223372036854775807; Unused=private-extension",
	); err != nil {
		t.Fatal(err)
	}
	for _, stored := range exchange.jar.cookies {
		if stored.origin.Path != "" || stored.origin.RawQuery != "" || stored.cookie.Raw != "" || len(stored.cookie.Unparsed) != 0 {
			t.Fatal("retained unnecessary raw metadata")
		}
		if stored.cookie.Name == "bounded" && stored.expires != auth.ParentExpires {
			t.Fatal("large Max-Age was not bounded to parent expiry")
		}
	}
	f.now = f.now.Add(3 * time.Second)
	expectUpstreamCookies(t, f, auth, "https://vendor.example/", "priority=yes; bounded=yes")
	f.now = f.now.Add(7 * time.Second)
	expectUpstreamCookies(t, f, auth, "https://vendor.example/", "bounded=yes")
	_, largePath, err := prepareCookieRequest(t, f.m, "https://vendor.example/"+strings.Repeat("p", UpstreamMaxCookieSize)+"/start", cookieAuthorization(auth))
	if err != nil {
		t.Fatal(err)
	}
	if err := storeCookieResponse(t, largePath, "derived=no"); err != nil || len(largePath.jar.cookies) != 1 {
		t.Fatalf("oversize default path was retained: %v", err)
	}
}

func TestUpstreamCookiesResponseBindingAndAuthorizationFailure(t *testing.T) {
	f := newUpstreamCookieFixture(t)
	auth := f.auth(t, "alice", "a")
	calls := 0
	lookupError := errors.New("database lookup failed")
	authorize := func(_ context.Context, target *url.URL, method string) (CookieAuthorization, error) {
		calls++
		if target.String() != "https://vendor.example/actual" || method != "GET" {
			t.Fatal("authorizer did not receive the actual request URL/method")
		}
		if calls > 1 {
			return CookieAuthorization{}, lookupError
		}
		return auth, nil
	}
	request, exchange, err := prepareCookieRequest(t, f.m, "https://vendor.example/actual", authorize)
	if err != nil || request.Header.Get("Cookie") != "" {
		t.Fatalf("request preparation failed: %v", err)
	}
	if err := storeCookieResponse(t, exchange, "private=denied"); !errors.Is(err, lookupError) || len(exchange.jar.cookies) != 0 {
		t.Fatalf("response authorization failure was not propagated: %v", err)
	}
	_, exchange, _ = prepareCookieRequest(t, f.m, "https://vendor.example/actual", cookieAuthorization(auth))
	other, _ := http.NewRequest("GET", "https://other.vendor.example/actual", nil)
	response := &http.Response{Header: http.Header{"Set-Cookie": {"private=wrong-host"}}, Request: other}
	if err := exchange.StoreResponse(context.Background(), response); err == nil || response.Header.Get("Set-Cookie") != "" {
		t.Fatal("implicit redirect response was accepted or leaked a cookie")
	}
}

func TestUpstreamCookiesPolicyNormalizationAndMetadataLimits(t *testing.T) {
	f := newUpstreamCookieFixture(t)
	f.items[0].CookiePolicy = resources.CookiePolicy{Enabled: true, JarScope: " RESOURCE ", AllowedCookieDomains: []string{".VENDOR.EXAMPLE", "vendor.example"}}
	f.install(t)
	auth := f.auth(t, "alice", "a")
	f.items[0].CookiePolicy.JarScope = ""
	f.items[0].CookiePolicy.AllowedCookieDomains = []string{"vendor.example"}
	f.install(t)
	current := f.auth(t, "alice", "a")
	if current.PolicyGeneration != auth.PolicyGeneration {
		t.Fatal("equivalent normalized policy changed generation")
	}
	f.items[0].CookiePolicy.AllowedCookieDomains = make([]string, UpstreamMaxCookieDomains+1)
	if err := f.m.ReplacePolicies(f.items); !errors.Is(err, ErrCookiePolicy) {
		t.Fatal("domain metadata limit was not enforced")
	}
	f.items[0].CookiePolicy.AllowedCookieDomains = nil
	f.install(t)
	current = f.auth(t, "alice", "a")
	current.ParentSessionID = strings.Repeat("p", 129)
	if _, _, err := prepareCookieRequest(t, f.m, "https://vendor.example/", cookieAuthorization(current)); err == nil {
		t.Fatal("parent metadata limit was not enforced")
	}
}
