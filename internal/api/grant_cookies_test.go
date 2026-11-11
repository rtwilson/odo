package api

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"example.org/odo/internal/auth/local"
	"example.org/odo/internal/config"
	"example.org/odo/internal/db"
	"example.org/odo/internal/proxy"
	"example.org/odo/internal/resources"
)

type grantCookieFixture struct {
	securityFixture
	c     *grantCookieCoordinator
	token string
	item  resources.Resource
}

func newGrantCookieFixture(t *testing.T) *grantCookieFixture {
	t.Helper()
	f := &grantCookieFixture{securityFixture: newSecurityFixture(t)}
	var err error
	f.item, _, err = f.h.server.store.GetResource("vendor")
	if err != nil {
		t.Fatal(err)
	}
	f.item.CookiePolicy.Enabled = true
	if err := f.h.server.store.UpsertResource(f.item); err != nil {
		t.Fatal(err)
	}
	f.token = f.grant(t)
	f.c, err = newGrantCookieCoordinator(f.h)
	if err != nil {
		t.Fatal(err)
	}
	f.c.now = func() time.Time { return f.now }
	return f
}

func (f *grantCookieFixture) prepare(t *testing.T) (*http.Request, *grantCookieExchange) {
	t.Helper()
	request, exchange, err := f.c.prepareRequest(httptest.NewRequest("GET", f.target, nil), f.token, f.authority)
	if err != nil {
		t.Fatal(err)
	}
	return request, exchange
}

func grantCookieResponse(exchange *grantCookieExchange, value string) error {
	response := &http.Response{Header: http.Header{"sEt-CoOkIe": {value}, "Set-Cookie2": {"browser=forbidden"}}}
	err := exchange.storeResponse(context.Background(), response)
	if len(response.Header) != 0 {
		return errors.New("response retained cookie headers")
	}
	return err
}

func TestGrantCookiesRoundTripAndLiveAuthorization(t *testing.T) {
	f := newGrantCookieFixture(t)
	parent, _, _ := f.h.server.store.GetSession(local.SessionIDFromToken(f.central))
	request := httptest.NewRequest("GET", f.target, nil)
	request.Header = http.Header{"cOoKiE": {"browser=secret"}, "Cookie2": {"session=untrusted"}}
	prepared, exchange, err := f.c.prepareRequest(request, f.token, f.authority)
	if err != nil || len(prepared.Header) != 0 || len(request.Header) != 2 {
		t.Fatalf("browser cookie boundary failed: %v", err)
	}
	if err := grantCookieResponse(exchange, "vendor=private; Secure; Path=/"); err != nil {
		t.Fatal(err)
	}
	prepared, _ = f.prepare(t)
	if prepared.Header.Get("Cookie") != "vendor=private" {
		t.Fatal("authorized request did not receive its vendor cookie")
	}
	// The callback's result is built from the live parent and current winner.
	target, _ := url.Parse(f.target)
	var auth proxy.CookieAuthorization
	if err := f.h.server.store.WithResourceAccess(func() error {
		var err error
		auth, err = f.c.authorize(context.Background(), f.token, f.authority, target, "GET")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if auth.ParentSessionID != parent.ID || auth.ParentSessionHash != parent.SessionHash || auth.ResourceID != "vendor" || auth.PolicyGeneration == 0 || auth.Anonymous || auth.ParentExpires.After(f.now.Add(handoffGrantTTL)) {
		t.Fatal("authorization did not use the verified parent, winner and grant deadline")
	}
	after, _, _ := f.h.server.store.GetSession(parent.ID)
	if after.LastSeenAt != parent.LastSeenAt {
		t.Fatal("cookie authorization touched session activity")
	}
}

func TestGrantCookiesRejectInvalidLiveState(t *testing.T) {
	for _, kind := range []string{
		"token", "authority", "target", "method", "disabled resource", "deleted resource", "changed domains", "blocked",
		"revoked", "password", "disabled account", "locked account", "deleted account", "roles", "auth version", "session hash",
		"grant expiry", "idle expiry", "absolute expiry", "logout", "session lookup", "registry lookup", "dns",
	} {
		t.Run(kind, func(t *testing.T) {
			f := newGrantCookieFixture(t)
			_, exchange := f.prepare(t)
			if err := grantCookieResponse(exchange, "vendor=old; Path=/"); err != nil {
				t.Fatal(err)
			}
			parent, _, _ := f.h.server.store.GetSession(local.SessionIDFromToken(f.central))
			target, method := f.target, "GET"
			var err error
			switch kind {
			case "token":
				f.token = "invalid"
			case "authority":
				other, registerErr := f.h.server.store.RegisterProxyHostname("other.example", "odo.example", "proxy.example")
				if registerErr != nil {
					t.Fatal(registerErr)
				}
				f.authority = other.Label + ".proxy.example"
			case "target":
				target = "https://other.example/"
			case "method":
				method = "DELETE"
			case "disabled resource", "changed domains", "blocked":
				if kind == "disabled resource" {
					f.item.Status = "disabled"
				} else if kind == "changed domains" {
					f.item.Domains = []resources.DomainRule{{Host: "other.example"}}
				} else {
					f.item.Domains = []resources.DomainRule{{Host: "vendor.example", Behavior: "block"}}
				}
				err = f.h.server.store.UpsertResource(f.item)
			case "deleted resource":
				_, err = f.h.server.store.DeleteResource(f.item.ID)
			case "revoked":
				err = f.h.server.store.RevokeSession(parent.ID)
			case "password":
				_, err = f.h.server.store.SetUserPassword(parent.UserID, "new-hash")
			case "disabled account", "locked account":
				_, _, err = f.h.server.store.SetUserStatus(parent.UserID, strings.Fields(kind)[0])
			case "deleted account":
				_, err = f.h.server.store.DeleteUser(parent.UserID, "")
			case "roles":
				_, _, err = f.h.server.store.PatchUser(parent.UserID, db.UserPatch{Roles: []string{"admin"}})
			case "auth version":
				_, err = f.control.Exec(`UPDATE users SET auth_version = auth_version + 1`)
			case "session hash":
				_, err = f.control.Exec(`UPDATE sessions SET session_hash = 'different'`)
			case "grant expiry":
				f.now = f.now.Add(handoffGrantTTL)
			case "idle expiry", "absolute expiry":
				f.now = f.now.Truncate(time.Second).Add(time.Second)
				if kind == "idle expiry" {
					_, err = f.control.Exec(`UPDATE sessions SET last_seen_at = ?`, f.now.Add(-sessionIdleTimeout()).Format(time.RFC3339))
				} else {
					_, err = f.control.Exec(`UPDATE sessions SET expires_at = ?`, f.now.Format(time.RFC3339))
				}
			case "logout":
				assertLogoutCleared(t, requestLogout(f.h.server, &http.Cookie{Name: "__Host-odo_session", Value: f.central}), "__Host-")
			case "session lookup":
				_, err = f.control.Exec(`ALTER TABLE sessions RENAME TO unavailable_sessions`)
			case "registry lookup":
				_, err = f.control.Exec(`ALTER TABLE proxy_hostnames RENAME TO unavailable_hostnames`)
			case "dns":
				f.h.server.ipLookup = func(context.Context, string) ([]net.IPAddr, error) {
					return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			prepared, rejected, err := f.c.prepareRequest(httptest.NewRequest(method, target, nil), f.token, f.authority)
			if err == nil || prepared != nil || rejected != nil {
				t.Fatal("invalid live state prepared a request")
			}
			// Token/authority/target/method mutations above belong to the new
			// request, not the outstanding exchange. Durable mutations apply to both.
			if kind != "token" && kind != "authority" && kind != "target" && kind != "method" {
				if err := grantCookieResponse(exchange, "late=forbidden; Path=/"); err == nil {
					t.Fatal("invalid live state accepted response cookies")
				}
			}
		})
	}
}

func TestGrantCookiesRevisionChangesRetireExchanges(t *testing.T) {
	for _, kind := range []string{"identical", "policy reversion", "disable enable", "delete recreate", "winning resource"} {
		t.Run(kind, func(t *testing.T) {
			f := newGrantCookieFixture(t)
			_, old := f.prepare(t)
			if err := grantCookieResponse(old, "old=private; Path=/"); err != nil {
				t.Fatal(err)
			}
			generation, _ := f.c.jars.PolicyGeneration(f.item.ID)
			changed := f.item
			switch kind {
			case "policy reversion", "disable enable":
				if kind == "policy reversion" {
					changed.CookiePolicy.Enabled = false
				} else {
					changed.Status = "disabled"
				}
				if err := f.h.server.store.UpsertResource(changed); err != nil {
					t.Fatal(err)
				}
			case "delete recreate":
				if _, err := f.h.server.store.DeleteResource(f.item.ID); err != nil {
					t.Fatal(err)
				}
			case "winning resource":
				// Both resources cover this host. Preserve the existing sorted
				// resource matching, without allowing the grant to choose a jar.
				f.item.ID = "a-winner"
			}
			if err := f.h.server.store.UpsertResource(f.item); err != nil {
				t.Fatal(err)
			}
			// No request ran between change and reversion. The persisted revision
			// must still retire the old response and its stored cookies.
			if err := grantCookieResponse(old, "late=forbidden; Path=/"); err == nil {
				t.Fatal("response survived a resource revision change")
			}
			prepared, fresh := f.prepare(t)
			current, err := f.c.jars.PolicyGeneration(f.item.ID)
			if err != nil || current == generation || prepared.Header.Get("Cookie") != "" {
				t.Fatal("new snapshot reused a retired jar")
			}
			if err := grantCookieResponse(fresh, "current=private; Path=/"); err != nil {
				t.Fatal(err)
			}
			prepared, _ = f.prepare(t)
			if prepared.Header.Get("Cookie") != "current=private" {
				t.Fatal("new winning resource did not receive its own jar")
			}
		})
	}
}

func TestGrantCookiesSnapshotFailuresRetireState(t *testing.T) {
	for _, kind := range []string{"invalid policy", "invalid resource", "missing revision", "stale revision", "database closed"} {
		t.Run(kind, func(t *testing.T) {
			f := newGrantCookieFixture(t)
			_, old := f.prepare(t)
			if err := grantCookieResponse(old, "old=private; Path=/"); err != nil {
				t.Fatal(err)
			}
			generation, _ := f.c.jars.PolicyGeneration(f.item.ID)
			snapshot, err := f.h.server.store.ResourceSnapshot()
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "invalid policy":
				changed := f.item
				changed.CookiePolicy.JarScope = "parent"
				err = f.h.server.store.UpsertResource(changed)
			case "invalid resource":
				_, err = f.control.Exec(`UPDATE resources SET config_json = '{}'`)
			case "missing revision":
				_, err = f.control.Exec(`DELETE FROM resource_state`)
			case "stale revision":
				_, err = f.control.Exec(`UPDATE resource_state SET revision = revision - 1`)
			case "database closed":
				err = f.h.server.store.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			if request, exchange, err := f.c.prepareRequest(httptest.NewRequest("GET", f.target, nil), f.token, f.authority); err == nil || request != nil || exchange != nil {
				t.Fatal("failed snapshot allowed jar access")
			}
			if _, err := f.c.jars.PolicyGeneration(f.item.ID); err == nil {
				t.Fatal("failed snapshot left policies available")
			}
			if kind == "database closed" {
				return
			}
			if kind == "missing revision" || kind == "stale revision" {
				_, err = f.control.Exec(`INSERT INTO resource_state (id, revision) VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET revision = excluded.revision`, snapshot.Revision)
			} else {
				err = f.h.server.store.UpsertResource(f.item)
			}
			if err != nil {
				t.Fatal(err)
			}
			prepared, _ := f.prepare(t)
			current, _ := f.c.jars.PolicyGeneration(f.item.ID)
			if current == generation || prepared.Header.Get("Cookie") != "" {
				t.Fatal("snapshot recovery resurrected old cookies")
			}
			if err := grantCookieResponse(old, "late=forbidden"); err == nil {
				t.Fatal("snapshot recovery resurrected an old response")
			}
		})
	}
}

func TestGrantCookiesCookielessPoliciesNeverDowngradeInvalidGrant(t *testing.T) {
	for _, kind := range []string{"disabled cookies", "public exception"} {
		t.Run(kind, func(t *testing.T) {
			f := newGrantCookieFixture(t)
			if kind == "disabled cookies" {
				f.item.CookiePolicy.Enabled = false
			} else {
				f.item.Domains = []resources.DomainRule{{Host: "other.example"}}
				f.item.AnonymousURLRules = []resources.AnonymousURLRule{{Pattern: "https://vendor.example/*", Behavior: "allow_public_proxy", Methods: []string{"GET"}}}
			}
			if err := f.h.server.store.UpsertResource(f.item); err != nil {
				t.Fatal(err)
			}
			_, exchange := f.prepare(t)
			if err := grantCookieResponse(exchange, "must=discard; Path=/"); err != nil {
				t.Fatal(err)
			}
			prepared, _ := f.prepare(t)
			if prepared.Header.Get("Cookie") != "" {
				t.Fatal("cookieless resource retained response cookies")
			}
			if prepared, exchange, err := f.c.prepareRequest(httptest.NewRequest("GET", f.target, nil), "invalid", f.authority); err == nil || prepared != nil || exchange != nil {
				t.Fatal("invalid grant downgraded to cookieless/anonymous authorization")
			}
		})
	}
}

func TestGrantCookiesSeparateUsersAndSessions(t *testing.T) {
	f := newGrantCookieFixture(t)
	parent, _, _ := f.h.server.store.GetSession(local.SessionIDFromToken(f.central))
	bob := createLocalTestUser(t, f.h.server, "bob", "correct horse battery")
	tokens := []string{f.token}
	for _, userID := range []string{parent.UserID, bob.ID} {
		central, session, err := f.h.server.newBrowserSession(userID, httptest.NewRequest("POST", "/login", nil))
		if err != nil {
			t.Fatal(err)
		}
		if err := f.h.server.store.CreateSession(session); err != nil {
			t.Fatal(err)
		}
		other := f.securityFixture
		other.central = central
		tokens = append(tokens, other.grant(t))
	}
	finished := make(chan error, len(tokens))
	for i, token := range tokens {
		go func() {
			want := []string{"session=alice-one", "session=alice-two", "session=bob"}[i]
			for iteration := range 3 {
				prepared, exchange, err := f.c.prepareRequest(httptest.NewRequest("GET", f.target, nil), token, f.authority)
				if err != nil {
					finished <- err
					return
				}
				expected := want
				if iteration == 0 {
					expected = ""
				}
				if prepared.Header.Get("Cookie") != expected {
					finished <- errors.New("cookies crossed a user/session boundary")
					return
				}
				if err := grantCookieResponse(exchange, want+"; Path=/"); err != nil {
					finished <- err
					return
				}
			}
			finished <- nil
		}()
	}
	for range tokens {
		if err := <-finished; err != nil {
			t.Error(err)
		}
	}
}

func TestGrantCookiesResourceWriteCannotInterveneBeforeJarAccess(t *testing.T) {
	f := newGrantCookieFixture(t)
	_, old := f.prepare(t)
	if err := grantCookieResponse(old, "old=private; Path=/"); err != nil {
		t.Fatal(err)
	}
	entered, resume := make(chan struct{}), make(chan struct{}, 1)
	defer close(resume)
	var once sync.Once
	f.c.now = func() time.Time {
		once.Do(func() {
			// Authorization has read and published its snapshot, but has not
			// reached the manager's cookie attachment yet.
			close(entered)
			<-resume
		})
		return f.now
	}
	prepared := make(chan error, 1)
	go func() {
		request, _, err := f.c.prepareRequest(httptest.NewRequest("GET", f.target, nil), f.token, f.authority)
		if err == nil && request.Header.Get("Cookie") != "old=private" {
			err = errors.New("authorized snapshot lost its jar before the writer committed")
		}
		prepared <- err
	}()
	<-entered
	started, written := make(chan struct{}), make(chan error, 1)
	go func() {
		close(started)
		written <- f.h.server.store.UpsertResource(f.item)
	}()
	<-started
	select {
	case err := <-written:
		written <- err
		t.Error("resource write completed between authorization and jar access")
	case <-time.After(50 * time.Millisecond):
	}
	resume <- struct{}{}
	if err := <-prepared; err != nil {
		t.Fatal(err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	request, _ := f.prepare(t)
	if request.Header.Get("Cookie") != "" {
		t.Fatal("post-commit preparation retained the old jar")
	}
	if err := grantCookieResponse(old, "late=forbidden"); err == nil {
		t.Fatal("post-commit response accepted the old generation")
	}
}

func TestGrantCookiesResourceChangeDuringDNSIsObserved(t *testing.T) {
	f := newGrantCookieFixture(t)
	f.h.server.ipLookup = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		// This must complete: holding the resource guard across DNS would
		// deadlock the writer. Authorization must then see the new revision.
		changed := f.item
		changed.Status = "disabled"
		if err := f.h.server.store.UpsertResource(changed); err != nil {
			return nil, err
		}
		return publicTestResolver(ctx, host)
	}
	if request, exchange, err := f.c.prepareRequest(httptest.NewRequest("GET", f.target, nil), f.token, f.authority); err == nil || request != nil || exchange != nil {
		t.Fatal("request authorized a snapshot from before DNS completed")
	}
}

func TestGrantCookiesPartialImportCannotHideCommittedChanges(t *testing.T) {
	for _, failure := range []string{"later resource", "import revision"} {
		t.Run(failure, func(t *testing.T) {
			f := newGrantCookieFixture(t)
			_, old := f.prepare(t)
			if err := grantCookieResponse(old, "old=private; Path=/"); err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			resourceDir := filepath.Join(dir, "resources")
			if err := os.Mkdir(resourceDir, 0700); err != nil {
				t.Fatal(err)
			}
			payload, err := json.Marshal(f.item) // An identical committed update still counts.
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(resourceDir, "a.json"), payload, 0600); err != nil {
				t.Fatal(err)
			}
			if failure == "later resource" {
				if err := os.WriteFile(filepath.Join(resourceDir, "b.json"), []byte(`{"id":"bad"}`), 0600); err != nil {
					t.Fatal(err)
				}
			} else if _, err := f.control.Exec(`CREATE TRIGGER fail_import_revision BEFORE INSERT ON config_revisions BEGIN SELECT RAISE(ABORT, 'injected failure'); END`); err != nil {
				t.Fatal(err)
			}
			results, err := config.ImportResources(f.h.server.store, dir)
			if failure == "later resource" {
				if err != nil || len(results) != 2 || !results[0].Imported || results[1].Imported || results[1].Error == "" {
					t.Fatalf("partial import fixture did not commit its first write: %v", err)
				}
			} else if err == nil {
				t.Fatal("import revision failure was not injected")
			}
			prepared, _ := f.prepare(t)
			if prepared.Header.Get("Cookie") != "" {
				t.Fatal("later import failure concealed a committed resource change")
			}
			if err := grantCookieResponse(old, "late=forbidden"); err == nil {
				t.Fatal("partial import left the old exchange usable")
			}
		})
	}
}

func TestGrantCookiesCapacityFailurePreservesGrantAndOtherJars(t *testing.T) {
	f := newGrantCookieFixture(t)
	_, first := f.prepare(t)
	if err := grantCookieResponse(first, "first=private; Path=/"); err != nil {
		t.Fatal(err)
	}
	parent, _, _ := f.h.server.store.GetSession(local.SessionIDFromToken(f.central))
	for i := range proxy.UpstreamMaxJars {
		central, session, err := f.h.server.newBrowserSession(parent.UserID, httptest.NewRequest("POST", "/login", nil))
		if err != nil {
			t.Fatal(err)
		}
		if err := f.h.server.store.CreateSession(session); err != nil {
			t.Fatal(err)
		}
		other := f.securityFixture
		other.central = central
		token := other.grant(t)
		request, exchange, err := f.c.prepareRequest(httptest.NewRequest("GET", f.target, nil), token, f.authority)
		if i < proxy.UpstreamMaxJars-1 {
			if err != nil {
				t.Fatal(err)
			}
			continue
		}
		var full *proxy.CookieJarCapacityError
		if !errors.As(err, &full) || request != nil || exchange != nil {
			t.Fatal("capacity exhaustion did not fail before fetching")
		}
		if err := f.h.validateGrant(context.Background(), token, f.authority, f.target, "GET", f.now); err != nil {
			t.Fatal("capacity exhaustion invalidated the grant")
		}
	}
	request, _ := f.prepare(t)
	if request.Header.Get("Cookie") != "first=private" {
		t.Fatal("capacity exhaustion evicted another parent's cookies")
	}
}

func TestGrantCookiesResponseFailuresStripHeaders(t *testing.T) {
	for _, failure := range []string{"wrong response target", "canceled", "nil exchange", "missing resolver"} {
		t.Run(failure, func(t *testing.T) {
			f := newGrantCookieFixture(t)
			_, exchange := f.prepare(t)
			response := &http.Response{Header: http.Header{"sEt-CoOkIe": {"private=value"}, "Set-Cookie2": {"private=value"}}}
			ctx := context.Background()
			switch failure {
			case "wrong response target":
				response.Request = httptest.NewRequest("GET", "https://other.example/", nil)
			case "canceled":
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			case "nil exchange":
				exchange = nil
			case "missing resolver":
				f.h.server.ipLookup = nil
			}
			if err := exchange.storeResponse(ctx, response); err == nil || len(response.Header) != 0 {
				t.Fatal("failed response retained cookie headers or reported success")
			}
		})
	}
}
