package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"example.org/odo/internal/accesslog"
	"example.org/odo/internal/auth/local"
	"example.org/odo/internal/db"
	"example.org/odo/internal/proxy"
	"example.org/odo/internal/resources"
	"golang.org/x/net/publicsuffix"
)

type handoffBrowser struct {
	securityFixture
	client *http.Client
	logs   *bytes.Buffer
}

// All browser authorities use HTTPS fake names. Only this test transport maps
// them to one local TLS listener; its certificate is verified for that listener.
// Odo's separate target resolver returns public test IPs and never fetches them.
func newHandoffBrowser(t *testing.T, enabled, authenticated bool) handoffBrowser {
	t.Helper()
	flag := "false"
	if enabled {
		flag = "true"
	}
	t.Setenv("APP_EXPERIMENTAL_HANDOFF", flag)
	t.Setenv("APP_ENV", "test")
	t.Setenv("APP_PROXY_REQUIRE_LOGIN", "true")
	f := newSecurityFixture(t)
	server := f.h.server
	if enabled {
		f.h = server.handoff
		if f.h == nil {
			t.Fatal("handoff mode not constructed")
		}
	}
	logs := new(bytes.Buffer)
	server.logger = slog.New(slog.NewJSONHandler(logs, nil))
	server.accessLog, _ = accesslog.New(accesslog.FormatPrivacy, logs)
	server.httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("handoff fetched upstream content")
		return nil, io.ErrUnexpectedEOF
	})}
	listener := httptest.NewTLSServer(server.Routes())
	t.Cleanup(listener.Close)
	localURL, _ := url.Parse(listener.URL)
	transport := listener.Client().Transport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.ServerName = localURL.Hostname()
	transport.TLSClientConfig.MinVersion = tls.VersionTLS12
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, localURL.Host)
	}
	t.Cleanup(transport.CloseIdleConnections)
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		t.Fatal(err)
	}
	if authenticated {
		central, _ := url.Parse("https://odo.example")
		jar.SetCookies(central, []*http.Cookie{handoffCookie("__Host-odo_session", f.central, time.Now().Add(time.Hour))})
	}
	client := &http.Client{Jar: jar, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Hostname() != "odo.example" {
			for _, cookie := range r.Cookies() {
				if cookie.Name != vendorNonceCookie && cookie.Name != vendorGrantCookie {
					t.Error("browser sent a central cookie to vendor host")
				}
			}
			if r.Header.Get("Authorization") != "" {
				t.Error("browser sent management credentials to vendor host")
			}
		}
		return transport.RoundTrip(r)
	})}
	return handoffBrowser{securityFixture: f, client: client, logs: logs}
}

func (b handoffBrowser) request(t *testing.T, method, target string, fields url.Values) (*http.Response, string) {
	t.Helper()
	var body io.Reader
	if fields != nil {
		body = strings.NewReader(fields.Encode())
	}
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	if method == "POST" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "https://odo.example")
	}
	req.Header.Set("Accept", "text/html")
	response, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("missing handoff privacy headers")
	}
	return response, string(data)
}

func (b handoffBrowser) launch(t *testing.T) (*http.Response, string) {
	t.Helper()
	return b.request(t, "GET", "https://odo.example/launch?"+url.Values{"url": {b.target}}.Encode(), nil)
}

func (b handoffBrowser) ticket(t *testing.T) string {
	t.Helper()
	response, _ := b.launch(t)
	if response.StatusCode != 303 {
		t.Fatalf("launch status: %d", response.StatusCode)
	}
	if cookie := findCookie(response.Cookies(), handoffNonceCookie); cookie != nil {
		assertHandoffBrowserCookie(t, cookie)
	}
	prepared, _ := b.request(t, "GET", response.Header.Get("Location"), nil)
	if prepared.StatusCode != 303 {
		t.Fatalf("preflight status: %d", prepared.StatusCode)
	}
	if nonce := findCookie(prepared.Cookies(), vendorNonceCookie); nonce != nil {
		assertHandoffBrowserCookie(t, nonce)
	}
	callback, _ := url.Parse(prepared.Header.Get("Location"))
	page, html := b.request(t, "GET", callback.String(), nil)
	if page.StatusCode != 200 || !strings.Contains(html, "Continue to vendor.example") {
		t.Fatal("confirmation page missing")
	}
	// Read the actual session-derived CSRF value rendered in the form.
	_, rest, ok := strings.Cut(html, `name="csrf" value="`)
	if !ok {
		t.Fatal("CSRF field missing")
	}
	csrf, _, ok := strings.Cut(rest, `"`)
	if !ok {
		t.Fatal("CSRF field malformed")
	}
	fields := callback.Query()
	fields.Set("csrf", csrf)
	confirmed, _ := b.request(t, "POST", "https://odo.example"+handoffConfirmPath, fields)
	if confirmed.StatusCode != 303 {
		t.Fatalf("confirmation status: %d", confirmed.StatusCode)
	}
	location := confirmed.Header.Get("Location")
	for _, private := range []string{b.target, "private-search", b.central, b.nonce, b.vendor} {
		if strings.Contains(location, private) {
			t.Fatal("ticket redirect disclosed private data")
		}
	}
	return location
}

func (b handoffBrowser) finish(t *testing.T, ticket string) string {
	t.Helper()
	response, _ := b.request(t, "GET", ticket, nil)
	if response.StatusCode != 303 {
		t.Fatalf("redemption status: %d", response.StatusCode)
	}
	grant := findCookie(response.Cookies(), vendorGrantCookie)
	if grant == nil || !grant.Secure || !grant.HttpOnly || grant.Domain != "" || grant.Path != "/" || grant.SameSite != http.SameSiteLaxMode || grant.MaxAge > int(handoffGrantTTL.Seconds()) {
		t.Fatal("incorrect grant cookie attributes")
	}
	clean := response.Header.Get("Location")
	u, _ := url.Parse(clean)
	if u.RawQuery != "" || u.Path != handoffVendorPath {
		t.Fatal("redemption did not clean ticket URL")
	}
	receipt, body := b.request(t, "GET", clean, nil)
	if receipt.StatusCode != 200 || !strings.Contains(body, "Vendor content delivery is disabled") || strings.Contains(body, b.target) || strings.Contains(body, "private-search") {
		t.Fatal("missing inert completion page")
	}
	return clean
}

func TestExperimentalHandoffBrowserFlow(t *testing.T) {
	b := newHandoffBrowser(t, true, true)
	ticket := b.ticket(t)
	clean := b.finish(t, ticket)
	if replay, _ := b.request(t, "GET", ticket, nil); replay.StatusCode != 404 || findCookie(replay.Cookies(), vendorGrantCookie) != nil {
		t.Fatal("ticket replay succeeded")
	}
	vendorURL, _ := url.Parse(clean)
	centralURL, _ := url.Parse("https://odo.example")
	for _, cookie := range b.client.Jar.Cookies(centralURL) {
		if cookie.Name == vendorGrantCookie || cookie.Name == vendorNonceCookie {
			t.Fatal("vendor cookie escaped to central host")
		}
	}
	for _, cookie := range b.client.Jar.Cookies(vendorURL) {
		if cookie.Name != vendorGrantCookie && cookie.Name != vendorNonceCookie {
			t.Fatal("central cookie escaped to vendor")
		}
	}
	if b.h.server.sessions.Count() != 0 {
		t.Fatal("handoff allocated an upstream cookie jar")
	}
	// Neither authority serves a vendor body, including missed-rewrite recovery.
	for _, target := range []string{"https://" + vendorURL.Host + "/article", "https://odo.example/odo/https/vendor.example/article", "https://odo.example/article"} {
		response, body := b.request(t, "GET", target, nil)
		if response.StatusCode < 400 || strings.Contains(body, "<script") {
			t.Fatal("content route became available")
		}
	}
	for _, secret := range []string{ticket, b.target, b.central, "private-search", vendorURL.RawQuery} {
		if secret != "" && strings.Contains(b.logs.String(), secret) {
			t.Fatal("handoff logs disclosed sensitive data")
		}
	}
}

func TestExperimentalHandoffLoginContinuation(t *testing.T) {
	b := newHandoffBrowser(t, true, false)
	response, _ := b.launch(t)
	if response.StatusCode != 302 {
		t.Fatal("unauthenticated launch did not request login")
	}
	loginURL, _ := url.Parse(response.Header.Get("Location"))
	if strings.Contains(loginURL.String(), "vendor.example") || strings.Contains(loginURL.String(), "private-search") {
		t.Fatal("login continuation exposed target")
	}
	login, _ := b.request(t, "POST", "https://odo.example/login", url.Values{"username": {"alice"}, "password": {"correct horse battery"}, "next": {loginURL.Query().Get("next")}})
	if login.StatusCode != 302 {
		t.Fatalf("login status: %d", login.StatusCode)
	}
	continued, _ := b.request(t, "GET", "https://odo.example"+login.Header.Get("Location"), nil)
	if continued.StatusCode != 303 || !strings.Contains(continued.Header.Get("Location"), handoffVendorPath+"?handoff=") {
		t.Fatal("login did not continue into handoff")
	}
}

func TestExperimentalHandoffAdmissionAndIsolation(t *testing.T) {
	b := newHandoffBrowser(t, true, true)
	mapping, err := b.h.server.store.RegisterProxyHostname("other.example", "odo.example", "proxy.example")
	if err != nil {
		t.Fatal(err)
	}
	other := mapping.Label + ".proxy.example"
	for _, path := range []string{"/admin", "/login", "/logout", "/api/v1", "/resources", "/launch", "/.well-known/odo/prepare", "/.well-known/odo/%72edeem"} {
		response, _ := b.request(t, "GET", "https://"+b.authority+path, nil)
		if response.StatusCode != 421 || len(response.Cookies()) != 0 {
			t.Fatal("vendor reached central application or another endpoint")
		}
	}
	response, _ := b.request(t, "GET", "https://unknown.proxy.example"+handoffVendorPath+"?ticket="+b.vendor, nil)
	if response.StatusCode != 421 || len(response.Cookies()) != 0 {
		t.Fatal("unknown host admitted")
	}
	ticket := b.ticket(t)
	parsed, _ := url.Parse(ticket)
	wrong := *parsed
	wrong.Host = other
	denied, _ := b.request(t, "GET", wrong.String(), nil)
	if denied.StatusCode < 400 || len(denied.Cookies()) != 0 {
		t.Fatal("ticket crossed vendor hosts")
	}
	clean := b.finish(t, ticket)
	receiptURL, _ := url.Parse(clean)
	receiptURL.Host = other
	denied, _ = b.request(t, "GET", receiptURL.String(), nil)
	if denied.StatusCode != 401 {
		t.Fatal("grant cookie shared across vendors")
	}
	// Even a manually copied grant is rejected by its server-side host binding.
	original, _ := url.Parse(clean)
	for _, cookie := range b.client.Jar.Cookies(original) {
		if cookie.Name == vendorGrantCookie {
			b.client.Jar.SetCookies(receiptURL, []*http.Cookie{handoffCookie(vendorGrantCookie, cookie.Value, time.Now().Add(time.Minute))})
		}
	}
	denied, _ = b.request(t, "GET", receiptURL.String(), nil)
	if denied.StatusCode != 401 {
		t.Fatal("server accepted grant on a different vendor")
	}
}

func TestExperimentalHandoffRevocation(t *testing.T) {
	for _, mutation := range []string{"logout", "password", "auth_version", "disabled", "locked", "deleted", "roles", "expired", "revoked"} {
		t.Run(mutation, func(t *testing.T) {
			b := newHandoffBrowser(t, true, true)
			clean := b.finish(t, b.ticket(t))
			outstanding := b.ticket(t)
			id := local.SessionIDFromToken(b.central)
			session, _, err := b.h.server.store.GetSession(id)
			if err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "logout":
				response, _ := b.request(t, "POST", "https://odo.example/logout", url.Values{})
				if response.StatusCode != 302 {
					t.Fatal("logout failed")
				}
			case "password":
				if _, err := b.h.server.store.SetUserPassword(session.UserID, "replacement-hash"); err != nil {
					t.Fatal(err)
				}
			case "auth_version":
				if _, err := b.control.Exec(`UPDATE users SET auth_version=auth_version+1 WHERE id=?`, session.UserID); err != nil {
					t.Fatal(err)
				}
			case "disabled", "locked":
				if _, _, err := b.h.server.store.SetUserStatus(session.UserID, mutation); err != nil {
					t.Fatal(err)
				}
			case "deleted":
				if _, err := b.h.server.store.DeleteUser(session.UserID, "administrator"); err != nil {
					t.Fatal(err)
				}
			case "roles":
				if _, _, err := b.h.server.store.PatchUser(session.UserID, db.UserPatch{Roles: []string{"staff"}}); err != nil {
					t.Fatal(err)
				}
			case "expired":
				if _, err := b.control.Exec(`UPDATE sessions SET expires_at=? WHERE id=?`, time.Now().Add(-time.Second).Format(time.RFC3339), id); err != nil {
					t.Fatal(err)
				}
			case "revoked":
				if err := b.h.server.store.RevokeSession(id); err != nil {
					t.Fatal(err)
				}
			}
			response, _ := b.request(t, "GET", clean, nil)
			if response.StatusCode < 400 {
				t.Fatal("changed parent retained a usable grant")
			}
			response, _ = b.request(t, "GET", outstanding, nil)
			if response.StatusCode < 400 || findCookie(response.Cookies(), vendorGrantCookie) != nil {
				t.Fatal("changed parent redeemed an outstanding ticket")
			}
		})
	}
}

func TestExperimentalHandoffFailures(t *testing.T) {
	for _, kind := range []string{"expired ticket", "changed resource", "unknown registry", "database", "grant capacity"} {
		t.Run(kind, func(t *testing.T) {
			b := newHandoffBrowser(t, true, true)
			ticketURL := b.ticket(t)
			parsed, _ := url.Parse(ticketURL)
			key := local.HashToken(parsed.Query().Get("ticket"))
			ticket := b.h.state.tickets[key]
			switch kind {
			case "expired ticket":
				ticket.expires = time.Now().Add(-time.Second)
				b.h.state.tickets[key] = ticket
			case "changed resource":
				if _, err := b.h.server.store.DeleteResource("vendor"); err != nil {
					t.Fatal(err)
				}
				if err := b.h.server.store.UpsertResource(resources.Resource{ID: "replacement", Name: "Replacement", Domains: []resources.DomainRule{{Host: "vendor.example"}}}); err != nil {
					t.Fatal(err)
				}
			case "unknown registry":
				if _, err := b.control.Exec(`DELETE FROM proxy_hostnames`); err != nil {
					t.Fatal(err)
				}
			case "database":
				if _, err := b.control.Exec(`ALTER TABLE sessions RENAME TO unavailable_sessions`); err != nil {
					t.Fatal(err)
				}
			case "grant capacity":
				for i := 0; i < maxHandoffGrantsPerParent; i++ {
					token, err := local.NewToken("", 32)
					if err != nil {
						t.Fatal(err)
					}
					b.h.state.grants[local.HashToken(token)] = handoffGrant{binding: ticket.binding, expires: time.Now().Add(time.Hour)}
				}
			}
			response, body := b.request(t, "GET", ticketURL, nil)
			if response.StatusCode < 400 || findCookie(response.Cookies(), vendorGrantCookie) != nil || response.Header.Get("Location") != "" || strings.Contains(body, "unavailable_sessions") {
				t.Fatal("failure reported successful handoff or leaked database detail")
			}
			if kind == "database" || kind == "grant capacity" || kind == "changed resource" {
				if b.h.state.tickets[key] != ticket {
					t.Fatal("failed redemption consumed live ticket")
				}
			}
		})
	}
}

func TestExperimentalHandoffConcurrentRedemption(t *testing.T) {
	b := newHandoffBrowser(t, true, true)
	b.h.server.logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	b.h.server.accessLog, _ = accesslog.New(accesslog.FormatPrivacy, io.Discard)
	ticket := b.ticket(t)
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			response, _ := b.request(t, "GET", ticket, nil)
			if response.StatusCode == 303 {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 || len(b.h.state.grants) != 1 {
		t.Fatal("concurrent redemption produced multiple grants")
	}
}

func TestExperimentalHandoffPasswordRollback(t *testing.T) {
	b := newHandoffBrowser(t, true, true)
	clean := b.finish(t, b.ticket(t))
	session, _, err := b.h.server.store.GetSession(local.SessionIDFromToken(b.central))
	if err != nil {
		t.Fatal(err)
	}
	before, _, err := b.h.server.store.GetUser(session.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.control.Exec(`CREATE TRIGGER reject_handoff_revocation BEFORE UPDATE OF revoked_at ON sessions BEGIN SELECT RAISE(ABORT,'injected revocation failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := b.h.server.store.SetUserPassword(session.UserID, "new-hash"); err == nil {
		t.Fatal("password transaction unexpectedly succeeded")
	}
	after, _, err := b.h.server.store.GetUser(session.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if after.AuthVersion != before.AuthVersion || after.PasswordHash != before.PasswordHash {
		t.Fatal("failed transaction persisted account mutation")
	}
	if response, _ := b.request(t, "GET", clean, nil); response.StatusCode != 200 {
		t.Fatal("rolled-back transaction falsely revoked grant")
	}
}

func assertHandoffBrowserCookie(t *testing.T, cookie *http.Cookie) {
	t.Helper()
	if cookie == nil || !cookie.Secure || !cookie.HttpOnly || cookie.Domain != "" || cookie.Path != "/" || cookie.SameSite != http.SameSiteLaxMode || cookie.MaxAge <= 0 {
		t.Fatal("incorrect host-only handoff cookie attributes")
	}
}

func TestExperimentalHandoffDisabledPreservesURLModes(t *testing.T) {
	for _, mode := range []string{"path", "query", "dual"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("APP_PROXY_URL_MODE", mode)
			b := newHandoffBrowser(t, false, true)
			if b.h.server.handoff != nil {
				t.Fatal("feature enabled by default")
			}
			response, _ := b.launch(t)
			if response.StatusCode != 302 || len(response.Cookies()) != 0 {
				t.Fatal("default launch changed")
			}
			parsed, _, ok, err := proxy.ParseProxyRequest(httptest.NewRequest("GET", response.Header.Get("Location"), nil))
			if err != nil || !ok || parsed.String() != b.target {
				t.Fatal("path/query launch target changed")
			}
			response, _ = b.request(t, "GET", "https://"+b.authority+handoffVendorPath+"?ticket="+b.vendor, nil)
			if response.StatusCode != 421 {
				t.Fatal("disabled feature admitted vendor handoff")
			}
		})
	}
}

func TestExperimentalHandoffRejectsUnregisteredAndInactiveLaunch(t *testing.T) {
	for _, kind := range []string{"registry", "resource"} {
		t.Run(kind, func(t *testing.T) {
			b := newHandoffBrowser(t, true, true)
			if kind == "registry" {
				if _, err := b.control.Exec(`DELETE FROM proxy_hostnames`); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := b.h.server.store.UpsertResource(resources.Resource{ID: "vendor", Name: "Vendor", Status: "disabled", Domains: []resources.DomainRule{{Host: "vendor.example"}}}); err != nil {
					t.Fatal(err)
				}
			}
			response, _ := b.launch(t)
			if response.StatusCode != 403 || len(response.Cookies()) != 0 || len(b.h.state.entries) != 0 {
				t.Fatal("unauthorized launch created handoff state")
			}
			if kind == "registry" {
				_, found, err := b.h.server.store.LookupProxyHostname(strings.Split(b.authority, ".")[0])
				if err != nil || found {
					t.Fatal("launch automatically registered host")
				}
			}
		})
	}
}

func TestExperimentalHandoffSpoofedAuthority(t *testing.T) {
	b := newHandoffBrowser(t, true, true)
	handler := b.h.server.Routes()
	for _, tc := range []struct{ host, target string }{
		{"evil.example", "https://odo.example/admin"},
		{b.authority, "https://odo.example" + handoffVendorPath},
		{b.authority, "https://h-other.proxy.example" + handoffVendorPath},
		{b.authority, "http://" + b.authority + handoffVendorPath},
	} {
		req := httptest.NewRequest("GET", tc.target, nil)
		req.Host = tc.host
		req.Header.Set("X-Forwarded-Host", "odo.example")
		req.Header.Set("Forwarded", "host=odo.example;proto=https")
		req.Header.Set("Authorization", "Bearer secret")
		req.AddCookie(&http.Cookie{Name: "__Host-odo_session", Value: b.central})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != 421 || len(rec.Result().Cookies()) != 0 {
			t.Fatal("spoofed or conflicting authority admitted")
		}
	}
}

func TestExperimentalHandoffConfigFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name, flag, env, guard, public string
		valid                          bool
	}{
		{"off", "false", "production", "false", "", true},
		{"test", "true", "test", "true", "https://odo.example", true},
		{"invalid flag", "maybe", "test", "true", "https://odo.example", false},
		{"production", "true", "production", "true", "https://odo.example", false},
		{"unguarded", "true", "test", "false", "https://odo.example", false},
		{"HTTP central", "true", "test", "true", "http://odo.example", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("APP_EXPERIMENTAL_HANDOFF", tc.flag)
			t.Setenv("APP_ENV", tc.env)
			t.Setenv("APP_HOST_GUARD", tc.guard)
			t.Setenv("APP_PUBLIC_URL", tc.public)
			t.Setenv("APP_PROXY_BASE_DOMAIN", "proxy.example")
			err := ValidateHostGuardConfig()
			if (err == nil) != tc.valid {
				t.Fatal("incorrect experimental configuration validation")
			}
			if !tc.valid {
				server := NewServer(nil, t.TempDir(), "secret", slog.New(slog.NewJSONHandler(io.Discard, nil)))
				rec := httptest.NewRecorder()
				server.Routes().ServeHTTP(rec, httptest.NewRequest("GET", "https://odo.example/api/v1/health", nil))
				if rec.Code != 503 || len(rec.Result().Cookies()) != 0 {
					t.Fatal("invalid directly constructed configuration did not fail closed")
				}
			}
		})
	}
}

func TestExperimentalHandoffSuppressesSensitiveLogHeaders(t *testing.T) {
	for _, format := range []string{accesslog.FormatCombined, accesslog.FormatJSON} {
		t.Run(format, func(t *testing.T) {
			b := newHandoffBrowser(t, true, true)
			b.h.server.accessLog, _ = accesslog.New(format, b.logs)
			ticketURL := b.ticket(t)
			clean := b.finish(t, ticketURL)
			u, _ := url.Parse(clean)
			grant := ""
			for _, cookie := range b.client.Jar.Cookies(u) {
				if cookie.Name == vendorGrantCookie {
					grant = cookie.Value
				}
			}
			for _, target := range []string{clean, "https://unknown.proxy.example/private-search"} {
				req, err := http.NewRequest("GET", target, nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Referer", ticketURL+"&search=private-search")
				req.Header.Set("User-Agent", b.central+" "+grant)
				response, err := b.client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
			}
			parsed, _ := url.Parse(ticketURL)
			for _, secret := range []string{parsed.Query().Get("ticket"), b.central, grant, "private-search"} {
				if secret != "" && strings.Contains(b.logs.String(), secret) {
					t.Fatal("combined/JSON log disclosed sensitive control header")
				}
			}
		})
	}
}
