package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"example.org/odo/internal/auth/local"
	"example.org/odo/internal/proxy"
	"example.org/odo/internal/resources"
)

const (
	vendorPublicIP   = "93.184.216.34"
	vendorBodyMarker = "vendor-body-marker"
)

// fakeVendor is a local HTTPS server whose certificate is issued for fake
// public names. Odo reaches it only through the real safe client: the resolver
// returns a public test IP, IP validation runs, and only then does the test
// dialer map that validated IP to the loopback listener.
type fakeVendor struct {
	server  *httptest.Server
	roots   *x509.CertPool
	hits    atomic.Int32
	mu      sync.Mutex
	last    *http.Request
	entered chan struct{}
	release chan struct{}
	done    chan struct{}
}

func newFakeVendor(t *testing.T, names ...string) *fakeVendor {
	t.Helper()
	return newFakeVendorSite(t, nil, names...)
}

// newFakeVendorSite serves site (when non-nil) instead of the default routes,
// still recording hits and the last request.
func newFakeVendorSite(t *testing.T, site http.Handler, names ...string) *fakeVendor {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	v := &fakeVendor{roots: x509.NewCertPool(), entered: make(chan struct{}, 4), release: make(chan struct{}), done: make(chan struct{}, 4)}
	v.roots.AddCert(leaf)
	handler := http.Handler(http.HandlerFunc(v.serve))
	if site != nil {
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			v.hits.Add(1)
			v.mu.Lock()
			v.last = r.Clone(context.Background())
			v.mu.Unlock()
			site.ServeHTTP(w, r)
		})
	}
	v.server = httptest.NewUnstartedServer(handler)
	v.server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}}, MinVersion: tls.VersionTLS12}
	v.server.StartTLS()
	t.Cleanup(func() {
		select {
		case <-v.release:
		default:
			close(v.release)
		}
		v.server.Close()
	})
	return v
}

func (v *fakeVendor) serve(w http.ResponseWriter, r *http.Request) {
	v.hits.Add(1)
	v.mu.Lock()
	v.last = r.Clone(context.Background())
	v.mu.Unlock()
	query := r.URL.Query()
	switch r.URL.Path {
	case "/private":
		for name, value := range map[string]string{
			"Content-Security-Policy": "default-src https://vendor.example", "Access-Control-Allow-Origin": "*",
			"Strict-Transport-Security": "max-age=600", "Refresh": "0; url=https://evil.example/", "Link": "<https://evil.example/>; rel=preload",
			"Alt-Svc": `h3=":443"`, "Set-Cookie2": "legacy=1", "X-Internal-Debug": "secret", "Cache-Control": "public, max-age=600",
			"Location": "https://evil.example/", "Content-Language": "en", "ETag": `"v1"`,
		} {
			w.Header().Set(name, value)
		}
		w.Header().Add("Set-Cookie", "tracking=private; Path=/; Secure")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<html>"+vendorBodyMarker+"</html>\n\n\n\n\n")
	case "/set":
		w.Header().Add("Set-Cookie", "who="+query.Get("v")+"; Path=/; Secure")
		_, _ = io.WriteString(w, "set")
	case "/echo":
		_, _ = io.WriteString(w, "cookie="+r.Header.Get("Cookie"))
	case "/redirect":
		if value := query.Get("cookie"); value != "" {
			w.Header().Add("Set-Cookie", "who="+value+"; Path=/; Secure")
		}
		w.Header().Set("Location", query.Get("to"))
		w.WriteHeader(http.StatusFound)
	case "/switch":
		// A hostile vendor answering a plain GET with a protocol switch.
		conn, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		_, _ = buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n" + vendorBodyMarker)
		_ = buffered.Flush()
		_ = conn.Close()
	case "/slow":
		v.entered <- struct{}{}
		select {
		case <-v.release:
			_, _ = io.WriteString(w, "slow-"+vendorBodyMarker)
		case <-r.Context().Done():
			v.done <- struct{}{}
		}
	default:
		_, _ = io.WriteString(w, "vendor-default "+r.URL.Path)
	}
}

func (v *fakeVendor) lastRequest() *http.Request {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.last
}

type deliveryHarness struct {
	handoffBrowser
	vendor   *fakeVendor
	routes   http.Handler
	grant    string
	resolver atomic.Pointer[proxy.IPLookupFunc]
	dialTo   atomic.Pointer[string]
}

func publicVendorLookup(context.Context, string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP(vendorPublicIP)}}, nil
}

func newDeliveryHarness(t *testing.T) *deliveryHarness {
	t.Helper()
	return newDeliveryHarnessWithSite(t, nil)
}

func newDeliveryHarnessWithSite(t *testing.T, site http.Handler) *deliveryHarness {
	t.Helper()
	b := newHandoffBrowser(t, true, true)
	d := &deliveryHarness{handoffBrowser: b, vendor: newFakeVendorSite(t, site, "vendor.example")}
	item, _, err := b.h.server.store.GetResource("vendor")
	if err != nil {
		t.Fatal(err)
	}
	item.CookiePolicy.Enabled = true
	if err := b.h.server.store.UpsertResource(item); err != nil {
		t.Fatal(err)
	}
	d.setResolver(publicVendorLookup)
	address := d.vendor.server.Listener.Addr().String()
	d.dialTo.Store(&address)
	lookup := func(ctx context.Context, host string) ([]net.IPAddr, error) { return (*d.resolver.Load())(ctx, host) }
	b.h.server.ipLookup = lookup
	b.h.vendor = proxy.NewSafeHTTPClient(lookup, func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != net.JoinHostPort(vendorPublicIP, "443") {
			return nil, errors.New("test dialer received an unexpected address")
		}
		return (&net.Dialer{}).DialContext(ctx, network, *d.dialTo.Load())
	}, &tls.Config{RootCAs: d.vendor.roots, MinVersion: tls.VersionTLS12})
	d.routes = b.h.server.Routes()
	d.grant = b.securityFixture.grant(t)
	return d
}

func (d *deliveryHarness) setResolver(lookup proxy.IPLookupFunc) { d.resolver.Store(&lookup) }

func (d *deliveryHarness) serve(method, path, grant string, edit func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "https://"+d.authority+path, nil)
	if grant != "" {
		req.AddCookie(&http.Cookie{Name: vendorGrantCookie, Value: grant})
	}
	if edit != nil {
		edit(req)
	}
	rec := httptest.NewRecorder()
	d.routes.ServeHTTP(rec, req)
	return rec
}

// grantFor mints a grant for another central session on the same runtime.
func (d *deliveryHarness) grantFor(t *testing.T, userID string) (central, grant string) {
	t.Helper()
	central, session, err := d.h.server.newBrowserSession(userID, httptest.NewRequest("POST", "/login", nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.h.server.store.CreateSession(session); err != nil {
		t.Fatal(err)
	}
	other := d.securityFixture
	other.central = central
	return central, other.grant(t)
}

func (d *deliveryHarness) parentUserID(t *testing.T) string {
	t.Helper()
	parent, _, err := d.h.server.store.GetSession(local.SessionIDFromToken(d.central))
	if err != nil {
		t.Fatal(err)
	}
	return parent.UserID
}

func TestVendorDeliveryBrowserGetAndHead(t *testing.T) {
	d := newDeliveryHarness(t)
	// End to end through the real TLS listener and browser cookie jar.
	d.finish(t, d.ticket(t))
	response, body := d.request(t, "GET", "https://"+d.authority+"/private?search=private-search&b=%2F", nil)
	if response.StatusCode != 200 || !strings.Contains(body, vendorBodyMarker) || response.Header.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("GET did not deliver vendor content: %d", response.StatusCode)
	}
	if last := d.vendor.lastRequest(); last.Method != "GET" || last.URL.RequestURI() != "/private?search=private-search&b=%2F" || last.Host != "vendor.example" {
		t.Fatal("upstream did not receive the exact registry host, escaped path and query")
	}
	head, body := d.request(t, "HEAD", "https://"+d.authority+"/private", nil)
	if head.StatusCode != 200 || body != "" || d.vendor.lastRequest().Method != "HEAD" || head.Header.Get("Content-Type") == "" {
		t.Fatal("HEAD returned a body or did not reach upstream as HEAD")
	}
	for _, secret := range []string{"private-search", vendorBodyMarker, d.grant, d.central} {
		if strings.Contains(d.logs.String(), secret) {
			t.Fatal("logs disclosed patron or vendor data")
		}
	}
}

func TestVendorDeliveryRequiresLiveGrant(t *testing.T) {
	for _, kind := range []string{"missing", "invalid", "duplicate", "expired", "revoked", "logout", "password", "disabled account", "locked account", "wrong host"} {
		t.Run(kind, func(t *testing.T) {
			d := newDeliveryHarness(t)
			// Not a document navigation: the boundary answers 401 instead of
			// restarting the handoff (covered by TestVendorDeliveryRestartsHandoff).
			grant, edit := d.grant, func(r *http.Request) { r.Header.Set("Sec-Fetch-Dest", "image") }
			parent, _, _ := d.h.server.store.GetSession(local.SessionIDFromToken(d.central))
			switch kind {
			case "missing":
				grant = ""
			case "invalid":
				grant = strings.Repeat("A", len(d.grant))
			case "duplicate":
				edit = func(r *http.Request) {
					r.Header.Set("Sec-Fetch-Dest", "image")
					r.AddCookie(&http.Cookie{Name: vendorGrantCookie, Value: d.grant})
				}
			case "expired":
				d.h.state.mu.Lock()
				for key, value := range d.h.state.grants {
					value.expires = time.Now().Add(-time.Second)
					d.h.state.grants[key] = value
				}
				d.h.state.mu.Unlock()
			case "revoked":
				if err := d.h.server.store.RevokeSession(parent.ID); err != nil {
					t.Fatal(err)
				}
			case "logout":
				requestLogout(d.h.server, &http.Cookie{Name: "__Host-odo_session", Value: d.central})
			case "password":
				if _, err := d.h.server.store.SetUserPassword(parent.UserID, "new-hash"); err != nil {
					t.Fatal(err)
				}
			case "disabled account", "locked account":
				if _, _, err := d.h.server.store.SetUserStatus(parent.UserID, strings.Fields(kind)[0]); err != nil {
					t.Fatal(err)
				}
			case "wrong host":
				mapping, err := d.h.server.store.RegisterProxyHostname("vendor2.example", "odo.example", "proxy.example")
				if err != nil {
					t.Fatal(err)
				}
				d.authority = mapping.Label + ".proxy.example"
			}
			if rec := d.serve("GET", "/private", grant, edit); rec.Code != 401 || strings.Contains(rec.Body.String(), vendorBodyMarker) {
				t.Fatalf("got %d", rec.Code)
			}
			if d.vendor.hits.Load() != 0 {
				t.Fatal("denied request reached upstream")
			}
		})
	}
}

func TestVendorDeliveryHostAndRequestAdmission(t *testing.T) {
	d := newDeliveryHarness(t)
	_, unregistered, err := proxy.RegistryHostname("unregistered.example", "odo.example", "proxy.example")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, method, host, path string
		edit                     func(*http.Request)
		want                     int
	}{
		{"unknown label", "GET", "unknown.proxy.example", "/private", nil, 421},
		{"unregistered", "GET", unregistered + ".proxy.example", "/private", nil, 421},
		{"post", "POST", d.authority, "/private", nil, 405},
		{"delete", "DELETE", d.authority, "/private", nil, 405},
		{"body", "GET", d.authority, "/private", func(r *http.Request) { r.ContentLength = 4; r.Body = io.NopCloser(strings.NewReader("body")) }, 400},
		{"chunked", "GET", d.authority, "/private", func(r *http.Request) { r.TransferEncoding = []string{"chunked"} }, 400},
		{"absolute mismatch", "GET", d.authority, "/private", func(r *http.Request) { r.URL.Host = "odo.example" }, 421},
		{"absolute http", "GET", d.authority, "/private", func(r *http.Request) { r.URL.Scheme = "http" }, 421},
		{"userinfo", "GET", d.authority, "/private", func(r *http.Request) { r.URL.User = url.User("x") }, 421},
		{"dot segment", "GET", d.authority, "/a/../private", nil, 400},
		{"encoded dot segment", "GET", d.authority, "/a/%2E%2e/private", nil, 400},
		{"backslash", "GET", d.authority, "/a%5C..%5Cprivate", nil, 400},
		{"control", "GET", d.authority, "/a%00", nil, 400},
		{"reserved", "GET", d.authority, "/.well-known/odo/other", nil, 400},
		{"long", "GET", d.authority, "/private?q=" + strings.Repeat("a", vendorContentMaxRequestURI), nil, 414},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "https://"+tc.host+tc.path, nil)
			req.AddCookie(&http.Cookie{Name: vendorGrantCookie, Value: d.grant})
			if tc.edit != nil {
				tc.edit(req)
			}
			rec := httptest.NewRecorder()
			d.routes.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("got %d want %d", rec.Code, tc.want)
			}
		})
	}
	if d.vendor.hits.Load() != 0 {
		t.Fatal("rejected request reached upstream")
	}
	// The redemption control route is preserved and is never proxied.
	if rec := d.serve("GET", handoffVendorPath, d.grant, nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Authentication handoff complete") || d.vendor.hits.Load() != 0 {
		t.Fatal("handoff receipt route changed")
	}
}

func TestVendorDeliveryCurrentPolicy(t *testing.T) {
	for _, kind := range []string{"disabled", "deleted", "method", "blocked"} {
		t.Run(kind, func(t *testing.T) {
			d := newDeliveryHarness(t)
			item, _, _ := d.h.server.store.GetResource("vendor")
			method := "GET"
			var err error
			switch kind {
			case "disabled":
				item.Status = "disabled"
				err = d.h.server.store.UpsertResource(item)
			case "deleted":
				_, err = d.h.server.store.DeleteResource("vendor")
			case "method":
				item.HTTPMethods = []string{"GET"}
				method = "HEAD"
				err = d.h.server.store.UpsertResource(item)
			case "blocked":
				item.Domains = []resources.DomainRule{{Host: "vendor.example", Behavior: "block"}}
				err = d.h.server.store.UpsertResource(item)
			}
			if err != nil {
				t.Fatal(err)
			}
			if rec := d.serve(method, "/private", d.grant, nil); rec.Code != 403 || d.vendor.hits.Load() != 0 {
				t.Fatalf("policy denial: %d", rec.Code)
			}
		})
	}
}

func TestVendorDeliveryResourceChangeDuringUpstreamRequest(t *testing.T) {
	d := newDeliveryHarness(t)
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() { result <- d.serve("GET", "/slow", d.grant, nil) }()
	<-d.vendor.entered
	item, _, _ := d.h.server.store.GetResource("vendor")
	item.Status = "disabled"
	if err := d.h.server.store.UpsertResource(item); err != nil {
		t.Fatal(err)
	}
	close(d.vendor.release)
	rec := <-result
	if rec.Code == 200 || strings.Contains(rec.Body.String(), vendorBodyMarker) {
		t.Fatalf("response delivered after its resource was disabled: %d", rec.Code)
	}
}

func TestVendorDeliveryCookieRoundTripAndBrowserBoundary(t *testing.T) {
	d := newDeliveryHarness(t)
	rec := d.serve("GET", "/set?v=alice", d.grant, nil)
	if rec.Code != 200 || len(rec.Result().Cookies()) != 0 || rec.Header().Values("Set-Cookie") != nil {
		t.Fatal("upstream Set-Cookie reached the browser")
	}
	rec = d.serve("GET", "/echo", d.grant, func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: "__Host-odo_session", Value: d.central})
		r.AddCookie(&http.Cookie{Name: vendorNonceCookie, Value: d.nonce})
		r.AddCookie(&http.Cookie{Name: "browser", Value: "untrusted"})
		r.Header.Set("Authorization", "Bearer secret")
		r.Header.Set("Proxy-Authorization", "Basic secret")
		r.Header.Set("Forwarded", "for=10.0.0.1;host=odo.example")
		r.Header.Set("X-Forwarded-For", "10.0.0.1")
		r.Header.Set("X-Forwarded-Host", "odo.example")
		r.Header.Set("X-CSRF-Token", "csrf-secret")
		r.Header.Set("Connection", "X-Hop")
		r.Header.Set("X-Hop", "hop")
		r.Header.Set("Accept-Language", "en")
	})
	if rec.Code != 200 || rec.Body.String() != "cookie=who=alice" {
		t.Fatalf("vendor jar round trip failed: %q", rec.Body.String())
	}
	last := d.vendor.lastRequest()
	for _, name := range []string{"Authorization", "Proxy-Authorization", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Csrf-Token", "X-Hop"} {
		if last.Header.Get(name) != "" {
			t.Fatalf("browser header %s reached upstream", name)
		}
	}
	if last.Header.Get("Accept-Language") != "en" {
		t.Fatal("safe request header was not forwarded")
	}
}

func TestVendorDeliveryJarIsolation(t *testing.T) {
	d := newDeliveryHarness(t)
	_, aliceTwo := d.grantFor(t, d.parentUserID(t))
	bob := createLocalTestUser(t, d.h.server, "bob", "correct horse battery")
	_, bobGrant := d.grantFor(t, bob.ID)
	if rec := d.serve("GET", "/set?v=alice-one", d.grant, nil); rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	for name, grant := range map[string]string{"second session of one user": aliceTwo, "another user": bobGrant} {
		if rec := d.serve("GET", "/echo", grant, nil); rec.Code != 200 || rec.Body.String() != "cookie=" {
			t.Fatalf("%s received another jar's cookies", name)
		}
	}
	if rec := d.serve("GET", "/echo", d.grant, nil); rec.Body.String() != "cookie=who=alice-one" {
		t.Fatal("original jar lost its cookie")
	}
}

func TestVendorDeliverySameHostTwoResources(t *testing.T) {
	d := newDeliveryHarness(t)
	if rec := d.serve("GET", "/set?v=vendor-resource", d.grant, nil); rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	// A second resource for the same host now wins existing matching order. The
	// grant never selects a jar: the new winner gets its own, empty jar.
	winner := resources.Resource{ID: "a-winner", Name: "Winner", Domains: []resources.DomainRule{{Host: "vendor.example"}}, CookiePolicy: resources.CookiePolicy{Enabled: true}}
	if err := d.h.server.store.UpsertResource(winner); err != nil {
		t.Fatal(err)
	}
	if rec := d.serve("GET", "/echo", d.grant, nil); rec.Code != 200 || rec.Body.String() != "cookie=" {
		t.Fatalf("new winning resource received another resource's cookies: %q", rec.Body.String())
	}
}

func TestVendorDeliverySSRFAndUpstreamFailures(t *testing.T) {
	for _, kind := range []string{"private", "loopback", "rebinding", "dns", "tls", "connect"} {
		t.Run(kind, func(t *testing.T) {
			d := newDeliveryHarness(t)
			var calls atomic.Int32
			switch kind {
			case "private", "loopback":
				ip := map[string]string{"private": "10.0.0.7", "loopback": "127.0.0.1"}[kind]
				d.setResolver(func(context.Context, string) ([]net.IPAddr, error) { return []net.IPAddr{{IP: net.ParseIP(ip)}}, nil })
			case "rebinding":
				// Public during authorization, private at connection time.
				d.setResolver(func(ctx context.Context, host string) ([]net.IPAddr, error) {
					if calls.Add(1) == 1 {
						return publicVendorLookup(ctx, host)
					}
					return []net.IPAddr{{IP: net.ParseIP("192.168.1.10")}}, nil
				})
			case "dns":
				d.setResolver(func(context.Context, string) ([]net.IPAddr, error) { return nil, errors.New("no such host") })
			case "tls":
				wrong := newFakeVendor(t, "other.example")
				address := wrong.server.Listener.Addr().String()
				d.dialTo.Store(&address)
				defer func() {
					if wrong.hits.Load() != 0 {
						t.Fatal("request completed despite an invalid certificate")
					}
				}()
			case "connect":
				closed, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				address := closed.Addr().String()
				_ = closed.Close()
				d.dialTo.Store(&address)
			}
			rec := d.serve("GET", "/private", d.grant, nil)
			if rec.Code != 502 || d.vendor.hits.Load() != 0 || strings.Contains(rec.Body.String(), vendorBodyMarker) {
				t.Fatalf("got %d", rec.Code)
			}
			if kind == "rebinding" && calls.Load() < 2 {
				t.Fatal("connection-time validation did not run")
			}
		})
	}
}

func TestVendorDeliveryRedirectsAndResponseHeaders(t *testing.T) {
	d := newDeliveryHarness(t)
	rec := d.serve("GET", "/private", d.grant, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), vendorBodyMarker) {
		t.Fatal(rec.Code)
	}
	for _, name := range []string{"Content-Security-Policy", "Access-Control-Allow-Origin", "Strict-Transport-Security", "Refresh", "Link", "Alt-Svc", "Set-Cookie", "Set-Cookie2", "X-Internal-Debug", "Location"} {
		if rec.Header().Get(name) != "" {
			t.Fatalf("unsafe upstream header %s reached the browser", name)
		}
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Content-Language") != "en" || rec.Header().Get("ETag") != `"v1"` || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("safe or required response headers missing")
	}
	for to, want := range map[string]string{
		"/next?x=1%2F2":                     "https://" + d.authority + "/next?x=1%2F2",
		"https://VENDOR.example:443/a#frag": "https://" + d.authority + "/a",
		"https://evil.example/":             "",
		"http://vendor.example/":            "",
		"https://user@vendor.example/":      "",
		"//evil.example/":                   "",
		"/.well-known/odo/redeem":           "",
		"/a/../b":                           "https://" + d.authority + "/b", // resolved as a browser would
	} {
		rec := d.serve("GET", "/redirect?"+url.Values{"to": {to}}.Encode(), d.grant, nil)
		if want == "" {
			if rec.Code != 502 || rec.Header().Get("Location") != "" {
				t.Fatalf("%s: unsafe redirect was represented (%d)", to, rec.Code)
			}
		} else if rec.Code != 302 || rec.Header().Get("Location") != want {
			t.Fatalf("%s: got %d %q", to, rec.Code, rec.Header().Get("Location"))
		}
	}
}

func TestVendorDeliveryCancellationAndTimeout(t *testing.T) {
	d := newDeliveryHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() { result <- d.serve("GET", "/slow", d.grant, func(r *http.Request) { *r = *r.WithContext(ctx) }) }()
	<-d.vendor.entered
	cancel()
	select {
	case <-d.vendor.done:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream request was not canceled")
	}
	if rec := <-result; rec.Code == 200 {
		t.Fatal("canceled request reported success")
	}
	client := *d.h.vendor
	client.Timeout = 200 * time.Millisecond
	d.h.vendor = &client
	if rec := d.serve("GET", "/slow", d.grant, nil); rec.Code != 504 {
		t.Fatalf("timeout status %d", rec.Code)
	}
}

func TestVendorDeliveryNeverReachesCentralRoutes(t *testing.T) {
	d := newDeliveryHarness(t)
	for _, path := range []string{"/admin", "/login", "/logout", "/api/v1/users", "/resources", "/about", "/source", "/openapi.yaml"} {
		rec := d.serve("GET", path, d.grant, func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: "__Host-odo_session", Value: d.central})
			r.Header.Set("Authorization", "Bearer secret")
		})
		// The path is the vendor's own path: Odo's handler is never invoked.
		if rec.Code != 200 || rec.Body.String() != "vendor-default "+path || d.vendor.lastRequest().Header.Get("Authorization") != "" || strings.Contains(d.vendor.lastRequest().Header.Get("Cookie"), d.central) {
			t.Fatalf("%s reached a central route or leaked credentials", path)
		}
	}
	// The central origin still never delivers vendor content in this mode.
	hits := d.vendor.hits.Load()
	for _, tc := range []struct{ method, path string }{{"GET", "/odo/https/vendor.example/private"}, {"POST", "/odo/https/vendor.example/private"}, {"GET", "/odo?url=https://vendor.example/private"}} {
		req := httptest.NewRequest(tc.method, "https://odo.example"+tc.path, nil)
		req.AddCookie(&http.Cookie{Name: "__Host-odo_session", Value: d.central})
		rec := httptest.NewRecorder()
		d.routes.ServeHTTP(rec, req)
		if rec.Code == 200 || strings.Contains(rec.Body.String(), vendorBodyMarker) {
			t.Fatalf("central origin delivered vendor content: %s %s", tc.method, tc.path)
		}
	}
	if d.vendor.hits.Load() != hits {
		t.Fatal("central origin fetched vendor content")
	}
}

func TestVendorDeliveryDisabledAndProductionRejected(t *testing.T) {
	b := newHandoffBrowser(t, false, true)
	if b.h.server.handoff != nil {
		t.Fatal("experiment constructed while disabled")
	}
	vendor := newFakeVendor(t, "vendor.example")
	req := httptest.NewRequest("GET", "https://"+b.authority+"/private", nil)
	req.AddCookie(&http.Cookie{Name: vendorGrantCookie, Value: b.vendor})
	rec := httptest.NewRecorder()
	b.h.server.Routes().ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), vendorBodyMarker) || vendor.hits.Load() != 0 {
		t.Fatal("disabled experiment delivered vendor content")
	}

	t.Setenv("APP_EXPERIMENTAL_HANDOFF", "true")
	t.Setenv("APP_HOST_GUARD", "true")
	t.Setenv("APP_PUBLIC_URL", "https://odo.example")
	t.Setenv("APP_PROXY_BASE_DOMAIN", "proxy.example")
	t.Setenv("APP_ENV", "production")
	if err := ValidateHostGuardConfig(); err == nil {
		t.Fatal("production accepted experimental vendor delivery")
	}
	server := NewServer(b.h.server.store, t.TempDir(), "secret", b.h.server.logger)
	if server.handoff != nil || server.handoffErr == nil {
		t.Fatal("production constructed the experimental runtime")
	}
	rec = httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, httptest.NewRequest("GET", "https://"+b.authority+"/private", nil))
	if rec.Code != 503 {
		t.Fatalf("production experiment did not fail closed: %d", rec.Code)
	}
	if _, err := newHandoffRuntime(server, proxy.HostRoutingConfig{}); err == nil {
		t.Fatal("runtime construction accepted an invalid deployment")
	}
}

func navigation(r *http.Request) {
	r.Header.Set("Accept", "text/html")
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	r.Header.Set("Sec-Fetch-Dest", "document")
}

func TestVendorDeliveryRestartsHandoff(t *testing.T) {
	relaunch := "https://odo.example/launch?" + url.Values{"url": {"https://vendor.example/private?search=private-search"}}.Encode()
	for _, kind := range []string{"missing", "invalid", "expired", "logout"} {
		t.Run(kind, func(t *testing.T) {
			d := newDeliveryHarness(t)
			grant := d.grant
			switch kind {
			case "missing":
				grant = ""
			case "invalid":
				grant = strings.Repeat("A", len(d.grant))
			case "expired":
				d.h.state.mu.Lock()
				for key, value := range d.h.state.grants {
					value.expires = time.Now().Add(-time.Second)
					d.h.state.grants[key] = value
				}
				d.h.state.mu.Unlock()
			case "logout":
				requestLogout(d.h.server, &http.Cookie{Name: "__Host-odo_session", Value: d.central})
			}
			rec := d.serve("GET", "/private?search=private-search", grant, navigation)
			if rec.Code != 303 || rec.Header().Get("Location") != relaunch || rec.Body.Len() != 0 || rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("navigation did not restart the handoff: %d %q", rec.Code, rec.Header().Get("Location"))
			}
			if d.vendor.hits.Load() != 0 {
				t.Fatal("restart reached upstream")
			}
		})
	}
	d := newDeliveryHarness(t)
	for name, edit := range map[string]func(*http.Request){
		"subresource": func(r *http.Request) { navigation(r); r.Header.Set("Sec-Fetch-Dest", "image") },
		"fetch":       func(r *http.Request) { navigation(r); r.Header.Set("Sec-Fetch-Mode", "cors") },
		"json":        func(r *http.Request) { r.Header.Set("Accept", "application/json") },
		"duplicate": func(r *http.Request) {
			navigation(r)
			r.AddCookie(&http.Cookie{Name: vendorGrantCookie, Value: d.grant})
		},
	} {
		grant := ""
		if name == "duplicate" {
			grant = d.grant
		}
		if rec := d.serve("GET", "/private", grant, edit); rec.Code != 401 || rec.Header().Get("Location") != "" {
			t.Fatalf("%s: non-navigation restarted the handoff (%d)", name, rec.Code)
		}
	}
	if rec := d.serve("HEAD", "/private", "", navigation); rec.Code != 401 {
		t.Fatalf("HEAD restarted the handoff (%d)", rec.Code)
	}
	// A live grant denied by current policy is never redirected.
	item, _, _ := d.h.server.store.GetResource("vendor")
	item.Status = "disabled"
	if err := d.h.server.store.UpsertResource(item); err != nil {
		t.Fatal(err)
	}
	if rec := d.serve("GET", "/private", d.grant, navigation); rec.Code != 403 || rec.Header().Get("Location") != "" {
		t.Fatalf("policy denial restarted the handoff (%d)", rec.Code)
	}
}

// The real browser loop: entry without a grant, handoff, return to the target,
// grant expiry, re-handoff, and the vendor jar surviving across grants.
func TestVendorDeliveryBrowserReHandoffKeepsVendorSession(t *testing.T) {
	d := newDeliveryHarness(t)
	visit := func(path string) (*http.Response, string) {
		d.target = "https://vendor.example" + path
		response, _ := d.request(t, "GET", "https://"+d.authority+path, nil)
		relaunch := "https://odo.example/launch?" + url.Values{"url": {d.target}}.Encode()
		if response.StatusCode != 303 || response.Header.Get("Location") != relaunch {
			t.Fatalf("%s: no re-handoff (%d)", path, response.StatusCode)
		}
		d.finish(t, d.ticket(t))
		return d.request(t, "GET", "https://"+d.authority+path, nil)
	}
	if response, body := visit("/set?v=patron"); response.StatusCode != 200 || body != "set" {
		t.Fatalf("entry handoff did not reach the vendor (%d)", response.StatusCode)
	}
	d.h.state.mu.Lock()
	for key, value := range d.h.state.grants {
		value.expires = time.Now().Add(-time.Second)
		d.h.state.grants[key] = value
	}
	d.h.state.mu.Unlock()
	if response, body := visit("/echo"); response.StatusCode != 200 || body != "cookie=who=patron" {
		t.Fatalf("vendor session did not survive re-handoff: %q", body)
	}
}

// Redemption and upstream redirects share these rules: a URL built from the
// trusted authority, `//` paths kept on it, vendor parameters preserved, and
// Odo's reserved namespace rejected in escaped forms too.
func TestVendorRedirectLocationRules(t *testing.T) {
	base, _ := url.Parse("https://vendor.example/start")
	const authority = "h-test.proxy.example"
	for raw, want := range map[string]string{
		"https://vendor.example//evil.example/x":            "https://" + authority + "//evil.example/x",
		"https://vendor.example/a?ticket=1&url=https%3A%2F": "https://" + authority + "/a?ticket=1&url=https%3A%2F",
		"https://vendor.example/%2Ewell-known/odo/redeem":   "",
		"https://vendor.example/.WELL-KNOWN/odo/x":          "",
		"https://vendor.example.evil/":                      "",
		"https://vendor.example:8443/":                      "",
	} {
		got, ok := vendorRedirectLocation(base, "vendor.example", authority, raw)
		if (want == "") == ok || got != want {
			t.Fatalf("%s: got %q %v", raw, got, ok)
		}
	}
}

func (d *deliveryHarness) grantState(t *testing.T) handoffGrant {
	t.Helper()
	d.h.state.mu.Lock()
	defer d.h.state.mu.Unlock()
	grant, found := d.h.state.grants[local.HashToken(d.grant)]
	if !found {
		t.Fatal("grant state missing")
	}
	return grant
}

func (d *deliveryHarness) setGrantState(grant handoffGrant) {
	d.h.state.mu.Lock()
	defer d.h.state.mu.Unlock()
	d.h.state.grants[local.HashToken(d.grant)] = grant
}

func TestGrantRenewalSlidesWithinParentLimit(t *testing.T) {
	d := newDeliveryHarness(t)
	mapping, err := d.h.mapping(d.authority)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC()
	if _, renewed := d.h.state.renewGrant(d.grant, mapping, d.authority, start); renewed {
		t.Fatal("fresh grant renewed inside the throttle interval")
	}
	later := start.Add(10 * time.Minute)
	expires, renewed := d.h.state.renewGrant(d.grant, mapping, d.authority, later)
	if !renewed || !expires.Equal(later.Add(handoffGrantTTL)) || !d.grantState(t).expires.Equal(expires) {
		t.Fatal("active grant did not slide")
	}
	// Renewal never passes the parent's absolute session expiry.
	grant := d.grantState(t)
	grant.limit = later.Add(handoffGrantTTL + 5*time.Minute)
	d.setGrantState(grant)
	if expires, renewed = d.h.state.renewGrant(d.grant, mapping, d.authority, later.Add(20*time.Minute)); !renewed || !expires.Equal(grant.limit) {
		t.Fatal("renewal exceeded the parent's absolute expiry")
	}
	if _, renewed = d.h.state.renewGrant(d.grant, mapping, d.authority, later.Add(25*time.Minute)); renewed {
		t.Fatal("capped grant renewed again")
	}
	other, err := d.h.server.store.RegisterProxyHostname("vendor2.example", "odo.example", "proxy.example")
	if err != nil {
		t.Fatal(err)
	}
	for name, check := range map[string]func() bool{
		"other mapping": func() bool {
			_, ok := d.h.state.renewGrant(d.grant, other, d.authority, later.Add(21*time.Minute))
			return ok
		},
		"other authority": func() bool {
			_, ok := d.h.state.renewGrant(d.grant, mapping, other.Label+".proxy.example", later.Add(21*time.Minute))
			return ok
		},
		"invalid token": func() bool {
			_, ok := d.h.state.renewGrant("invalid", mapping, d.authority, later.Add(21*time.Minute))
			return ok
		},
		"expired": func() bool {
			_, ok := d.h.state.renewGrant(d.grant, mapping, d.authority, grant.limit.Add(time.Second))
			return ok
		},
	} {
		if check() {
			t.Fatalf("%s renewed a grant", name)
		}
	}
	d.h.state.mu.Lock()
	_, found := d.h.state.grants[local.HashToken(d.grant)]
	d.h.state.mu.Unlock()
	if found {
		t.Fatal("expired grant was revived")
	}
}

func TestVendorDeliveryRenewsGrantOnAuthorizedUse(t *testing.T) {
	d := newDeliveryHarness(t)
	// A grant redeemed twenty minutes ago: ten minutes of its window remain.
	age := func() handoffGrant {
		grant := d.grantState(t)
		grant.expires = time.Now().UTC().Add(10 * time.Minute)
		d.setGrantState(grant)
		return grant
	}
	aged := age()
	rec := d.serve("GET", "/private", d.grant, nil)
	cookies := rec.Result().Cookies()
	if rec.Code != 200 || len(cookies) != 1 || len(rec.Header().Values("Set-Cookie")) != 1 {
		t.Fatalf("authorized use did not refresh exactly the grant cookie (%d)", rec.Code)
	}
	cookie := cookies[0]
	if cookie.Name != vendorGrantCookie || cookie.Value != d.grant || !cookie.Secure || !cookie.HttpOnly || cookie.Domain != "" || cookie.Path != "/" ||
		cookie.SameSite != http.SameSiteLaxMode || cookie.MaxAge < int((handoffGrantTTL-time.Minute).Seconds()) || cookie.MaxAge > int(handoffGrantTTL.Seconds()) {
		t.Fatal("refreshed grant cookie has wrong attributes")
	}
	if !d.grantState(t).expires.After(aged.expires.Add(15*time.Minute)) || !d.grantState(t).limit.Equal(aged.limit) {
		t.Fatal("server-side grant did not slide, or its parent limit changed")
	}
	// Immediately again: throttled, so no cookie churn on routine assets.
	if rec := d.serve("GET", "/private", d.grant, nil); rec.Code != 200 || len(rec.Result().Cookies()) != 0 {
		t.Fatal("renewal was not throttled")
	}
	// Denials and upstream failures are not authorized use and never renew.
	for name, setup := range map[string]func(){
		"upstream failure": func() {
			d.setResolver(func(context.Context, string) ([]net.IPAddr, error) { return nil, errors.New("no such host") })
		},
		"unsupported redirect": func() { d.setResolver(publicVendorLookup) },
		"policy denial": func() {
			d.setResolver(publicVendorLookup)
			item, _, _ := d.h.server.store.GetResource("vendor")
			item.HTTPMethods = []string{"GET"}
			if err := d.h.server.store.UpsertResource(item); err != nil {
				t.Fatal(err)
			}
		},
	} {
		aged = age()
		method, path := "GET", "/private"
		if name == "policy denial" {
			method = "HEAD"
		}
		if name == "unsupported redirect" {
			path = "/redirect?" + url.Values{"to": {"https://evil.example/"}}.Encode()
		}
		setup()
		if rec := d.serve(method, path, d.grant, nil); rec.Code < 400 || len(rec.Result().Cookies()) != 0 || !d.grantState(t).expires.Equal(aged.expires) {
			t.Fatalf("%s renewed the grant (%d)", name, rec.Code)
		}
	}
	// A revoked parent ends the grant at once, however recently it was renewed.
	d.setResolver(publicVendorLookup)
	requestLogout(d.h.server, &http.Cookie{Name: "__Host-odo_session", Value: d.central})
	if rec := d.serve("GET", "/private", d.grant, func(r *http.Request) { r.Header.Set("Sec-Fetch-Dest", "image") }); rec.Code != 401 || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("renewed grant outlived its parent session (%d %v)", rec.Code, rec.Result().Cookies())
	}
}

// Session revocation while the upstream request is in flight: the response is
// reauthorized before cookie storage, so it fails closed and stores nothing.
func TestVendorDeliverySessionRevokedDuringUpstreamRequest(t *testing.T) {
	for _, kind := range []string{"logout", "password", "disabled account"} {
		t.Run(kind, func(t *testing.T) {
			d := newDeliveryHarness(t)
			parent, _, _ := d.h.server.store.GetSession(local.SessionIDFromToken(d.central))
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				result <- d.serve("GET", "/slow", d.grant, func(r *http.Request) { r.Header.Set("Sec-Fetch-Dest", "image") })
			}()
			<-d.vendor.entered
			var err error
			switch kind {
			case "logout":
				requestLogout(d.h.server, &http.Cookie{Name: "__Host-odo_session", Value: d.central})
			case "password":
				_, err = d.h.server.store.SetUserPassword(parent.UserID, "new-hash")
			case "disabled account":
				_, _, err = d.h.server.store.SetUserStatus(parent.UserID, "disabled")
			}
			if err != nil {
				t.Fatal(err)
			}
			close(d.vendor.release)
			rec := <-result
			if rec.Code != 401 || strings.Contains(rec.Body.String(), vendorBodyMarker) || len(rec.Result().Cookies()) != 0 {
				t.Fatalf("revoked session's response was delivered: %d", rec.Code)
			}
		})
	}
}

// A cookie-policy change retires the jar, and reverting the change creates a
// fresh generation rather than reviving the retired cookies.
func TestVendorDeliveryPolicyReversionDoesNotReviveCookies(t *testing.T) {
	d := newDeliveryHarness(t)
	if rec := d.serve("GET", "/set?v=before", d.grant, nil); rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	item, _, _ := d.h.server.store.GetResource("vendor")
	for _, enabled := range []bool{false, true} {
		item.CookiePolicy.Enabled = enabled
		if err := d.h.server.store.UpsertResource(item); err != nil {
			t.Fatal(err)
		}
		if rec := d.serve("GET", "/echo", d.grant, nil); rec.Code != 200 || rec.Body.String() != "cookie=" {
			t.Fatalf("cookie policy enabled=%v served a retired cookie: %q", enabled, rec.Body.String())
		}
	}
	if rec := d.serve("GET", "/set?v=after", d.grant, nil); rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	if rec := d.serve("GET", "/echo", d.grant, nil); rec.Body.String() != "cookie=who=after" {
		t.Fatalf("current generation lost its cookie: %q", rec.Body.String())
	}
}

// A response Odo refuses to deliver leaves no cookie in the browser or jar.
func TestVendorDeliveryFailedResponsesStoreNoState(t *testing.T) {
	d := newDeliveryHarness(t)
	if rec := d.serve("GET", "/redirect?"+url.Values{"to": {"https://evil.example/"}, "cookie": {"from-failed-redirect"}}.Encode(), d.grant, nil); rec.Code != 502 || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("unsupported redirect: %d", rec.Code)
	}
	if rec := d.serve("GET", "/switch", d.grant, nil); rec.Code != 502 || strings.Contains(rec.Body.String(), vendorBodyMarker) || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("protocol switch was forwarded: %d", rec.Code)
	}
	if rec := d.serve("GET", "/echo", d.grant, nil); rec.Code != 200 || rec.Body.String() != "cookie=" {
		t.Fatalf("failed response stored vendor cookies: %q", rec.Body.String())
	}
}

func (d *deliveryHarness) grantCount() int {
	d.h.state.mu.Lock()
	defer d.h.state.mu.Unlock()
	return len(d.h.state.grants)
}

// Post-commit retirement: a committed resource change clears idle jars at
// commit, with no request in between.
func TestVendorDeliveryResourceCommitRetiresIdleJars(t *testing.T) {
	for _, kind := range []string{"cookie policy disabled", "resource disabled", "resource deleted", "identical write"} {
		t.Run(kind, func(t *testing.T) {
			d := newDeliveryHarness(t)
			if rec := d.serve("GET", "/set?v=idle", d.grant, nil); rec.Code != 200 || d.h.cookies.jars.Len() != 1 {
				t.Fatal("jar not allocated")
			}
			item, _, _ := d.h.server.store.GetResource("vendor")
			var err error
			switch kind {
			case "cookie policy disabled":
				item.CookiePolicy.Enabled = false
				err = d.h.server.store.UpsertResource(item)
			case "resource disabled":
				item.Status = "disabled"
				err = d.h.server.store.UpsertResource(item)
			case "resource deleted":
				_, err = d.h.server.store.DeleteResource("vendor")
			case "identical write":
				err = d.h.server.store.UpsertResource(item)
			}
			if err != nil {
				t.Fatal(err)
			}
			if d.h.cookies.jars.Len() != 0 {
				t.Fatal("committed resource change left the idle jar allocated")
			}
		})
	}
}

// Post-commit retirement: committed session revocation clears that parent's
// jars and handoff grants at once, and leaves other patrons untouched.
func TestVendorDeliverySessionRevocationRetiresJarsAndGrants(t *testing.T) {
	for _, kind := range []string{"logout", "admin revoke", "password", "disabled", "locked", "deleted"} {
		t.Run(kind, func(t *testing.T) {
			d := newDeliveryHarness(t)
			bob := createLocalTestUser(t, d.h.server, "bob", "correct horse battery")
			_, bobGrant := d.grantFor(t, bob.ID)
			for _, grant := range []string{d.grant, bobGrant} {
				if rec := d.serve("GET", "/set?v=x", grant, nil); rec.Code != 200 {
					t.Fatal(rec.Code)
				}
			}
			if d.h.cookies.jars.Len() != 2 || d.grantCount() != 2 {
				t.Fatal("setup did not allocate two jars and grants")
			}
			parent, _, _ := d.h.server.store.GetSession(local.SessionIDFromToken(d.central))
			var err error
			switch kind {
			case "logout":
				requestLogout(d.h.server, &http.Cookie{Name: "__Host-odo_session", Value: d.central})
			case "admin revoke":
				err = d.h.server.store.RevokeUserSessions(parent.UserID)
			case "password":
				_, err = d.h.server.store.SetUserPassword(parent.UserID, "new-hash")
			case "disabled", "locked":
				_, _, err = d.h.server.store.SetUserStatus(parent.UserID, kind)
			case "deleted":
				_, err = d.h.server.store.DeleteUser(parent.UserID, "")
			}
			if err != nil {
				t.Fatal(err)
			}
			if d.h.cookies.jars.Len() != 1 || d.grantCount() != 1 {
				t.Fatalf("revocation left jars=%d grants=%d (want only bob's)", d.h.cookies.jars.Len(), d.grantCount())
			}
			if rec := d.serve("GET", "/echo", bobGrant, nil); rec.Code != 200 || rec.Body.String() != "cookie=who=x" {
				t.Fatal("another patron's vendor session was retired")
			}
		})
	}
}
