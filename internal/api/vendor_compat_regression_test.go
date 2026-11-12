package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"example.org/odo/internal/accesslog"
	"example.org/odo/internal/proxy"
	"example.org/odo/internal/resources"
)

const (
	jstorPublicIP = "93.184.216.40"
	osmTileURL    = "https://tile.openstreetmap.org/{z}/{x}/{y}.png"
)

// recordingLookup resolves hosts with resolve and remembers every name asked.
type recordingLookup struct {
	mu      sync.Mutex
	asked   map[string]bool
	resolve func(host string) ([]net.IPAddr, error)
}

func (l *recordingLookup) lookup(_ context.Context, host string) ([]net.IPAddr, error) {
	l.mu.Lock()
	l.asked[host] = true
	l.mu.Unlock()
	return l.resolve(host)
}

func (l *recordingLookup) wasAsked(host string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.asked[host]
}

func loadJSTORFixture(t *testing.T) resources.Resource {
	t.Helper()
	data, err := os.ReadFile("testdata/jstor-resource.json")
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := resources.Decode(data)
	if err != nil {
		t.Fatalf("known-good JSTOR configuration no longer validates: %v", err)
	}
	return fixture
}

// The JSTOR configuration that works against the real vendor is a regression
// fixture: its validated semantics, launch policy, hostname enrollment and the
// full handoff/delivery path must keep working without editing it.
func TestJSTORFixtureRegression(t *testing.T) {
	fixture := loadJSTORFixture(t)
	again, err := resources.Validate(fixture)
	if err != nil || !reflect.DeepEqual(again, fixture) {
		t.Fatal("JSTOR fixture normalization is not stable")
	}
	if fixture.ID != "jstor" || fixture.Status != "active" || len(fixture.Domains) != 12 ||
		!reflect.DeepEqual(fixture.HTTPMethods, []string{"GET", "HEAD", "POST", "PUT", "PATCH", "OPTIONS", "DELETE"}) ||
		!fixture.CookiePolicy.Enabled || !reflect.DeepEqual(fixture.CookiePolicy.AllowedCookieDomains, []string{"jstor.org"}) {
		t.Fatalf("JSTOR fixture semantics changed: %+v", fixture)
	}

	// Launch-target policy, without DNS.
	for target, want := range map[string]string{
		"https://www.jstor.org/stable/123":      "proxy",
		"https://about.jstor.org/":              "proxy",
		"https://jstor.org/":                    "proxy",
		"https://search.jstor.org/":             "proxy",
		"https://www.jstore.org/":               "proxy",
		"https://analytics.example.com/":        "blocked",
		"https://www.jstor.org.evil.example/":   "denied",
		"https://notjstor.org/":                 "denied",
		"http://www.jstor.org/":                 "denied",
		"https://bucket.s3.amazonaws.com/x.pdf": "proxy",
	} {
		result := resources.TestURL(target, []resources.Resource{fixture})
		got := "denied"
		switch {
		case result.Blocked:
			got = "blocked"
		case result.Allowed && result.Action == "proxy" && result.ResourceID == "jstor":
			got = "proxy"
		}
		if got != want {
			t.Fatalf("%s: policy %s, want %s (%s)", target, got, want, result.Reason)
		}
		if want == "proxy" {
			for _, method := range []string{"GET", "HEAD", "POST"} {
				if !resources.MethodAllowed(result, method) {
					t.Fatalf("%s: %s no longer allowed", target, method)
				}
			}
		}
	}

	d := newDeliveryHarness(t)
	if err := d.h.server.store.UpsertResource(fixture); err != nil {
		t.Fatal(err)
	}
	// Enrollment: exact proxy hosts only, with readable names. Subdomain-only
	// hosts, blocked hosts and the S3 rule are never discovered or enrolled.
	if _, err := d.h.server.store.ReconcileProxyHostnames("odo.example", "proxy.example", nil); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"www.jstor.org", "about.jstor.org", "dfr.jstor.org", "labs.jstor.org", "links.jstor.org", "mobile.jstor.org", "plants.jstor.org", "uk.jstor.org"} {
		record, found, err := d.h.server.store.LookupProxyHostnameByUpstream(host)
		if err != nil || !found || record.Label != strings.ReplaceAll(host, ".", "-") {
			t.Fatalf("%s not enrolled with its readable name: %+v %v", host, record, err)
		}
	}
	for _, host := range []string{"jstor.org", "jstore.org", "amazonaws.com", "analytics.example.com", "search.jstor.org"} {
		if _, found, _ := d.h.server.store.LookupProxyHostnameByUpstream(host); found {
			t.Fatalf("%s was enrolled automatically", host)
		}
	}

	const index = `<!doctype html><title>JSTOR fixture</title>
<a id="stable" href="https://www.jstor.org/stable/1">Stable</a>
<a id="about" href="https://about.jstor.org/info">About</a>
<a id="apex" href="https://jstor.org/x">Apex</a>
<img id="tile" src="https://tile.openstreetmap.org/1/0/0.png" alt="">`
	jstor := newFakeVendorSite(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := func() bool {
			cookie, err := r.Cookie("UUID")
			if err != nil || cookie.Value != "jstor-session" {
				http.Error(w, "jstor session required", http.StatusForbidden)
				return false
			}
			return true
		}
		switch r.Host + r.URL.Path {
		case "www.jstor.org/":
			http.SetCookie(w, &http.Cookie{Name: "UUID", Value: "jstor-session", Domain: "jstor.org", Path: "/", Secure: true, HttpOnly: true})
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = io.WriteString(w, index)
		case "www.jstor.org/stable/1":
			if session() {
				_, _ = io.WriteString(w, "stable-ok")
			}
		case "www.jstor.org/go-about":
			http.Redirect(w, r, "https://about.jstor.org/info", http.StatusFound)
		case "www.jstor.org/go-apex":
			http.Redirect(w, r, "https://jstor.org/", http.StatusFound)
		case "about.jstor.org/info":
			if session() {
				_, _ = io.WriteString(w, "about-ok")
			}
		default:
			http.NotFound(w, r)
		}
	}), "www.jstor.org", "about.jstor.org")
	resolver := &recordingLookup{asked: map[string]bool{}, resolve: func(host string) ([]net.IPAddr, error) {
		switch {
		case host == "vendor.example":
			return []net.IPAddr{{IP: net.ParseIP(vendorPublicIP)}}, nil
		case host == "analytics.example.com":
			// Resolvable, so the launch is refused by the block rule itself.
			return []net.IPAddr{{IP: net.ParseIP(jstorPublicIP)}}, nil
		case host == "jstor.org" || strings.HasSuffix(host, ".jstor.org"):
			return []net.IPAddr{{IP: net.ParseIP(jstorPublicIP)}}, nil
		}
		return nil, errors.New("unexpected test hostname")
	}}
	d.setResolver(resolver.lookup)
	roots := d.vendor.roots.Clone()
	roots.AddCert(jstor.server.TLS.Certificates[0].Leaf)
	d.h.vendor = proxy.NewSafeHTTPClient(resolver.lookup, func(ctx context.Context, network, address string) (net.Conn, error) {
		switch address {
		case net.JoinHostPort(vendorPublicIP, "443"):
			return (&net.Dialer{}).DialContext(ctx, network, d.vendor.server.Listener.Addr().String())
		case net.JoinHostPort(jstorPublicIP, "443"):
			return (&net.Dialer{}).DialContext(ctx, network, jstor.server.Listener.Addr().String())
		}
		return nil, errors.New("unexpected validated test address")
	}, &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12})
	t.Cleanup(d.h.vendor.CloseIdleConnections)

	// Launch, handoff (with sibling grants) and delivery of the entry page.
	start := "https://odo.example/launch?" + url.Values{"url": {"https://www.jstor.org/"}}.Encode()
	response, body := followAutomaticHandoff(t, d.handoffBrowser, start)
	const www = "www-jstor-org.proxy.example"
	if response.StatusCode != 200 || response.Request.URL.Host != www || !strings.Contains(body, "JSTOR fixture") {
		t.Fatalf("JSTOR launch did not deliver the entry page: %d %s", response.StatusCode, response.Request.URL.Host)
	}
	links := pageURLs(t, []byte(body))
	if links["stable"] != "https://"+www+"/stable/1" || links["about"] != "https://about-jstor-org.proxy.example/info" ||
		links["apex"] != "https://jstor.org/x" || links["tile"] != "https://tile.openstreetmap.org/1/0/0.png" {
		t.Fatalf("JSTOR links rewritten incorrectly: %v", links)
	}
	if response.Header.Get("Referrer-Policy") != vendorReferrerPolicy || response.Header.Get("Content-Security-Policy") != "" {
		t.Fatal("JSTOR page response policy headers changed")
	}
	for _, cookie := range d.client.Jar.Cookies(response.Request.URL) {
		if cookie.Name != vendorGrantCookie && cookie.Name != vendorNonceCookie {
			t.Fatalf("vendor cookie %q reached the browser", cookie.Name)
		}
	}
	// The vendor session cookie lives only in Odo's resource jar.
	if got, data := d.browse(t, "GET", "https://"+www+"/stable/1", "document", nil); got.StatusCode != 200 || string(data) != "stable-ok" {
		t.Fatalf("jar cookie not replayed: %d", got.StatusCode)
	}
	if head, data := d.browse(t, "HEAD", "https://"+www+"/", "document", nil); head.StatusCode != 200 || len(data) != 0 || !strings.HasPrefix(head.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("HEAD delivery: %d", head.StatusCode)
	}
	redirect, _ := d.browse(t, "GET", "https://"+www+"/go-about", "document", nil)
	if redirect.StatusCode != http.StatusFound || redirect.Header.Get("Location") != "https://about-jstor-org.proxy.example/info" {
		t.Fatalf("same-resource redirect not translated: %d %q", redirect.StatusCode, redirect.Header.Get("Location"))
	}
	if about, data := d.browse(t, "GET", redirect.Header.Get("Location"), "document", nil); about.StatusCode != 200 || string(data) != "about-ok" {
		t.Fatalf("sibling host did not share the resource jar: %d", about.StatusCode)
	}
	// A redirect to a host with no registered proxy name cannot be represented.
	if apex, _ := d.browse(t, "GET", "https://"+www+"/go-apex", "document", nil); apex.StatusCode != http.StatusBadGateway || apex.Header.Get("Location") != "" {
		t.Fatalf("redirect to unregistered apex: %d", apex.StatusCode)
	}
	if resolver.wasAsked("tile.openstreetmap.org") {
		t.Fatal("Odo resolved a third-party asset host")
	}
	// The block rule still refuses a launch.
	denied, text := d.request(t, "GET", "https://odo.example/launch?"+url.Values{"url": {"https://analytics.example.com/"}}.Encode(), nil)
	if denied.StatusCode != http.StatusForbidden || !strings.Contains(text, `"reason":"resource_policy"`) || lastDenialReason(t, d) != launchDeniedBlocked {
		t.Fatalf("blocked JSTOR host launch: %d %s", denied.StatusCode, text)
	}
}

// A vendor page that loads a public third-party asset (an OpenStreetMap tile
// layer). Odo must neither rewrite nor fetch it, must not apply central page
// policy, and must let the browser send an origin-only Referer, which the tile
// servers require. Odo's own denials stay distinguishable from vendor ones.
func TestVendorPageExternalAssetReferrerPolicy(t *testing.T) {
	page := `<!doctype html><title>Map</title><div id="map"></div>
<img id="tile" src="https://tile.openstreetmap.org/3/2/3.png" alt="">
<script>L.tileLayer('` + osmTileURL + `', {maxZoom: 19}).addTo(map);</script>`
	d := newDeliveryHarnessWithSite(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/map":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Referrer-Policy", "unsafe-url")
			_, _ = io.WriteString(w, page)
		case "/challenge":
			// What a vendor's bot-management layer answers; Odo relays it.
			w.Header().Set("Content-Type", "text/html; charset=UTF-8")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, "<title>Just a moment...</title>vendor-challenge")
		default:
			http.NotFound(w, r)
		}
	}))
	resolver := &recordingLookup{asked: map[string]bool{}, resolve: func(string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP(vendorPublicIP)}}, nil
	}}
	d.setResolver(resolver.lookup)

	rec := d.serve("GET", "/map", d.grant, func(r *http.Request) { r.Header.Set("Sec-Fetch-Dest", "document") })
	if rec.Code != 200 || rec.Header().Get("Referrer-Policy") != vendorReferrerPolicy {
		t.Fatalf("vendor page: %d referrer-policy %q", rec.Code, rec.Header().Get("Referrer-Policy"))
	}
	for _, name := range []string{"Content-Security-Policy", "X-Frame-Options", "Permissions-Policy"} {
		if rec.Header().Get(name) != "" {
			t.Fatalf("central %s applied to vendor page", name)
		}
	}
	body := rec.Body.String()
	if !strings.Contains(body, osmTileURL) || pageURLs(t, []byte(body))["tile"] != "https://tile.openstreetmap.org/3/2/3.png" {
		t.Fatal("third-party tile URLs were rewritten")
	}
	if resolver.wasAsked("tile.openstreetmap.org") {
		t.Fatal("Odo resolved or fetched the third-party tile host")
	}

	// A vendor's own refusal is relayed as the vendor's bytes and status.
	hits := d.vendor.hits.Load()
	rec = d.serve("GET", "/challenge", d.grant, nil)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "vendor-challenge") || d.vendor.hits.Load() != hits+1 ||
		lastAccessEntry(t, d).UpstreamStatus != http.StatusForbidden {
		t.Fatalf("vendor 403 not relayed as upstream response: %d", rec.Code)
	}
	// Odo's own policy refusal (PUT is not in this resource's methods) is JSON,
	// never reaches the vendor and records no upstream status.
	rec = d.serve("PUT", "/map", d.grant, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-origin") })
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"error":"vendor request is not allowed"`) ||
		d.vendor.hits.Load() != hits+1 || lastAccessEntry(t, d).UpstreamStatus != 0 || rec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("Odo policy denial: %d %s", rec.Code, rec.Body.String())
	}
	// A third-party host was never registered, so its proxy name is refused.
	d.authority = "tile-openstreetmap-org.proxy.example"
	rec = d.serve("GET", "/3/2/3.png", d.grant, func(r *http.Request) { r.Header.Set("Sec-Fetch-Dest", "image") })
	if rec.Code != http.StatusMisdirectedRequest || rec.Header().Get("Referrer-Policy") != "no-referrer" || d.vendor.hits.Load() != hits+1 {
		t.Fatalf("unregistered third-party proxy name: %d", rec.Code)
	}
}

func lastAccessEntry(t *testing.T, d *deliveryHarness) accesslog.Entry {
	t.Helper()
	entries := d.h.server.accessLog.Recent()
	if len(entries) == 0 {
		t.Fatal("no access log entries")
	}
	return entries[0]
}

func lastDenialReason(t *testing.T, d *deliveryHarness) string {
	t.Helper()
	return lastAccessEntry(t, d).DenialReason
}

// Every "launch target is not allowed" carries a fixed reason code; the access
// log records the precise one and never the target.
func TestLaunchDenialReasonCodes(t *testing.T) {
	d := newDeliveryHarness(t)
	d.setResolver(func(_ context.Context, host string) ([]net.IPAddr, error) {
		switch host {
		case "internal.example":
			return []net.IPAddr{{IP: net.ParseIP("10.0.0.7")}}, nil
		case "gone.example":
			return nil, errors.New("no such host")
		}
		return []net.IPAddr{{IP: net.ParseIP(vendorPublicIP)}}, nil
	})
	store := d.h.server.store
	item, _, err := store.GetResource("vendor")
	if err != nil {
		t.Fatal(err)
	}
	item.Domains = append(item.Domains,
		resources.DomainRule{Host: "unregistered.example"},
		resources.DomainRule{Host: "internal.example"},
		resources.DomainRule{Host: "gone.example"},
		resources.DomainRule{Host: "blocked.example", Match: "exact", Role: "blocked", Action: "block", Behavior: "block"},
	)
	if item, err = resources.Validate(item); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertResource(item); err != nil {
		t.Fatal(err)
	}
	postOnly, err := resources.Validate(resources.Resource{ID: "postonly", Name: "POST only", HTTPMethods: []string{"POST"}, Domains: []resources.DomainRule{{Host: "postonly.example"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertResource(postOnly); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RegisterProxyHostname("postonly.example", "odo.example", "proxy.example"); err != nil {
		t.Fatal(err)
	}

	launch := func(query string) (int, string, string) {
		t.Helper()
		response, body := d.request(t, "GET", "https://odo.example/launch?"+query, nil)
		var payload struct{ Error, Reason string }
		if response.StatusCode == http.StatusForbidden {
			if err := json.Unmarshal([]byte(body), &payload); err != nil || payload.Error != "launch target is not allowed" {
				t.Fatalf("denial body changed: %s", body)
			}
		}
		return response.StatusCode, payload.Reason, lastDenialReason(t, d)
	}
	encoded := func(target string) string { return url.Values{"url": {target}}.Encode() }

	// Repeated identical, encoded and raw launches all start a handoff.
	for i := 0; i < 12; i++ {
		if status, _, _ := launch(encoded("https://vendor.example/private?x=1")); status != http.StatusSeeOther {
			t.Fatalf("repeated launch %d: %d", i, status)
		}
	}
	if status, _, _ := launch("url=https://vendor.example/private?x=1&y=2"); status != http.StatusSeeOther {
		t.Fatalf("raw launch: %d", status)
	}

	for _, tc := range []struct {
		target, public, logged string
	}{
		{"https://www.vendor.example/", "resource_policy", launchDeniedNoResource},
		{"https://blocked.example/", "resource_policy", launchDeniedBlocked},
		{"https://internal.example/", "resource_policy", launchDeniedUnsafe},
		{"https://gone.example/", "resource_policy", launchDeniedUnresolved},
		{"https://postonly.example/", "method_not_allowed", launchDeniedMethod},
		// Allowed by policy, but no administrator enrolled a proxy name.
		{"https://unregistered.example/", "hostname_not_registered", launchDeniedUnregistered},
	} {
		status, public, logged := launch(encoded(tc.target))
		if status != http.StatusForbidden || public != tc.public || logged != tc.logged {
			t.Fatalf("%s: %d public=%q logged=%q", tc.target, status, public, logged)
		}
	}
	// A denied launch creates no handoff state for an unregistered host.
	if _, found, _ := store.LookupProxyHostnameByUpstream("unregistered.example"); found {
		t.Fatal("launch enrolled a hostname")
	}

	// Policy revisions take effect on the next launch, in both directions.
	item.Status = "disabled"
	if err := store.UpsertResource(item); err != nil {
		t.Fatal(err)
	}
	if status, public, logged := launch(encoded("https://vendor.example/")); status != http.StatusForbidden || public != "resource_policy" || logged != launchDeniedNoResource {
		t.Fatalf("disabled resource launch: %d %q %q", status, public, logged)
	}
	item.Status = "active"
	if err := store.UpsertResource(item); err != nil {
		t.Fatal(err)
	}
	if status, _, _ := launch(encoded("https://vendor.example/")); status != http.StatusSeeOther {
		t.Fatalf("re-enabled resource launch: %d", status)
	}

	// A stored row that no longer validates (here, a label the proxy name rules
	// reject) is refused rather than guessed.
	if _, err := d.control.Exec(`UPDATE proxy_hostnames SET label = ? WHERE hostname = ?`, "not-this-host", "vendor.example"); err != nil {
		t.Fatal(err)
	}
	if status, public, logged := launch(encoded("https://vendor.example/")); status != http.StatusForbidden || public != launchDeniedMappingInvalid || logged != launchDeniedMappingInvalid {
		t.Fatalf("invalid mapping launch: %d %q %q", status, public, logged)
	}

	payload, _ := json.Marshal(d.h.server.accessLog.Recent())
	for _, private := range []string{"vendor.example", "unregistered.example", "internal.example", "gone.example", "postonly.example", "private?x"} {
		if strings.Contains(string(payload), private) || strings.Contains(d.logs.String(), private) {
			t.Fatalf("logs disclosed launch target %q", private)
		}
	}
}

// Launches racing resource saves (with the enrollment a save triggers) are
// never refused while the target stays allowed throughout.
func TestLaunchDuringConcurrentResourceUpdates(t *testing.T) {
	d := newDeliveryHarness(t)
	store := d.h.server.store
	item, _, err := store.GetResource("vendor")
	if err != nil {
		t.Fatal(err)
	}
	launchURL := "https://odo.example/launch?" + url.Values{"url": {"https://vendor.example/private"}}.Encode()
	stop := make(chan struct{})
	updates := make(chan error, 1)
	go func() {
		defer close(updates)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			revision := item
			revision.Description = strings.Repeat("r", i%7)
			if err := store.UpsertResource(revision); err != nil {
				updates <- err
				return
			}
			if _, err := store.ReconcileProxyHostnames("odo.example", "proxy.example", nil); err != nil {
				updates <- err
				return
			}
		}
	}()
	var wg sync.WaitGroup
	statuses := make(chan int, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			response, err := d.client.Get(launchURL)
			if err != nil {
				statuses <- -1
				return
			}
			_, _ = io.Copy(io.Discard, response.Body)
			response.Body.Close()
			statuses <- response.StatusCode
		}()
	}
	wg.Wait()
	close(stop)
	close(statuses)
	if err := <-updates; err != nil {
		t.Fatal(err)
	}
	for status := range statuses {
		if status != http.StatusSeeOther {
			t.Fatalf("launch during resource updates: %d", status)
		}
	}
}
