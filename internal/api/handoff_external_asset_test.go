package api

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"example.org/odo/internal/auth/local"
	"example.org/odo/internal/proxy"
	"example.org/odo/internal/resources"
)

// This exercises two independently granted hosts. The page's external URL
// remains unchanged: requesting the CDN proxy URL below is an explicit test
// action, not automatic rewriting or grant acquisition by Odo.
func TestVendorExternalAssetRequiresIndependentHandoff(t *testing.T) {
	const cdnHost = "cdn.external.example"
	const cdnIP = "93.184.216.35"
	pixel, err := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aE1sAAAAASUVORK5CYII=")
	if err != nil {
		t.Fatal(err)
	}
	d := newDeliveryHarnessWithSite(t, fakeVendorSite())
	cdn := newFakeVendorSite(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != cdnHost || r.URL.Path != "/pixel.png" {
			http.NotFound(w, r)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "cdn_session", Value: "cdn-only", Path: "/", Secure: true, HttpOnly: true})
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(pixel)
	}), cdnHost)
	item, err := resources.Validate(resources.Resource{
		ID: "cdn", Name: "CDN", Domains: []resources.DomainRule{{Host: cdnHost}},
		CookiePolicy: resources.CookiePolicy{Enabled: true, JarScope: "resource"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.h.server.store.UpsertResource(item); err != nil {
		t.Fatal(err)
	}
	mapping, err := d.h.server.store.RegisterProxyHostname(cdnHost, "odo.example", "proxy.example")
	if err != nil {
		t.Fatal(err)
	}
	cdnAuthority := mapping.Label + ".proxy.example"
	cdnURL, _ := url.Parse("https://" + cdnAuthority + "/pixel.png")

	// Each public test IP maps only to its own local TLS listener. Certificate
	// verification still uses the actual upstream hostname, with both test CAs.
	lookup := func(_ context.Context, host string) ([]net.IPAddr, error) {
		switch host {
		case "vendor.example":
			return []net.IPAddr{{IP: net.ParseIP(vendorPublicIP)}}, nil
		case cdnHost:
			return []net.IPAddr{{IP: net.ParseIP(cdnIP)}}, nil
		default:
			return nil, errors.New("unexpected test hostname")
		}
	}
	d.setResolver(lookup)
	roots := d.vendor.roots.Clone()
	roots.AddCert(cdn.server.TLS.Certificates[0].Leaf)
	client := proxy.NewSafeHTTPClient(lookup, func(ctx context.Context, network, address string) (net.Conn, error) {
		var destination string
		switch address {
		case net.JoinHostPort(vendorPublicIP, "443"):
			destination = d.vendor.server.Listener.Addr().String()
		case net.JoinHostPort(cdnIP, "443"):
			destination = cdn.server.Listener.Addr().String()
		default:
			return nil, errors.New("unexpected validated test address")
		}
		return (&net.Dialer{}).DialContext(ctx, network, destination)
	}, &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12})
	d.h.vendor = client
	t.Cleanup(client.CloseIdleConnections)

	d.target = "https://vendor.example/"
	d.finish(t, d.ticket(t))
	vendorURL := "https://" + d.authority + "/"
	response, body := d.browse(t, "GET", vendorURL, "document", nil)
	if response.StatusCode != 200 || pageURLs(t, body)["external"] != "https://"+cdnHost+"/pixel.png" || cdn.hits.Load() != 0 {
		t.Fatal("page rewrote or fetched the external image")
	}
	assertDenied := func(want int) {
		t.Helper()
		before := cdn.hits.Load()
		response, _ := d.browse(t, "GET", cdnURL.String(), "image", nil)
		if response.StatusCode != want || response.Header.Get("Location") != "" || len(response.Cookies()) != 0 || cdn.hits.Load() != before {
			t.Fatalf("CDN denial: status=%d, want %d; must not redirect, set cookies or fetch upstream", response.StatusCode, want)
		}
	}
	assertDenied(401)
	// Copy the actual first host's browser grant to the CDN host. Cookie scope
	// alone is not the protection: the server must reject its host binding too.
	vendorParsed, _ := url.Parse(vendorURL)
	firstGrant := findCookie(d.client.Jar.Cookies(vendorParsed), vendorGrantCookie)
	if firstGrant == nil {
		t.Fatal("vendor grant missing")
	}
	d.client.Jar.SetCookies(cdnURL, []*http.Cookie{handoffCookie(vendorGrantCookie, firstGrant.Value, time.Now().Add(time.Minute))})
	assertDenied(401)
	d.client.Jar.SetCookies(cdnURL, []*http.Cookie{{Name: vendorGrantCookie, Path: "/", MaxAge: -1}})

	// Use the same browser and parent session, but launch and explicitly confirm
	// a separate handoff for the CDN through the HTTP control endpoints.
	cdnBrowser := d.handoffBrowser
	cdnBrowser.authority, cdnBrowser.target = cdnAuthority, "https://"+cdnHost+"/pixel.png"
	cdnBrowser.finish(t, cdnBrowser.ticket(t))
	cdnGrant := findCookie(d.client.Jar.Cookies(cdnURL), vendorGrantCookie)
	if cdnGrant == nil || cdnGrant.Value == firstGrant.Value {
		t.Fatal("CDN did not receive an independent grant")
	}
	for i := 0; i < 2; i++ {
		response, body := d.browse(t, "GET", cdnURL.String(), "image", nil)
		if response.StatusCode != 200 || response.Header.Get("Content-Type") != "image/png" || string(body) != string(pixel) {
			t.Fatalf("CDN image delivery failed: %d", response.StatusCode)
		}
		wantCookie := ""
		if i == 1 {
			wantCookie = "cdn_session=cdn-only"
		}
		if cdn.lastRequest().Header.Get("Cookie") != wantCookie {
			t.Fatal("CDN jar received unexpected credentials")
		}
	}
	// Inject browser credentials directly at the HTTP boundary on both hosts;
	// only each upstream's own jar cookie may emerge at the vendor listener.
	for _, tc := range []struct {
		authority, path, grant, cookie string
		upstream                       *fakeVendor
	}{
		{d.authority, "/", firstGrant.Value, "vendor_session=s3cret", d.vendor},
		{cdnAuthority, "/pixel.png", cdnGrant.Value, "cdn_session=cdn-only", cdn},
	} {
		requestHarness := deliveryHarness{handoffBrowser: d.handoffBrowser, routes: d.routes}
		requestHarness.authority = tc.authority
		rec := requestHarness.serve("GET", tc.path, tc.grant, func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: "__Host-odo_session", Value: d.central})
			r.AddCookie(&http.Cookie{Name: "browser_secret", Value: "must-not-forward"})
			r.Header.Set("Authorization", "Bearer must-not-forward")
		})
		last := tc.upstream.lastRequest()
		if rec.Code != 200 || last.Header.Get("Cookie") != tc.cookie || last.Header.Get("Authorization") != "" {
			t.Fatal("browser credentials crossed the upstream boundary")
		}
	}
	for _, target := range []*url.URL{vendorParsed, cdnURL} {
		for _, cookie := range d.client.Jar.Cookies(target) {
			if cookie.Name != vendorGrantCookie && cookie.Name != vendorNonceCookie {
				t.Fatal("upstream cookie reached browser")
			}
		}
	}
	item.Status = "disabled"
	if err := d.h.server.store.UpsertResource(item); err != nil {
		t.Fatal(err)
	}
	assertDenied(403)
	// Restore policy and prove access works before revocation, so the subsequent
	// 401 is caused by the revoked parent rather than the disabled resource.
	item.Status = "active"
	if err := d.h.server.store.UpsertResource(item); err != nil {
		t.Fatal(err)
	}
	if response, _ := d.browse(t, "GET", cdnURL.String(), "image", nil); response.StatusCode != 200 {
		t.Fatal("CDN policy did not restore access")
	}
	if err := d.h.server.store.RevokeSession(local.SessionIDFromToken(d.central)); err != nil {
		t.Fatal(err)
	}
	assertDenied(401)
	before := d.vendor.hits.Load()
	if response, _ := d.browse(t, "GET", vendorURL, "image", nil); response.StatusCode != 401 || d.vendor.hits.Load() != before {
		t.Fatal("revoked parent retained vendor access")
	}
}
