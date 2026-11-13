package api

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"example.org/odo/internal/auth/local"
	"example.org/odo/internal/proxy"
	"example.org/odo/internal/resources"
)

// A resource spanning two registered hosts: one confirmation gives the
// browser host-only grants on both, the page's asset URL is rewritten onto the
// second host's proxy authority, and that asset then loads through Odo.
func TestSameResourceHostsShareOneHandoff(t *testing.T) {
	const cdnHost = "cdn.external.example"
	const cdnIP = "93.184.216.35"
	pixel, _ := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aE1sAAAAASUVORK5CYII=")
	d := newDeliveryHarnessWithSite(t, fakeVendorSite())
	cdn := newFakeVendorSite(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != cdnHost || r.URL.Path != "/pixel.png" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(pixel)
	}), cdnHost)
	item, _, err := d.h.server.store.GetResource("vendor")
	if err != nil {
		t.Fatal(err)
	}
	item.Domains = append(item.Domains, resources.DomainRule{Host: cdnHost})
	if err := d.h.server.store.UpsertResource(item); err != nil {
		t.Fatal(err)
	}
	mapping, err := d.h.server.store.RegisterProxyHostname(cdnHost, "odo.example", "proxy.example")
	if err != nil {
		t.Fatal(err)
	}
	cdnAuthority := mapping.Label + ".proxy.example"
	lookup := func(_ context.Context, host string) ([]net.IPAddr, error) {
		switch host {
		case "vendor.example":
			return []net.IPAddr{{IP: net.ParseIP(vendorPublicIP)}}, nil
		case cdnHost:
			return []net.IPAddr{{IP: net.ParseIP(cdnIP)}}, nil
		}
		return nil, errors.New("unexpected test hostname")
	}
	d.setResolver(lookup)
	roots := d.vendor.roots.Clone()
	roots.AddCert(cdn.server.TLS.Certificates[0].Leaf)
	d.h.vendor = proxy.NewSafeHTTPClient(lookup, func(ctx context.Context, network, address string) (net.Conn, error) {
		switch address {
		case net.JoinHostPort(vendorPublicIP, "443"):
			return (&net.Dialer{}).DialContext(ctx, network, d.vendor.server.Listener.Addr().String())
		case net.JoinHostPort(cdnIP, "443"):
			return (&net.Dialer{}).DialContext(ctx, network, cdn.server.Listener.Addr().String())
		}
		return nil, errors.New("unexpected validated test address")
	}, &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12})

	d.target = "https://vendor.example/"
	redeemed, _ := d.request(t, "GET", d.ticket(t), nil)
	redeemed, _ = d.request(t, "GET", redeemed.Header.Get("Location"), nil)
	hop := redeemed.Header.Get("Location")
	if redeemed.StatusCode != http.StatusSeeOther || !strings.HasPrefix(hop, "https://"+cdnAuthority+handoffVendorPath+"?sibling=") {
		t.Fatalf("redemption did not continue to the sibling host: %d %q", redeemed.StatusCode, hop)
	}
	for _, private := range []string{"vendor.example/", d.central, d.nonce} {
		if strings.Contains(hop, private) {
			t.Fatal("sibling hop URL disclosed private data")
		}
	}
	// One redirect per sibling: the hop sets the grant and continues directly.
	sibling, _ := d.request(t, "GET", hop, nil)
	cdnGrant := findCookie(sibling.Cookies(), vendorGrantCookie)
	if sibling.StatusCode != http.StatusSeeOther || sibling.Header.Get("Location") != "https://"+d.authority+"/" {
		t.Fatalf("sibling hop did not return to the target: %d %q", sibling.StatusCode, sibling.Header.Get("Location"))
	}
	if cdnGrant == nil || !cdnGrant.Secure || !cdnGrant.HttpOnly || cdnGrant.Domain != "" {
		t.Fatal("sibling host did not receive a host-only grant")
	}
	if replay, _ := d.request(t, "GET", hop, nil); replay.StatusCode != http.StatusNotFound {
		t.Fatalf("sibling hop replay: %d", replay.StatusCode)
	}

	response, body := d.browse(t, "GET", "https://"+d.authority+"/", "document", nil)
	if response.StatusCode != 200 || pageURLs(t, body)["external"] != "https://"+cdnAuthority+"/pixel.png" {
		t.Fatalf("same-resource asset URL was not rewritten: %q", pageURLs(t, body)["external"])
	}
	image, data := d.browse(t, "GET", "https://"+cdnAuthority+"/pixel.png", "image", nil)
	if image.StatusCode != 200 || string(data) != string(pixel) {
		t.Fatalf("sibling asset did not load through Odo: %d", image.StatusCode)
	}

	// A sibling grant is bound to its own host and the same parent session.
	vendorURL, _ := url.Parse("https://" + d.authority + "/")
	if first := findCookie(d.client.Jar.Cookies(vendorURL), vendorGrantCookie); first == nil || first.Value == cdnGrant.Value {
		t.Fatal("hosts share one grant value")
	}
	if err := d.h.server.store.RevokeSession(local.SessionIDFromToken(d.central)); err != nil {
		t.Fatal(err)
	}
	if denied, _ := d.browse(t, "GET", "https://"+cdnAuthority+"/pixel.png", "image", nil); denied.StatusCode != 401 {
		t.Fatalf("revoked parent kept sibling access: %d", denied.StatusCode)
	}
}

// Hosts of other resources never join the family: no hop, no rewrite.
func TestOtherResourceHostsGetNoSiblingGrant(t *testing.T) {
	d := newDeliveryHarnessWithSite(t, fakeVendorSite())
	other, err := resources.Validate(resources.Resource{ID: "cdn", Name: "CDN", Domains: []resources.DomainRule{{Host: "cdn.external.example"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.h.server.store.UpsertResource(other); err != nil {
		t.Fatal(err)
	}
	if _, err := d.h.server.store.RegisterProxyHostname("cdn.external.example", "odo.example", "proxy.example"); err != nil {
		t.Fatal(err)
	}
	d.target = "https://vendor.example/"
	redeemed, _ := d.request(t, "GET", d.ticket(t), nil)
	redeemed, _ = d.request(t, "GET", redeemed.Header.Get("Location"), nil)
	if location := redeemed.Header.Get("Location"); location != "https://"+d.authority+"/" {
		t.Fatalf("other resource's host joined the handoff: %q", location)
	}
}
