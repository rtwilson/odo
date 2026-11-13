package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"example.org/odo/internal/proxy"
)

// The fixture's vendor gets the readable default name, and every handoff
// step binds to that exact registered authority.
func TestReadableProxyNameUsedThroughoutHandoff(t *testing.T) {
	d := newDeliveryHarness(t)
	if d.authority != "vendor-example.proxy.example" {
		t.Fatalf("unexpected default proxy name: %q", d.authority)
	}
	if rec := d.serve("GET", "/private", d.grant, nil); rec.Code != http.StatusOK {
		t.Fatalf("readable host delivery: %d", rec.Code)
	}
}

// Launch resolves the registered identity from the canonical upstream name
// and never infers an upstream from a hyphenated guess.
func TestUpstreamMappingIsRegistryOnly(t *testing.T) {
	d := newDeliveryHarness(t)
	for _, raw := range []string{"vendor.example", "VENDOR.EXAMPLE.", "vendor.example:443"} {
		mapping, err := d.h.upstreamMapping(raw)
		if err != nil || mapping.Hostname != "vendor.example" || mapping.Label != "vendor-example" {
			t.Fatalf("%q: %+v %v", raw, mapping, err)
		}
	}
	for _, raw := range []string{"unknown.example", "vendor-example", "vendor-example.proxy.example", "odo.example", "bad host"} {
		if _, err := d.h.upstreamMapping(raw); !errors.Is(err, errHandoffDenied) {
			t.Fatalf("%q resolved: %v", raw, err)
		}
	}
	// A plausible readable name for an unregistered upstream is not admitted.
	d.authority = "unknown-example.proxy.example"
	if rec := d.serve("GET", "/private", d.grant, nil); rec.Code != http.StatusMisdirectedRequest || d.vendor.hits.Load() != 0 {
		t.Fatalf("unregistered readable name admitted: %d", rec.Code)
	}
}

// Migrating a legacy hashed name to its readable name retires the old proxy
// host and every grant bound to it; the old grant never works on the new name.
func TestReadableMigrationRetiresLegacyGrants(t *testing.T) {
	d := newDeliveryHarness(t)
	legacy := proxy.FallbackRegistryLabel("vendor.example")
	if _, err := d.control.Exec(`UPDATE proxy_hostnames SET label = ? WHERE hostname = ?`, legacy, "vendor.example"); err != nil {
		t.Fatal(err)
	}
	readable := d.authority
	d.authority = legacy + ".proxy.example"
	oldGrant := d.securityFixture.grant(t)
	if rec := d.serve("GET", "/private", oldGrant, nil); rec.Code != http.StatusOK {
		t.Fatalf("legacy name delivery before migration: %d", rec.Code)
	}
	records, err := d.h.server.store.MigrateProxyHostnames("odo.example", "proxy.example", nil)
	if err != nil || len(records) != 1 || records[0].Label+".proxy.example" != readable {
		t.Fatalf("migration: %+v %v", records, err)
	}
	hits := d.vendor.hits.Load()
	if rec := d.serve("GET", "/private", oldGrant, nil); rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("retired legacy name still admitted: %d", rec.Code)
	}
	d.authority = readable
	// A navigation restarts the handoff at central; a subresource gets 401.
	if rec := d.serve("GET", "/private", oldGrant, nil); rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "https://odo.example/launch") {
		t.Fatalf("legacy grant accepted on the readable name: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := d.serve("GET", "/private", oldGrant, func(r *http.Request) { r.Header.Set("Sec-Fetch-Dest", "image") }); rec.Code != http.StatusUnauthorized {
		t.Fatalf("legacy grant accepted for a subresource: %d", rec.Code)
	}
	if d.vendor.hits.Load() != hits {
		t.Fatal("stale grant reached upstream")
	}
	// A fresh handoff now lands on the readable name.
	launched, _ := d.request(t, "GET", "https://odo.example/launch?"+url.Values{"url": {"https://vendor.example/private"}}.Encode(), nil)
	location, _ := url.Parse(launched.Header.Get("Location"))
	if launched.StatusCode != http.StatusSeeOther || location == nil || location.Host != readable {
		t.Fatalf("launch after migration: %d %v", launched.StatusCode, location)
	}
	d.securityFixture.authority = readable
	if rec := d.serve("GET", "/private", d.securityFixture.grant(t), nil); rec.Code != http.StatusOK {
		t.Fatalf("new grant on readable name: %d", rec.Code)
	}
}

// Migration must also stop an in-progress protocol, not just a delivered grant.
func TestReadableMigrationInvalidatesPendingHandoffsAndTickets(t *testing.T) {
	f := newSecurityFixture(t)
	legacy := proxy.FallbackRegistryLabel("vendor.example")
	if _, err := f.control.Exec(`UPDATE proxy_hostnames SET label=? WHERE hostname=?`, legacy, "vendor.example"); err != nil {
		t.Fatal(err)
	}
	f.authority = legacy + ".proxy.example"
	pending, err := f.h.begin(context.Background(), f.central, f.authority, f.target, f.nonce, f.now)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := f.h.preflight(pending, f.authority, f.vendor, f.now)
	if err != nil {
		t.Fatal(err)
	}
	ticket := f.ticket(t)
	if _, err := f.h.server.store.MigrateProxyHostnames("odo.example", "proxy.example", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.confirm(context.Background(), pending, f.central, f.authority, f.nonce, proof, f.now); err == nil {
		t.Fatal("pending handoff survived migration")
	}
	for _, authority := range []string{f.authority, "vendor-example.proxy.example"} {
		if _, err := f.h.preflight(pending, authority, f.vendor, f.now); err == nil {
			t.Fatal("stale pending handoff prepared")
		}
		if _, _, err := f.h.redeem(context.Background(), ticket, authority, f.vendor, f.now); err == nil {
			t.Fatal("stale ticket redeemed")
		}
	}
}

func TestLegacyRegisteredNameSupportsAutomaticBrowserHandoff(t *testing.T) {
	d := newDeliveryHarness(t)
	legacy := proxy.FallbackRegistryLabel("vendor.example")
	if _, err := d.control.Exec(`UPDATE proxy_hostnames SET label=? WHERE hostname=?`, legacy, "vendor.example"); err != nil {
		t.Fatal(err)
	}
	d.authority = legacy + ".proxy.example"
	start := "https://odo.example/launch?" + url.Values{"url": {d.target}}.Encode()
	response, body := followAutomaticHandoff(t, d.handoffBrowser, start)
	if response.StatusCode != 200 || !strings.Contains(body, vendorBodyMarker) {
		t.Fatalf("legacy browser flow: %d", response.StatusCode)
	}
	if response.Request.URL.Host != d.authority {
		t.Fatalf("legacy flow guessed authority: %q", response.Request.URL.Host)
	}
}

// Even a corrupted registry row using a genuinely ambiguous readable label
// must not transfer a ticket/grant to the other upstream.
func TestCollidingReadableNameCannotTransferAuthorization(t *testing.T) {
	f := newSecurityFixture(t)
	grant := f.grant(t)
	ticket := f.ticket(t)
	// vendor.example and vendor-example both flatten to vendor-example.
	if _, err := f.control.Exec(`UPDATE proxy_hostnames SET hostname=? WHERE hostname=?`, "vendor-example", "vendor.example"); err != nil {
		t.Fatal(err)
	}
	if err := f.h.validateGrant(context.Background(), grant, f.authority, "https://vendor-example/private", "GET", f.now); err == nil {
		t.Fatal("grant transferred to colliding upstream")
	}
	if _, _, err := f.h.redeem(context.Background(), ticket, f.authority, f.vendor, f.now); err == nil {
		t.Fatal("ticket transferred to colliding upstream")
	}
}
