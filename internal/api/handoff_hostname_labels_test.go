package api

import (
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
