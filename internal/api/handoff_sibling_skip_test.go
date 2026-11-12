package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"example.org/odo/internal/resources"
)

// siblingSkipHarness adds registered sibling hosts to the fixture resource and
// resolves them through a switchable set of dead names.
func siblingSkipHarness(t *testing.T, hosts ...string) (*deliveryHarness, *atomic.Value, map[string]string) {
	t.Helper()
	d := newDeliveryHarness(t)
	item, _, err := d.h.server.store.GetResource("vendor")
	if err != nil {
		t.Fatal(err)
	}
	authorities := map[string]string{}
	for _, host := range hosts {
		item.Domains = append(item.Domains, resources.DomainRule{Host: host})
	}
	if err := d.h.server.store.UpsertResource(item); err != nil {
		t.Fatal(err)
	}
	for _, host := range hosts {
		mapping, err := d.h.server.store.RegisterProxyHostname(host, "odo.example", "proxy.example")
		if err != nil {
			t.Fatal(err)
		}
		authorities[host] = mapping.Label + ".proxy.example"
	}
	dead := &atomic.Value{}
	dead.Store(map[string]bool{})
	d.setResolver(func(_ context.Context, host string) ([]net.IPAddr, error) {
		if dead.Load().(map[string]bool)[host] {
			return nil, errors.New("no such host")
		}
		return []net.IPAddr{{IP: net.ParseIP(vendorPublicIP)}}, nil
	})
	d.target = "https://vendor.example/"
	return d, dead, authorities
}

// redeemToFirstHop redeems a fresh ticket and passes grant verification,
// returning where the browser goes next (a sibling hop or the target).
func redeemToFirstHop(t *testing.T, d *deliveryHarness) string {
	t.Helper()
	redeemed, _ := d.request(t, "GET", d.ticket(t), nil)
	verified, _ := d.request(t, "GET", redeemed.Header.Get("Location"), nil)
	if verified.StatusCode != http.StatusSeeOther {
		t.Fatalf("grant verification: %d", verified.StatusCode)
	}
	return verified.Header.Get("Location")
}

func hasGrant(d *deliveryHarness, authority string) bool {
	target, _ := url.Parse("https://" + authority + "/")
	return findCookie(d.client.Jar.Cookies(target), vendorGrantCookie) != nil
}

// A configured host that does not resolve is left out of the chain entirely,
// so it costs the browser no redirects; live hosts still get grants.
func TestSiblingChainOmitsUnresolvableHosts(t *testing.T) {
	d, dead, authorities := siblingSkipHarness(t, "alive.example", "dead.example")
	dead.Store(map[string]bool{"dead.example": true})
	next := redeemToFirstHop(t, d)
	final := "https://" + d.authority + "/"
	for hops := 0; next != final; hops++ {
		if hops > 4 || strings.Contains(next, authorities["dead.example"]) {
			t.Fatalf("chain visited an unresolvable host or never ended: %q", next)
		}
		response, _ := d.request(t, "GET", next, nil)
		if response.StatusCode != http.StatusSeeOther {
			t.Fatalf("hop failed: %d", response.StatusCode)
		}
		next = response.Header.Get("Location")
	}
	if !hasGrant(d, authorities["alive.example"]) || hasGrant(d, authorities["dead.example"]) {
		t.Fatal("grants do not match reachable hosts")
	}
}

// A host that fails its live check after the chain was issued is skipped
// without a grant; the patron still reaches the target.
func TestSiblingHopSkipsHostThatBecameUnavailable(t *testing.T) {
	d, dead, authorities := siblingSkipHarness(t, "alive.example", "flaky.example")
	next := redeemToFirstHop(t, d)
	if !strings.HasPrefix(next, "https://"+authorities["alive.example"]+handoffVendorPath+"?sibling=") {
		t.Fatalf("unexpected first hop: %q", next)
	}
	dead.Store(map[string]bool{"flaky.example": true})
	final := "https://" + d.authority + "/"
	var skipped string
	for hops := 0; next != final; hops++ {
		if hops > 6 {
			t.Fatal("chain never reached the target")
		}
		response, _ := d.request(t, "GET", next, nil)
		if response.StatusCode != http.StatusSeeOther {
			t.Fatalf("hop %q failed: %d", next, response.StatusCode)
		}
		if strings.Contains(next, authorities["flaky.example"]) {
			skipped = next
			if lastDenialReason(t, d) != siblingSkippedReason || len(response.Cookies()) != 0 {
				t.Fatal("skipped hop not recorded or issued a cookie")
			}
		}
		next = response.Header.Get("Location")
	}
	if skipped == "" || !hasGrant(d, authorities["alive.example"]) || hasGrant(d, authorities["flaky.example"]) {
		t.Fatal("unavailable host was not skipped cleanly")
	}
	// The skipped hop was consumed: replaying it grants nothing.
	if replay, _ := d.request(t, "GET", skipped, nil); replay.StatusCode != http.StatusNotFound {
		t.Fatalf("skipped hop replay: %d", replay.StatusCode)
	}
}
