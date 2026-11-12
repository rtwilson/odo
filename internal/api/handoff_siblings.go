package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"example.org/odo/internal/proxy"
	"example.org/odo/internal/resources"
)

// Cross-host delivery for one resource. A resource often spans several hosts
// (a site and its asset or login hosts). After a patron redeems a ticket on one
// host, the browser is walked through single-use sibling hops so each other
// registered host of the SAME resource also gets its own host-only grant. Page
// links, assets and redirects to those hosts are then rewritten onto their
// proxy hosts. Hosts of other resources and unregistered hosts are untouched:
// no cookie is shared across hosts and no new host is ever enrolled.

// resourceItems returns the current resources for host-family decisions,
// without URL-specific anonymous exceptions (as in hostname inspection).
func (h *handoffSecurity) resourceItems() ([]resources.Resource, error) {
	var items []resources.Resource
	if h.cookies != nil {
		snapshot, err := h.cookies.currentSnapshot()
		if err != nil {
			return nil, err
		}
		items = append(items, snapshot.Resources...)
	} else {
		list, err := h.server.store.ListResources()
		if err != nil {
			return nil, err
		}
		items = list
	}
	for i := range items {
		items[i].AnonymousURLRules = nil
	}
	return items, nil
}

// resourceHosts lists the registered hosts whose domain policy currently
// resolves to resourceID as a proxied resource, in hostname order, starting
// with self and capped at self plus maxSiblingHosts others.
func (h *handoffSecurity) resourceHosts(resourceID, self string) ([]siblingHost, error) {
	if resourceID == "" {
		return nil, nil
	}
	items, err := h.resourceItems()
	if err != nil {
		return nil, err
	}
	records, err := h.server.store.ListProxyHostnames()
	if err != nil {
		return nil, err
	}
	var hosts []siblingHost
	for _, record := range records {
		if record.Hostname == self || len(hosts) >= maxSiblingHosts {
			continue
		}
		err := proxy.ValidateRegistryMapping(record.Hostname, record.Label, h.config.CentralHostname(), h.config.ProxyBaseDomain())
		if err != nil {
			continue
		}
		result := resources.TestURL((&url.URL{Scheme: "https", Host: record.Hostname, Path: "/"}).String(), items)
		if !result.Allowed || result.Action != "proxy" || result.ResourceID != resourceID {
			continue
		}
		hosts = append(hosts, siblingHost{mapping: record, authority: record.Label + "." + h.config.ProxyBaseDomain()})
	}
	return hosts, nil
}

// rewriteHosts maps this host and its resource's other registered hosts to
// their proxy authorities. Any lookup failure keeps same-host behavior.
func (h *handoffSecurity) rewriteHosts(target *url.URL, hostname, authority string) map[string]string {
	hosts := map[string]string{strings.ToLower(hostname): authority}
	items, err := h.resourceItems()
	if err != nil || target == nil {
		return hosts
	}
	result := resources.TestURL(target.String(), items)
	if !result.Allowed || result.Action != "proxy" {
		return hosts
	}
	siblings, err := h.resourceHosts(result.ResourceID, hostname)
	if err != nil {
		return hosts
	}
	for _, sibling := range siblings {
		hosts[strings.ToLower(sibling.mapping.Hostname)] = sibling.authority
	}
	return hosts
}

// siblingChain issues hops for the resource's other registered hosts and
// returns the first hop, or final when there are none. Failures fall back to
// final: the patron still reaches the page, only without sibling grants.
func (h *handoffSecurity) siblingChain(ctx context.Context, grantToken, resourceID, hostname, final string, now time.Time) string {
	grant, found := h.state.grantFamily(grantToken, now)
	if !found {
		return final
	}
	hosts, err := h.resourceHosts(resourceID, hostname)
	if err != nil || len(hosts) == 0 {
		return final
	}
	hosts = h.reachableSiblings(ctx, grant.binding, resourceID, hosts)
	if len(hosts) == 0 {
		return final
	}
	first, err := h.state.issueSiblings(grant, resourceID, hosts, final, now)
	if err != nil {
		return final
	}
	return first
}

// reachableSiblings keeps the hosts that pass the same live target check a hop
// performs (resource policy, GET permission and DNS safety). A configured host
// that does not resolve would otherwise cost the browser two redirects only to
// be refused. Checks run concurrently; hostname order is preserved.
func (h *handoffSecurity) reachableSiblings(ctx context.Context, parent handoffBinding, resourceID string, hosts []siblingHost) []siblingHost {
	ok := make([]bool, len(hosts))
	var wg sync.WaitGroup
	for i, host := range hosts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			binding := parent
			binding.hostname, binding.label, binding.proxyAuthority = host.mapping.Hostname, host.mapping.Label, host.authority
			probe := (&url.URL{Scheme: "https", Host: host.mapping.Hostname, Path: "/"}).String()
			_, err := h.target(ctx, binding, probe, http.MethodGet, resourceID)
			ok[i] = err == nil
		}()
	}
	wg.Wait()
	kept := hosts[:0:0]
	for i, host := range hosts {
		if ok[i] {
			kept = append(kept, host)
		}
	}
	return kept
}

// siblingSkippedReason is the access log denial_reason for a hop whose host
// failed its live check: the hop is dropped and navigation continues.
const siblingSkippedReason = "sibling_host_unavailable"

// redeemSiblingBrowser consumes one hop on its own host, rechecking the live
// parent session and that this host still belongs to the resource, then sets
// the host-only grant and continues to the stored next hop.
func (h *handoffSecurity) redeemSiblingBrowser(w http.ResponseWriter, r *http.Request, authority, token string) {
	now := time.Now().UTC()
	mapping, err := h.mapping(authority)
	if err != nil {
		h.confirmationError(w, r, err)
		return
	}
	sibling, found := h.state.inspectSibling(token, mapping, authority, now)
	if !found {
		writeError(w, http.StatusNotFound, "handoff not found")
		return
	}
	if _, err := h.parent(sibling.binding, now); err != nil {
		h.confirmationError(w, r, err)
		return
	}
	probe := (&url.URL{Scheme: "https", Host: mapping.Hostname, Path: "/"}).String()
	if _, err := h.target(r.Context(), sibling.binding, probe, http.MethodGet, sibling.resourceID); err != nil {
		// This host alone is unavailable (it stopped resolving, or policy changed
		// since the chain was issued). The parent is valid, so drop the hop
		// without a grant and continue; one bad host must not strand the patron.
		if !errors.Is(err, errHandoffDenied) {
			h.confirmationError(w, r, err)
			return
		}
		next, found := h.state.discardSibling(token, sibling.binding, now)
		if !found {
			writeError(w, http.StatusNotFound, "handoff not found")
			return
		}
		recordDenialReason(r, siblingSkippedReason)
		w.Header().Set("Location", next)
		w.WriteHeader(http.StatusSeeOther)
		return
	}
	grantToken, grant, err := h.state.redeemSibling(token, sibling.binding, now)
	if err != nil {
		if errors.Is(err, errInvalidHandoffTicket) {
			writeError(w, http.StatusNotFound, "handoff not found")
			return
		}
		h.confirmationError(w, r, err)
		return
	}
	// The browser keeps this cookie until the parent's absolute expiry; Odo
	// enforces inactivity server-side and renews the whole family together.
	http.SetCookie(w, handoffCookie(vendorGrantCookie, grantToken, grant.limit))
	h.verifyGrantRedirect(w, r, authority, grantToken, sibling.next)
}
