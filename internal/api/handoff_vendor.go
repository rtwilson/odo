package api

import (
	"errors"
	"net/http"
	"net/url"
	"time"

	"example.org/odo/internal/auth/local"
	"example.org/odo/internal/db"
)

const (
	vendorNonceCookie = "__Host-odo_grant_nonce"
	vendorGrantCookie = "__Host-odo_proxy_grant"
)

// Only this exact control path is a handoff control route. Matching
// absolute-form and Host authorities is mandatory; forwarding headers are ignored.
func (h *handoffSecurity) vendorRequest(r *http.Request) bool {
	return h.vendorContentAuthority(r) != "" && r.URL.Path == handoffVendorPath && r.URL.EscapedPath() == handoffVendorPath
}

// vendorContentAuthority returns the canonical proxy authority for a request
// syntactically addressed to one proxy hostname, or "". It does not consult the
// registry. Host is the only authority source; an absolute-form request URI
// must name the same label over HTTPS, and userinfo/opaque forms are rejected.
func (h *handoffSecurity) vendorContentAuthority(r *http.Request) string {
	central, label, err := h.config.ClassifyAuthority(r.Host)
	if err != nil || central || label == "" || r.URL == nil || r.URL.User != nil || r.URL.Opaque != "" {
		return ""
	}
	if r.URL.Host != "" || r.URL.Scheme != "" {
		absoluteCentral, absoluteLabel, err := h.config.ClassifyAuthority(r.URL.Host)
		if err != nil || absoluteCentral || absoluteLabel != label || r.URL.Scheme != "https" {
			return ""
		}
	}
	return label + "." + h.config.ProxyBaseDomain()
}

func (h *handoffSecurity) serveVendor(w http.ResponseWriter, r *http.Request) {
	handoffHeaders(w, r, "handoff_vendor")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, 405, "method not allowed")
		return
	}
	_, label, _ := h.config.ClassifyAuthority(r.Host)
	authority := label + "." + h.config.ProxyBaseDomain()
	mapping, err := h.mapping(authority)
	if err != nil {
		if errors.Is(err, errHandoffDenied) {
			writeError(w, 421, "request authority is not admitted")
		} else {
			h.server.internalError(w, r, err)
		}
		return
	}
	if r.URL.RawQuery == "" && !r.URL.ForceQuery {
		h.complete(w, r, mapping, authority)
		return
	}
	if len(r.URL.RawQuery) > 256 {
		writeError(w, 400, "invalid handoff input")
		return
	}
	fields, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(fields) != 1 {
		writeError(w, 400, "invalid handoff input")
		return
	}
	if values, ok := fields["handoff"]; ok && len(values) == 1 && validLaunchToken(values[0]) {
		h.prepareBrowser(w, r, mapping, authority, values[0])
		return
	}
	if values, ok := fields["ticket"]; ok && len(values) == 1 && validLaunchToken(values[0]) {
		h.redeemBrowser(w, r, mapping, authority, values[0])
		return
	}
	if values, ok := fields["finish"]; ok && len(values) == 1 && validLaunchToken(values[0]) {
		h.finishNavigation(w, r, mapping, authority, values[0])
		return
	}
	if values, ok := fields["sibling"]; ok && len(values) == 1 && validLaunchToken(values[0]) {
		h.redeemSiblingBrowser(w, r, authority, values[0])
		return
	}
	handoffNavigationFailure(w, http.StatusNotFound)
}

func (h *handoffSecurity) prepareBrowser(w http.ResponseWriter, r *http.Request, mapping db.ProxyHostname, authority, token string) {
	now := time.Now().UTC()
	h.state.mu.Lock()
	h.state.cleanupLocked(now)
	pending, found := h.state.liveEntry(local.HashToken(token), now)
	h.state.mu.Unlock()
	if !found || pending.binding.hostname != mapping.Hostname || pending.binding.label != mapping.Label || pending.binding.proxyAuthority != authority {
		handoffNavigationFailure(w, http.StatusNotFound)
		return
	}
	if _, err := h.parent(pending.binding, now); err != nil {
		h.confirmationError(w, r, err)
		return
	}
	if _, err := h.target(r.Context(), pending.binding, pending.target, "GET", pending.resourceID); err != nil {
		h.confirmationError(w, r, err)
		return
	}
	// Central cannot read a host-only vendor cookie. Check it here and skip
	// proof/ticket issuance only for the same live central parent and target.
	if grant, unique := uniqueConfirmationCookie(r, vendorGrantCookie); unique {
		auth, err := h.authorizeGrant(r.Context(), grant, authority, pending.target, "GET", now)
		if err == nil && auth.parentSessionID == pending.binding.parentSessionID && auth.parentSessionHash == pending.binding.parentSessionHash {
			base, _ := url.Parse(pending.target)
			if next, ok := vendorRedirectLocation(base, mapping.Hostname, authority, pending.target); ok {
				h.discardPending(token)
				w.Header().Set("Location", next)
				w.WriteHeader(http.StatusSeeOther)
				return
			}
		}
	}
	nonce, fresh, err := browserHandoffNonce(r, vendorNonceCookie)
	if err != nil {
		h.confirmationError(w, r, err)
		return
	}
	proof, err := h.state.prepare(token, mapping, authority, nonce, time.Now().UTC())
	if err != nil {
		h.confirmationError(w, r, err)
		return
	}
	if fresh {
		http.SetCookie(w, handoffCookie(vendorNonceCookie, nonce, time.Now().UTC().Add(pendingHandoffTTL)))
	}
	location := url.URL{Scheme: "https", Host: h.config.CentralHostname(), Path: handoffConfirmPath, RawQuery: url.Values{"handoff": {token}, "proof": {proof}}.Encode()}
	http.Redirect(w, r, location.String(), 303)
}

func (h *handoffSecurity) redeemBrowser(w http.ResponseWriter, r *http.Request, mapping db.ProxyHostname, authority, token string) {
	nonce, ok := uniqueConfirmationCookie(r, vendorNonceCookie)
	if !ok || !validLaunchToken(nonce) {
		handoffNavigationFailure(w, http.StatusNotFound)
		return
	}
	ticket, found := h.state.inspectTicket(token, mapping, authority, nonce, time.Now().UTC())
	if !found {
		handoffNavigationFailure(w, http.StatusNotFound)
		return
	}
	if _, err := h.parent(ticket.binding, time.Now().UTC()); err != nil {
		h.confirmationError(w, r, err)
		return
	}
	if _, err := h.target(r.Context(), ticket.binding, ticket.target, "GET", ticket.resourceID); err != nil {
		h.confirmationError(w, r, err)
		return
	}
	grantToken, _, err := h.state.redeem(token, ticket.binding, nonce, time.Now().UTC())
	if err != nil {
		h.confirmationError(w, r, err)
		return
	}
	grant, found := h.state.inspectGrant(grantToken, mapping, authority, time.Now().UTC())
	if !found {
		writeError(w, 401, "authentication handoff expired")
		return
	}
	http.SetCookie(w, handoffCookie(vendorGrantCookie, grantToken, grant.expires))
	// Clean the one-use token from the address bar by continuing to the ticket's
	// validated target on this same proxy host, where experimental delivery
	// authorizes it again. Anything not representable on this host falls back
	// to the inert receipt, which never displays the stored target.
	receipt := url.URL{Scheme: "https", Host: authority, Path: handoffVendorPath}
	location := receipt.String()
	if base, err := url.Parse(ticket.target); err == nil {
		if next, ok := vendorRedirectLocation(base, mapping.Hostname, authority, ticket.target); ok {
			location = next
		}
	}
	// Walk the browser through the resource's other registered hosts first,
	// so their assets and links work without another confirmation.
	location = h.siblingChain(r.Context(), grantToken, ticket.resourceID, mapping.Hostname, location, time.Now().UTC())
	h.verifyGrantRedirect(w, r, authority, grantToken, location)
}

func (h *handoffSecurity) complete(w http.ResponseWriter, r *http.Request, mapping db.ProxyHostname, authority string) {
	token, ok := uniqueConfirmationCookie(r, vendorGrantCookie)
	if !ok {
		writeError(w, 401, "authentication handoff required")
		return
	}
	grant, found := h.state.inspectGrant(token, mapping, authority, time.Now().UTC())
	if !found {
		writeError(w, 401, "authentication handoff required")
		return
	}
	if _, err := h.parent(grant.binding, time.Now().UTC()); err != nil {
		h.confirmationError(w, r, err)
		return
	}
	// This is only a receipt, not authorization for any upstream path or method.
	// Require current domain policy too; future fetches must use validateGrant
	// with their actual target/method and connection-time validated-IP dialing.
	ids, err := h.server.store.ProxyHostnameResourceIDs(mapping.Label)
	if err != nil {
		h.server.internalError(w, r, errors.New("handoff resource lookup failed"))
		return
	}
	if len(ids) == 0 {
		writeError(w, 403, "handoff is not allowed")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Odo handoff complete</title></head><body><main><h1>Authentication handoff complete</h1><p>Experimental vendor content delivery is enabled on this host for testing only.</p></main></body></html>`))
}
