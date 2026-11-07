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

// Only this exact control path may bypass central-only host admission. Matching
// absolute-form and Host authorities is mandatory; forwarding headers are ignored.
func (h *handoffSecurity) vendorRequest(r *http.Request) bool {
	central, label, err := h.config.ClassifyAuthority(r.Host)
	if err != nil || central || label == "" || r.URL == nil || r.URL.User != nil || r.URL.Opaque != "" || r.URL.Path != handoffVendorPath || r.URL.EscapedPath() != handoffVendorPath {
		return false
	}
	if r.URL.Host != "" || r.URL.Scheme != "" {
		absoluteCentral, absoluteLabel, err := h.config.ClassifyAuthority(r.URL.Host)
		if err != nil || absoluteCentral || absoluteLabel != label || r.URL.Scheme != "https" {
			return false
		}
	}
	return true
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
	writeError(w, 404, "handoff not found")
}

func (h *handoffSecurity) prepareBrowser(w http.ResponseWriter, r *http.Request, mapping db.ProxyHostname, authority, token string) {
	now := time.Now().UTC()
	h.state.mu.Lock()
	h.state.cleanupLocked(now)
	pending, found := h.state.entries[local.HashToken(token)]
	h.state.mu.Unlock()
	if !found || pending.binding.hostname != mapping.Hostname || pending.binding.label != mapping.Label || pending.binding.proxyAuthority != authority {
		writeError(w, 404, "handoff not found")
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
		writeError(w, 404, "handoff not found")
		return
	}
	ticket, found := h.state.inspectTicket(token, mapping, authority, nonce, time.Now().UTC())
	if !found {
		writeError(w, 404, "handoff not found")
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
	// Clean the one-use token from the address bar. The clean endpoint displays
	// only an inert receipt after live grant validation, never the stored target.
	location := url.URL{Scheme: "https", Host: authority, Path: handoffVendorPath}
	http.Redirect(w, r, location.String(), 303)
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
	_, _ = w.Write([]byte(`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Odo handoff complete</title></head><body><main><h1>Authentication handoff complete</h1><p>Vendor content delivery is disabled.</p></main></body></html>`))
}
