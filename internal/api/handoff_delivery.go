package api

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"example.org/odo/internal/accesslog"
	"example.org/odo/internal/proxy"
)

// Experimental vendor content delivery on registered proxy hostnames. It is
// reachable only through guardHost when APP_EXPERIMENTAL_HANDOFF is enabled,
// which startup rejects outside development/test. It serves GET and HEAD only,
// requires a live host-only grant, and authorizes every request and response
// through the runtime's single grantCookieCoordinator. It never rewrites bodies,
// follows redirects, or accepts client-supplied upstream URLs or resource IDs.

const (
	vendorContentRoute         = "handoff_vendor_content"
	vendorContentMaxRequestURI = 8 * 1024
	vendorReservedPath         = "/.well-known/odo"
)

// Only these browser request headers are sent upstream. Cookies, Authorization,
// Forwarded/X-Forwarded-*, hop-by-hop and all other headers are never copied.
var vendorRequestHeaders = []string{"Accept", "Accept-Language", "User-Agent", "Range", "If-Range"}

// Only these upstream response headers reach the browser. Set-Cookie, CSP, CORS,
// HSTS, Alt-Svc, Link, Refresh, Location (outside translated redirects) and
// hop-by-hop headers are dropped. Cache-Control is replaced with no-store.
var vendorResponseHeaders = []string{
	"Content-Type", "Content-Disposition", "Content-Language", "Last-Modified", "ETag",
	"Content-Length", "Content-Encoding", "Accept-Ranges", "Content-Range",
}

func (h *handoffSecurity) serveVendorContent(w http.ResponseWriter, r *http.Request) {
	r.Pattern = vendorContentRoute
	metadata := accesslog.MetadataFrom(r.Context())
	if metadata != nil {
		// The route replaces the path in access logs; never record vendor paths,
		// queries or raw browser headers.
		metadata.Route = vendorContentRoute
		metadata.SuppressBrowserHeaders = true
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if h.cookies == nil || h.vendor == nil {
		writeError(w, http.StatusServiceUnavailable, "vendor delivery is unavailable")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// GET/HEAD bodies are a smuggling and ambiguity vector; reject them.
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		writeError(w, http.StatusBadRequest, "request body is not allowed")
		return
	}
	authority := h.vendorContentAuthority(r)
	if authority == "" {
		writeError(w, http.StatusMisdirectedRequest, "request authority is not admitted")
		return
	}
	if len(r.RequestURI) > vendorContentMaxRequestURI {
		writeError(w, http.StatusRequestURITooLong, "request target is too long")
		return
	}
	if !vendorContentPathAllowed(r.URL) {
		writeError(w, http.StatusBadRequest, "request target is invalid")
		return
	}
	mapping, err := h.mapping(authority)
	if err != nil {
		if errors.Is(err, errHandoffDenied) {
			writeError(w, http.StatusMisdirectedRequest, "request authority is not admitted")
		} else {
			h.server.internalError(w, r, errors.New("vendor hostname lookup failed"))
		}
		return
	}
	// The upstream authority comes only from the trusted registry mapping.
	target, ok := vendorUpstreamURL(mapping.Hostname, r.URL)
	if !ok {
		writeError(w, http.StatusBadRequest, "request target is invalid")
		return
	}
	grant, ok := uniqueConfirmationCookie(r, vendorGrantCookie)
	if !ok || !validLaunchToken(grant) {
		// Duplicate grant cookies are ambiguous; never loop them through launch.
		if !hasCookie(r, vendorGrantCookie) || ok {
			if h.restartHandoff(w, r, target) {
				return
			}
		}
		writeError(w, http.StatusUnauthorized, "authentication handoff required")
		return
	}
	upstream, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), nil)
	if err != nil {
		writeError(w, http.StatusBadRequest, "request target is invalid")
		return
	}
	for _, name := range vendorRequestHeaders {
		for _, value := range r.Header.Values(name) {
			upstream.Header.Add(name, value)
		}
	}
	upstream.Header.Set("Accept-Encoding", "identity")

	// Live grant, parent session, current resource policy for this exact target
	// and method, DNS safety, and the resource's jar are all decided here.
	prepared, exchange, err := h.cookies.prepareRequest(upstream, grant, authority)
	if err != nil {
		// An expired/unknown grant or invalid parent session restarts the
		// handoff for top-level navigations; policy denials never do.
		if errors.Is(err, errHandoffDenied) && h.restartHandoff(w, r, target) {
			return
		}
		h.vendorDeliveryError(w, r, err, "authorize")
		return
	}
	response, err := h.vendor.Do(prepared)
	if err != nil {
		h.vendorDeliveryError(w, r, err, "fetch")
		return
	}
	defer response.Body.Close()
	if metadata != nil {
		metadata.UpstreamStatus = response.StatusCode
	}
	// Only final 2xx-5xx responses can be represented. A 101 protocol switch (or
	// any other 1xx/out-of-range status) would hand the browser connection to
	// raw upstream bytes. Nothing from such a response is stored or forwarded.
	if response.StatusCode < 200 || response.StatusCode > 599 {
		h.vendorDeliveryError(w, r, errUnsupportedVendorResponse, "response")
		return
	}
	// Decide representability before cookie storage: a redirect Odo refuses to
	// deliver must leave no vendor cookie behind, in the browser or the jar.
	var location string
	if isVendorRedirect(response.StatusCode) {
		next, ok := vendorRedirectLocation(target, mapping.Hostname, authority, response.Header.Get("Location"))
		if !ok {
			// Cross-host, downgraded or malformed redirects cannot be represented
			// on this proxy hostname; never follow or expose them.
			writeError(w, http.StatusBadGateway, "upstream redirect is not supported")
			return
		}
		location = next
	}
	// Reauthorize and store cookies before any header or byte is forwarded.
	if err := exchange.storeResponse(r.Context(), response); err != nil {
		h.vendorDeliveryError(w, r, err, "response")
		return
	}
	// A delivered, fully authorized use is patron activity: slide the grant
	// (throttled, capped at the parent's absolute expiry) and refresh its
	// host-only cookie. This is Odo's own cookie; upstream Set-Cookie is never
	// copied. Responses that fail closed below never renew.
	renew := func() {
		if expires, renewed := h.state.renewGrant(grant, mapping, authority, time.Now().UTC()); renewed {
			http.SetCookie(w, handoffCookie(vendorGrantCookie, grant, expires))
		}
	}
	if location != "" {
		renew()
		w.Header().Set("Location", location)
		w.WriteHeader(response.StatusCode)
		return
	}
	if policy, ok := r.Context().Value(responsePolicyKey{}).(*appResponseWriter); ok {
		// Vendor bytes are not Odo pages: do not apply the central app CSP.
		policy.proxy = true
	}
	headers := w.Header()
	for _, name := range vendorResponseHeaders {
		for _, value := range response.Header.Values(name) {
			headers.Add(name, value)
		}
	}
	headers.Set("Cache-Control", "no-store")
	headers.Set("X-Content-Type-Options", "nosniff")
	renew()
	w.WriteHeader(response.StatusCode)
	if r.Method == http.MethodGet {
		_, _ = io.Copy(w, response.Body)
	}
}

// restartHandoff sends a top-level GET navigation that lacks a live grant to
// central /launch with the trusted upstream target, so the patron re-runs the
// normal login/confirmation handshake and returns here. The target is built
// from the registry hostname, so this is never an open redirect. Subresource,
// XHR and HEAD requests keep their 401 and are never redirected.
func (h *handoffSecurity) restartHandoff(w http.ResponseWriter, r *http.Request, target *url.URL) bool {
	if !isDocumentNavigation(r) {
		return false
	}
	raw := url.Values{"url": {target.String()}}.Encode()
	if len(raw) > proxy.MaxLaunchQueryBytes {
		return false
	}
	location := url.URL{Scheme: "https", Host: h.config.CentralHostname(), Path: "/launch", RawQuery: raw}
	// An empty body avoids reflecting the patron destination into HTML.
	w.Header().Set("Location", location.String())
	w.WriteHeader(http.StatusSeeOther)
	return true
}

func hasCookie(r *http.Request, name string) bool {
	for _, cookie := range r.Cookies() {
		if cookie.Name == name {
			return true
		}
	}
	return false
}

// vendorContentPathAllowed rejects ambiguous paths that upstream servers may
// normalize differently, and Odo's reserved control namespace.
func vendorContentPathAllowed(u *url.URL) bool {
	escaped := u.EscapedPath()
	if !strings.HasPrefix(escaped, "/") || u.Fragment != "" {
		return false
	}
	lower := strings.ToLower(u.Path)
	if lower == vendorReservedPath || strings.HasPrefix(lower, vendorReservedPath+"/") {
		return false
	}
	for _, ch := range u.Path {
		if ch < 0x20 || ch == 0x7f || ch == '\\' {
			return false
		}
	}
	for _, segment := range strings.Split(strings.ToLower(escaped), "/") {
		segment = strings.ReplaceAll(segment, "%2e", ".")
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

// vendorUpstreamURL joins the registry hostname with the request's escaped path
// and opaque query, then requires the canonical form to preserve both exactly.
func vendorUpstreamURL(hostname string, requested *url.URL) (*url.URL, bool) {
	raw := "https://" + hostname + requested.EscapedPath()
	if requested.RawQuery != "" || requested.ForceQuery {
		raw += "?" + requested.RawQuery
	}
	target, err := proxy.NormalizeAndValidateTargetURL(raw)
	if err != nil || target.Scheme != "https" || target.Hostname() != hostname || target.Port() != "" ||
		target.User != nil || target.Fragment != "" || target.EscapedPath() != requested.EscapedPath() || target.RawQuery != requested.RawQuery {
		return nil, false
	}
	return target, true
}

func isVendorRedirect(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// vendorRedirectLocation represents only same-host HTTPS redirects, on this
// proxy authority. Anything else fails closed. Fragments are dropped.
func vendorRedirectLocation(base *url.URL, hostname, authority, raw string) (string, bool) {
	if raw == "" || len(raw) > vendorContentMaxRequestURI {
		return "", false
	}
	next, err := base.Parse(raw)
	if err != nil || next.Scheme != "https" || next.User != nil || next.Opaque != "" ||
		!strings.EqualFold(next.Hostname(), hostname) || (next.Port() != "" && next.Port() != "443") {
		return "", false
	}
	if !vendorContentPathAllowed(&url.URL{Path: next.Path, RawPath: next.RawPath}) {
		return "", false
	}
	location := url.URL{Scheme: "https", Host: authority, Path: next.Path, RawPath: next.RawPath, RawQuery: next.RawQuery, ForceQuery: next.ForceQuery}
	return location.String(), true
}

var errUnsupportedVendorResponse = errors.New("upstream response status is not supported")

// vendorDeliveryError maps failures without logging URLs, queries, cookies or
// upstream error text (net/http errors embed the full request URL).
func (h *handoffSecurity) vendorDeliveryError(w http.ResponseWriter, r *http.Request, err error, stage string) {
	var capacity *proxy.CookieJarCapacityError
	var netErr net.Error
	status, message := http.StatusBadGateway, "vendor request failed"
	switch {
	case errors.Is(err, errHandoffDenied):
		status, message = http.StatusUnauthorized, "authentication handoff required"
	case errors.Is(err, errVendorTargetUnsafe) || proxy.SafetyReason(err) != "":
		status, message = http.StatusBadGateway, "vendor destination is not allowed or could not be resolved"
	case errors.Is(err, proxy.ErrCookieAuthorization):
		status, message = http.StatusForbidden, "vendor request is not allowed"
	case errors.As(err, &capacity):
		status, message = http.StatusServiceUnavailable, "vendor delivery is busy"
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()):
		status, message = http.StatusGatewayTimeout, "vendor request timed out"
	case errors.Is(err, context.Canceled):
		status, message = http.StatusBadGateway, "vendor request was canceled"
	case errors.Is(err, errUnsupportedVendorResponse):
		status, message = http.StatusBadGateway, "upstream response is not supported"
	case stage == "authorize" || stage == "response":
		status, message = http.StatusServiceUnavailable, "vendor delivery is temporarily unavailable"
	}
	if h.server.logger != nil {
		h.server.logger.Warn("vendor delivery failed", "route", vendorContentRoute, "stage", stage, "status", status, "reason", message, "safety_reason", proxy.SafetyReason(err))
	}
	writeError(w, status, message)
}
