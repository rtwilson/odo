package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"example.org/odo/internal/accesslog"
	"example.org/odo/internal/auth/local"
	"example.org/odo/internal/proxy"
	"example.org/odo/internal/resources"
)

const handoffVendorPath = "/.well-known/odo/redeem"

// virtualHostRoutingConfig decides whether virtual-host proxying runs. It is
// enabled by APP_PROXY_URL_MODE=virtual_host, in any environment, or by the
// deprecated alias APP_EXPERIMENTAL_HANDOFF=true. It requires the central host
// guard and valid HTTPS deployment names; any problem is an error, never a
// silent fallback to path mode. Configuration is captured at server creation.
func virtualHostRoutingConfig() (bool, proxy.HostRoutingConfig, error) {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("APP_PROXY_URL_MODE")))
	legacy := false
	switch strings.ToLower(strings.TrimSpace(os.Getenv("APP_EXPERIMENTAL_HANDOFF"))) {
	case "", "false", "0", "no", "off":
	case "true", "1", "yes", "on":
		legacy = true
	default:
		return false, proxy.HostRoutingConfig{}, errors.New("APP_EXPERIMENTAL_HANDOFF must be true or false")
	}
	if legacy && mode != "" && mode != proxy.ProxyURLModeVirtualHost {
		return true, proxy.HostRoutingConfig{}, fmt.Errorf("APP_EXPERIMENTAL_HANDOFF=true conflicts with APP_PROXY_URL_MODE=%s; set APP_PROXY_URL_MODE=virtual_host instead", mode)
	}
	if !legacy && mode != proxy.ProxyURLModeVirtualHost {
		return false, proxy.HostRoutingConfig{}, nil
	}
	enabled, config, err := hostGuardConfigFromEnv()
	if err != nil {
		return true, config, err
	}
	if !enabled {
		return true, config, errors.New("virtual-host proxying requires APP_HOST_GUARD=true, APP_PUBLIC_URL and APP_PROXY_BASE_DOMAIN")
	}
	return true, config, nil
}

// VirtualHostAliasInUse reports the deprecated APP_EXPERIMENTAL_HANDOFF switch,
// so startup can warn about it.
func VirtualHostAliasInUse() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("APP_EXPERIMENTAL_HANDOFF"))) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}

// VirtualHostRoutingEnabled reports whether this process serves virtual hosts.
func VirtualHostRoutingEnabled() bool {
	enabled, _, err := virtualHostRoutingConfig()
	return enabled && err == nil
}

func handoffHeaders(w http.ResponseWriter, r *http.Request, route string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	r.Pattern = route
	if metadata := accesslog.MetadataFrom(r.Context()); metadata != nil {
		metadata.Route = route
		metadata.SuppressBrowserHeaders = true
	}
	if policy, ok := r.Context().Value(responsePolicyKey{}).(*appResponseWriter); ok {
		policy.csp = "default-src 'none'; script-src 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'"
	}
}

func handoffCookie(name, value string, expires time.Time) *http.Cookie {
	remaining := int(time.Until(expires).Seconds())
	if remaining < 0 {
		remaining = -1
	}
	return &http.Cookie{Name: name, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: expires, MaxAge: remaining}
}

func browserHandoffNonce(r *http.Request, name string) (string, bool, error) {
	count := 0
	value := ""
	for _, cookie := range r.Cookies() {
		if cookie.Name == name {
			count++
			value = cookie.Value
		}
	}
	if count == 1 && validLaunchToken(value) {
		return value, false, nil
	}
	if count != 0 {
		return "", false, errInvalidPendingHandoff
	}
	value, err := local.NewToken("", 32)
	return value, true, err
}

func (h *handoffSecurity) launch(w http.ResponseWriter, r *http.Request, target *url.URL) {
	handoffHeaders(w, r, "handoff_launch")
	// Unlike ordinary path mode, this authenticated transfer never uses anonymous
	// exceptions to mint a grant. Login continuation retains only an opaque ID.
	_, _, signedIn, err := h.server.currentUser(r)
	if err != nil {
		h.server.internalError(w, r, err)
		return
	}
	if !signedIn {
		if isDocumentNavigation(r) {
			h.server.beginLaunchLogin(w, r, target.String())
		} else {
			writeJSON(w, 401, map[string]string{"error": "login_required", "login_url": "/login"})
		}
		return
	}
	central, ok := uniqueConfirmationCookie(r, "__Host-odo_session")
	if !ok {
		writeError(w, 401, "login required")
		return
	}
	mapping, err := h.upstreamMapping(target.Hostname())
	switch {
	case errors.Is(err, errHostnameNotRegistered):
		// Policy allows the host, but no administrator has enrolled a proxy
		// hostname for it (for example a host covered only by a subdomain rule).
		denyLaunch(w, r, launchDeniedUnregistered)
		return
	case errors.Is(err, errHandoffDenied):
		denyLaunch(w, r, launchDeniedMappingInvalid)
		return
	case err != nil:
		h.server.internalError(w, r, err)
		return
	}
	authority := mapping.Label + "." + h.config.ProxyBaseDomain()
	nonce, fresh, err := browserHandoffNonce(r, handoffNonceCookie)
	if err != nil {
		h.confirmationError(w, r, err)
		return
	}
	token, err := h.begin(r.Context(), central, authority, target.String(), nonce, time.Now().UTC())
	if err != nil {
		h.confirmationError(w, r, err)
		return
	}
	if fresh {
		http.SetCookie(w, handoffCookie(handoffNonceCookie, nonce, time.Now().UTC().Add(pendingHandoffTTL)))
	}
	location := url.URL{Scheme: "https", Host: authority, Path: handoffVendorPath, RawQuery: url.Values{"handoff": {token}}.Encode()}
	http.Redirect(w, r, location.String(), http.StatusSeeOther)
}

func (h *handoffSecurity) dispatchCentral(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		legacyPath := func(value string) bool {
			return value == "/p" || value == "/odo" || strings.HasPrefix(value, "/odo/")
		}
		// Intercept before ServeMux can canonicalize a legacy bookmark or apply
		// the ordinary proxy session/login middleware. Aliases are rejected.
		if legacyPath(r.URL.Path) || legacyPath(path.Clean(r.URL.Path)) {
			h.migrateLegacyBookmark(w, r)
			return
		}
		if r.URL.Path == handoffStartPath {
			h.resumeNavigation(w, r)
			return
		}
		if r.URL.Path == handoffConfirmPath {
			h.serveConfirmation(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Migration validates without fetching, authenticating, or creating handoff
// state. /launch performs its own fresh validation and login/handoff workflow.
func (h *handoffSecurity) migrateLegacyBookmark(w http.ResponseWriter, r *http.Request) {
	handoffHeaders(w, r, "handoff_legacy_migration")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var target *url.URL
	var err error
	switch r.URL.EscapedPath() {
	case "/odo", "/odo/", "/p":
		target, err = proxy.ParseLaunchQuery(r.URL.RawQuery)
	default:
		if !strings.HasPrefix(r.URL.EscapedPath(), "/odo/https/") || len(r.URL.RequestURI()) > proxy.MaxLaunchQueryBytes {
			writeError(w, http.StatusBadRequest, "legacy target URL is invalid")
			return
		}
		target, _, _, err = proxy.ParseProxyRequest(r)
		if err == nil {
			// Apply the same strict syntax and HTTPS requirements as /launch,
			// preserving escaped paths and opaque vendor query bytes.
			target, err = proxy.ParseLaunchQuery(url.Values{"url": {target.String()}}.Encode())
		}
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "legacy target URL is invalid")
		return
	}
	target, result, reason := h.server.classifiedProxyTarget(r.Context(), target.String())
	if result.InternalError != nil {
		h.server.internalError(w, r, result.InternalError)
		return
	}
	if target != nil && result.Allowed && !resources.MethodAllowed(result, http.MethodGet) {
		reason = launchDeniedMethod
	}
	if reason != "" {
		recordDenialReason(r, reason)
		writeError(w, http.StatusForbidden, "legacy target is not allowed")
		return
	}
	location, err := h.navigationStart(target.String())
	if err != nil {
		h.server.internalError(w, r, err)
		return
	}
	// An empty redirect body avoids reflecting a patron destination into HTML.
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusSeeOther)
}
