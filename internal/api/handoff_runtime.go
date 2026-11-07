package api

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"example.org/odo/internal/accesslog"
	"example.org/odo/internal/auth/local"
	"example.org/odo/internal/proxy"
)

const handoffVendorPath = "/.well-known/odo/redeem"

// A separate test-only mode, not a virtual-host URL strategy. It cannot serve
// vendor bodies on either origin. Configuration is captured at server creation.
func experimentalHandoffConfig() (bool, proxy.HostRoutingConfig, error) {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("APP_EXPERIMENTAL_HANDOFF"))) {
	case "", "false", "0", "no", "off":
		return false, proxy.HostRoutingConfig{}, nil
	case "true", "1", "yes", "on":
	default:
		return false, proxy.HostRoutingConfig{}, errors.New("APP_EXPERIMENTAL_HANDOFF must be true or false")
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("APP_ENV"))) {
	case "", "development", "test":
	default:
		return true, proxy.HostRoutingConfig{}, errors.New("experimental handoff requires development or test environment")
	}
	enabled, config, err := hostGuardConfigFromEnv()
	if err != nil {
		return true, config, err
	}
	if !enabled {
		return true, config, errors.New("experimental handoff requires APP_HOST_GUARD=true")
	}
	return true, config, nil
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
	_, label, err := proxy.RegistryHostname(target.Hostname(), h.config.CentralHostname(), h.config.ProxyBaseDomain())
	if err != nil {
		writeError(w, 403, "launch target is not allowed")
		return
	}
	authority := label + "." + h.config.ProxyBaseDomain()
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
		if r.URL.Path == handoffConfirmPath {
			h.serveConfirmation(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
