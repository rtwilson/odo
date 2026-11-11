package api

import (
	"net/http"
	"net/url"
	"strings"

	"example.org/odo/internal/accesslog"
	"example.org/odo/internal/proxy"
)

func (s *Server) guardCentralOrigin(next http.Handler) http.Handler {
	enabled, config, configErr := hostGuardConfigFromEnv()
	if !enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reject := func(status int, message string) {
			if metadata := accesslog.MetadataFrom(r.Context()); metadata != nil {
				metadata.Route = "origin_rejected"
			}
			w.Header().Set("Cache-Control", "no-store")
			writeError(w, status, message)
		}
		if configErr != nil {
			reject(http.StatusServiceUnavailable, "host guard configuration is invalid")
			return
		}
		if r.URL.Path == "/logout" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			w.Header().Set("Allow", http.MethodPost)
			reject(http.StatusMethodNotAllowed, "logout requires POST")
			return
		}
		api := r.URL.Path == "/api/v1" || strings.HasPrefix(r.URL.Path, "/api/v1/")
		if !unsafeMethod(r.Method) || (!api && r.URL.Path != "/login" && r.URL.Path != "/logout") {
			next.ServeHTTP(w, r)
			return
		}
		origins := r.Header.Values("Origin")
		// Management bearer authentication is explicit, not an ambient browser
		// credential. An invalid key cannot fall back to session authentication.
		if len(origins) == 0 && api && bearerToken(r.Header.Get("Authorization")) != "" {
			next.ServeHTTP(w, r)
			return
		}
		if !centralRequestOriginAllowed(r, config) {
			reject(http.StatusForbidden, "request origin is not allowed")
			return
		}
		// Existing session CSRF checks still run after this boundary.
		next.ServeHTTP(w, r)
	})
}

// centralRequestOriginAllowed accepts a state-changing browser request only
// from the central origin. Central pages send Referrer-Policy: no-referrer, so
// under the Fetch standard browsers send "Origin: null" on their own
// same-origin form POSTs (login, logout, handoff confirmation). That value is
// accepted only with exactly one browser-set "Sec-Fetch-Site: same-origin",
// a forbidden header page script cannot set. Every other null origin
// (sandboxed frames, data: URLs, cross-site documents, redirects) reports a
// different site and stays rejected. Callers must already have admitted the
// request on the central host; CSRF token checks still run afterwards.
func centralRequestOriginAllowed(r *http.Request, config proxy.HostRoutingConfig) bool {
	origins := r.Header.Values("Origin")
	if len(origins) != 1 {
		return false
	}
	if centralOriginAllowed(origins[0], config) {
		return true
	}
	sites := r.Header.Values("Sec-Fetch-Site")
	return origins[0] == "null" && len(sites) == 1 && sites[0] == "same-origin"
}

func centralOriginAllowed(raw string, config proxy.HostRoutingConfig) bool {
	if raw != strings.TrimSpace(raw) || strings.Contains(raw, "#") {
		return false
	}
	origin, err := url.Parse(raw)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil ||
		origin.Opaque != "" || origin.Path != "" || origin.ForceQuery || origin.RawQuery != "" {
		return false
	}
	central, _, err := config.ClassifyAuthority(origin.Host)
	return err == nil && central
}
