package api

import (
	"net/http"

	"example.org/odo/internal/proxy"
	"example.org/odo/internal/resources"
)

func (s *Server) launch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	parsed, err := proxy.ParseLaunchQuery(r.URL.RawQuery)
	if err != nil {
		writeError(w, http.StatusBadRequest, "launch target URL is invalid")
		return
	}
	// Reuse the production DNS and resource checks, without issuing an upstream
	// HTTP request or creating a vendor cookie jar or hostname mapping.
	target, result := s.proxyTarget(r.Context(), parsed.String())
	if result.InternalError != nil {
		s.internalError(w, r, result.InternalError)
		return
	}
	if target == nil || !result.Allowed {
		writeError(w, http.StatusForbidden, "launch target is not allowed")
		return
	}
	if !resources.MethodAllowed(result, http.MethodGet) {
		writeError(w, http.StatusForbidden, "launch target is not allowed")
		return
	}
	if s.proxyLoginRequired() {
		anonymous := s.explicitAnonymousProxyResult(r, target)
		if anonymous.InternalError != nil {
			s.internalError(w, r, anonymous.InternalError)
			return
		}
		if !result.AnonymousRuleMatched && !(anonymous.Allowed && anonymous.AnonymousRuleMatched) {
			_, _, ok, err := s.currentUser(r)
			if err != nil {
				s.internalError(w, r, err)
				return
			}
			if !ok {
				// Do not put the target in a login return URL. A bounded,
				// server-side continuation will be a separate implementation.
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login_required", "login_url": "/login"})
				return
			}
		}
	}
	http.Redirect(w, r, proxy.BuildProxyURL(target), http.StatusFound)
}
