package api

import (
	"errors"
	"net/http"
	"net/url"
	"time"

	"example.org/odo/internal/auth/local"
	"example.org/odo/internal/cookiepolicy"
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
	s.redirectLaunchTarget(w, r, parsed.String())
}

func (s *Server) redirectLaunchTarget(w http.ResponseWriter, r *http.Request, rawTarget string) {
	// Reuse the production DNS and resource checks, without issuing an upstream
	// HTTP request or creating a vendor cookie jar or hostname mapping.
	target, result := s.proxyTarget(r.Context(), rawTarget)
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
	if s.handoff != nil {
		s.handoff.launch(w, r, target)
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
				if isDocumentNavigation(r) {
					s.beginLaunchLogin(w, r, target.String())
					return
				}
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login_required", "login_url": "/login"})
				return
			}
		}
	}
	http.Redirect(w, r, proxy.BuildProxyURL(target), http.StatusFound)
}

func (s *Server) beginLaunchLogin(w http.ResponseWriter, r *http.Request, target string) {
	cookieName := launchBrowserCookieName(r)
	nonce := ""
	if cookie, err := r.Cookie(cookieName); err == nil && validLaunchToken(cookie.Value) {
		nonce = cookie.Value
	}
	if nonce == "" {
		var err error
		nonce, err = local.NewToken("", 32)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
	}
	now := time.Now()
	token, err := s.launchContinuations.create(target, nonce, now)
	if errors.Is(err, errLaunchContinuationsFull) {
		writeError(w, http.StatusServiceUnavailable, "launch temporarily unavailable")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	http.SetCookie(w, cookiepolicy.Apply(r, &http.Cookie{
		Name: cookieName, Value: nonce, HttpOnly: true,
		MaxAge: int(launchContinuationTTL.Seconds()), Expires: now.Add(launchContinuationTTL),
	}))
	next := launchContinuePath + "?token=" + token
	http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusFound)
}

func (s *Server) continueLaunch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	token, valid := launchContinuationToken(r.URL.RawQuery)
	nonce, err := r.Cookie(launchBrowserCookieName(r))
	if !valid || err != nil || !validLaunchToken(nonce.Value) {
		writeError(w, http.StatusNotFound, "launch continuation not found")
		return
	}
	_, _, signedIn, err := s.currentUser(r)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !signedIn {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login_required", "login_url": "/login"})
		return
	}
	target, found := s.launchContinuations.consume(token, nonce.Value, time.Now())
	if !found {
		writeError(w, http.StatusNotFound, "launch continuation not found")
		return
	}
	s.redirectLaunchTarget(w, r, target)
}

func launchBrowserCookieName(r *http.Request) string {
	if cookiepolicy.Secure(r) {
		return "__Host-" + launchNonceCookieName
	}
	return launchNonceCookieName
}
