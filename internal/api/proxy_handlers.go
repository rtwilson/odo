package api

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"example.org/odo/internal/accesslog"
	"example.org/odo/internal/proxy"
	"example.org/odo/internal/resources"
)

func (s *Server) handleUnknownPath(w http.ResponseWriter, r *http.Request) {
	event := proxy.MissedRewriteEvent{
		Type:                proxy.MissedRewriteEventType,
		Method:              r.Method,
		Path:                r.URL.Path,
		LocalPath:           r.URL.Path,
		RequestKind:         proxy.MissedRewriteRequestKind(r),
		RecoveryAction:      proxy.RecoveryActionNotRecovered,
		AcceptHeaderSummary: proxy.AcceptHeaderSummary(r.Header.Get("Accept")),
		SecFetchDest:        strings.TrimSpace(r.Header.Get("Sec-Fetch-Dest")),
		SecFetchMode:        strings.TrimSpace(r.Header.Get("Sec-Fetch-Mode")),
	}
	if proxy.ProtectedAppPath(r.URL.Path) {
		event.Reason = "protected app path"
		s.missedDiag.Add(event)
		http.NotFound(w, r)
		return
	}
	if !proxy.RefererRecoveryEnabled() {
		event.Reason = "referer recovery disabled"
		s.missedDiag.Add(event)
		http.NotFound(w, r)
		return
	}
	target, refererRoute, err := proxy.RecoverTargetFromReferer(r)
	event.RefererRoute = refererRoute
	if err != nil {
		event.Reason = err.Error()
		s.missedDiag.Add(event)
		http.NotFound(w, r)
		return
	}
	event.RecoveredTargetHost = strings.ToLower(strings.TrimSuffix(target.Hostname(), "."))
	event.RecoveredPathPrefix = proxy.SafePathPrefix(target.EscapedPath())
	event.CanonicalProxyPath = proxy.CanonicalProxyPathWithoutQuery(target)

	if event.RequestKind == proxy.RequestKindDocument {
		validatedTarget, result := s.proxyTarget(r.Context(), target.String())
		if result.InternalError != nil {
			s.internalError(w, r, result.InternalError)
			return
		}
		if metadata := accesslog.MetadataFrom(r.Context()); metadata != nil {
			metadata.Route = "/odo-recovered"
			metadata.Recovered = true
			metadata.TargetHost = event.RecoveredTargetHost
			metadata.ResourceID = result.ResourceID
			metadata.RuleHost = result.RuleHost
			metadata.RuleMatch = result.RuleMatch
			metadata.Decision = "denied"
			if result.Allowed {
				metadata.Decision = "allowed"
			}
			metadata.DenialReason = result.Reason
		}
		if !result.Allowed || validatedTarget == nil {
			event.RecoveryAction = proxy.RecoveryActionDenied
			event.Reason = "recovery target denied"
			if result.Reason != "" {
				event.Reason = result.Reason
			}
			s.missedDiag.Add(event)
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error":   "target URL is not allowed",
				"allowed": false,
				"reason":  event.Reason,
			})
			return
		}
		canonical := proxy.BuildProxyURL(validatedTarget)
		canonicalURL, err := url.Parse(canonical)
		if err != nil {
			event.RecoveryAction = proxy.RecoveryActionDenied
			event.Reason = "canonical proxy URL is invalid"
			s.missedDiag.Add(event)
			http.NotFound(w, r)
			return
		}
		authReq := r.Clone(r.Context())
		authReq.URL = canonicalURL
		authReq.RequestURI = canonicalURL.RequestURI()
		if !s.requireProxySessionOrAnonymous(w, authReq, validatedTarget, result) {
			event.RecoveryAction = proxy.RecoveryActionDenied
			event.Reason = "proxy access requires login"
			s.missedDiag.Add(event)
			return
		}
		event.Recovered = true
		event.Type = proxy.MissedRewriteRecoveredEventType
		event.RecoveryAction = proxy.RecoveryActionRedirectedToCanonical
		event.Reason = "redirected to canonical proxy URL"
		s.missedDiag.Add(event)
		if s.proxyDebug {
			w.Header().Set("X-Odo-Recovered-From-Referer", "true")
			w.Header().Set("X-Odo-Recovery-Action", proxy.RecoveryActionHeader(event.RecoveryAction))
			w.Header().Set("X-Odo-Target-Host", event.RecoveredTargetHost)
		}
		http.Redirect(w, r, canonical, http.StatusFound)
		return
	}

	recoveredReq := r.Clone(r.Context())
	recoveredReq = proxy.WithRecoveredFromReferer(recoveredReq)
	recoveredReq = proxy.WithRecoveryAction(recoveredReq, proxy.RecoveryActionSilentlyProxied)
	recoveredReq.URL = &url.URL{Path: proxy.PublicProxyPath, RawQuery: "url=" + url.QueryEscape(target.String())}
	recoveredReq.RequestURI = recoveredReq.URL.RequestURI()
	if metadata := accesslog.MetadataFrom(recoveredReq.Context()); metadata != nil {
		metadata.Route = "/odo-recovered"
		metadata.Recovered = true
	}

	validatedTarget, result := s.proxyTarget(recoveredReq.Context(), target.String())
	if validatedTarget == nil && target.Hostname() != "" {
		result.Host = strings.ToLower(strings.TrimSuffix(target.Hostname(), "."))
	}
	if !s.requireProxySessionOrAnonymous(w, recoveredReq, target, result) {
		event.RecoveryAction = proxy.RecoveryActionDenied
		event.Reason = "proxy access requires login"
		s.missedDiag.Add(event)
		return
	}

	recorder := &recoveryRecorder{ResponseWriter: w}
	s.proxyH.ServeHTTP(recorder, recoveredReq)
	event.UpstreamStatus = recorder.status
	event.ContentType = recorder.Header().Get("Content-Type")
	if recorder.status >= http.StatusOK && recorder.status < http.StatusBadRequest {
		event.Recovered = true
		event.Type = proxy.MissedRewriteRecoveredEventType
		event.RecoveryAction = proxy.RecoveryActionSilentlyProxied
		event.Reason = "recovered from proxied referer"
	} else {
		event.RecoveryAction = proxy.RecoveryActionDenied
		event.Reason = "recovery target denied"
	}
	s.missedDiag.Add(event)
}

func (s *Server) legacyProxyRedirect(w http.ResponseWriter, r *http.Request) {
	targetURL, _, _, err := proxy.ParseProxyRequest(r)
	if err != nil {
		http.Redirect(w, r, proxy.PublicProxyPath, http.StatusMovedPermanently)
		return
	}
	http.Redirect(w, r, proxy.BuildProxyURL(targetURL), http.StatusMovedPermanently)
}

func (s *Server) proxyLoginRequired() bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv("APP_PROXY_REQUIRE_LOGIN")))
	switch value {
	case "false", "0", "no", "off":
		return false
	case "true", "1", "yes", "on":
		return true
	}
	count, err := s.store.CountUsers()
	return err == nil && count > 0
}

func (s *Server) requireProxySession(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		target, _, _, err := proxy.ParseProxyRequest(r)
		var result resources.TestResult
		var validatedTarget *url.URL
		if err == nil {
			validatedTarget, result = s.proxyTarget(r.Context(), target.String())
			if validatedTarget == nil && target != nil && target.Hostname() != "" {
				result.Host = strings.ToLower(strings.TrimSuffix(target.Hostname(), "."))
			}
		}
		if s.requireProxySessionOrAnonymous(w, r, target, result) {
			next.ServeHTTP(w, r)
		}
	}
}

func (s *Server) requireProxySessionOrAnonymous(w http.ResponseWriter, r *http.Request, target *url.URL, result resources.TestResult) bool {
	if result.InternalError != nil {
		s.internalError(w, r, result.InternalError)
		return false
	}
	if !s.proxyLoginRequired() {
		return true
	}
	if target != nil {
		if anonymous := s.explicitAnonymousProxyResult(r, target); anonymous.Allowed && anonymous.AnonymousRuleMatched {
			return true
		}
	}
	if result.Allowed && result.AnonymousRuleMatched {
		return true
	}
	_, _, ok, err := s.currentUser(r)
	if err != nil {
		s.internalError(w, r, err)
		return false
	}
	if ok {
		return true
	}
	s.markProxyLoginRequired(r, target, result)
	if isDocumentNavigation(r) {
		_ = s.store.Audit("login_required_redirect", fmt.Sprintf(`{"path":%q}`, r.URL.Path))
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		return false
	}
	writeJSON(w, http.StatusUnauthorized, map[string]string{
		"error":     "login_required",
		"login_url": "/login",
		"reason":    "proxy access requires login",
	})
	return false
}

func (s *Server) explicitAnonymousProxyResult(r *http.Request, target *url.URL) resources.TestResult {
	if target == nil {
		return resources.TestResult{Allowed: false}
	}
	items, err := s.store.ListResources()
	if err != nil {
		return resources.TestResult{Allowed: false, Reason: "resource lookup failed", InternalError: err}
	}
	return resources.AnonymousURLRuleResult(target.String(), r.Method, items)
}

func (s *Server) markProxyLoginRequired(r *http.Request, target *url.URL, result resources.TestResult) {
	metadata := accesslog.MetadataFrom(r.Context())
	if metadata == nil {
		return
	}
	metadata.Route = proxy.PublicProxyPath
	metadata.Decision = "login_required"
	metadata.DenialReason = "proxy access requires login"
	metadata.NextPath = r.URL.Path
	metadata.PathKind = proxy.MissedRewriteRequestKind(r)
	anonymousMatched := result.AnonymousRuleMatched
	metadata.AnonymousRuleMatched = &anonymousMatched
	if target != nil && target.Hostname() != "" {
		metadata.TargetHost = strings.ToLower(strings.TrimSuffix(target.Hostname(), "."))
	} else if result.Host != "" {
		metadata.TargetHost = result.Host
	}
	metadata.ResourceID = result.ResourceID
	metadata.RuleHost = result.RuleHost
	metadata.RuleMatch = result.RuleMatch
}

func (s *Server) proxyRequestAllowedAnonymously(r *http.Request) bool {
	target, _, _, err := proxy.ParseProxyRequest(r)
	if err != nil {
		return false
	}
	_, result := s.proxyTarget(r.Context(), target.String())
	return result.Allowed && result.AnonymousRuleMatched
}

func isDocumentNavigation(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	dest := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Dest")))
	if dest != "" && dest != "document" {
		return false
	}
	mode := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Mode")))
	if mode != "" && mode != "navigate" {
		return false
	}
	accept := strings.ToLower(r.Header.Get("Accept"))
	return accept == "" || strings.Contains(accept, "text/html")
}

type recoveryRecorder struct {
	http.ResponseWriter
	status int
}

func (r *recoveryRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *recoveryRecorder) Write(data []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(data)
}

func (s *Server) proxyRawURL(rawURL string) resources.TestResult {
	_, result := s.proxyTarget(context.Background(), rawURL)
	return result
}

func (s *Server) proxyTarget(ctx context.Context, rawURL string) (*url.URL, resources.TestResult) {
	target, err := proxy.ValidateTargetURL(ctx, rawURL, s.ipLookup)
	if err != nil {
		return nil, resources.TestResult{Allowed: false, Reason: err.Error(), SafetyReason: proxy.SafetyReason(err)}
	}
	items, err := s.store.ListResources()
	if err != nil {
		return nil, resources.TestResult{Allowed: false, Reason: "resource lookup failed", InternalError: err}
	}
	result := resources.TestURL(target.String(), items)
	if !result.Allowed {
		return nil, result
	}
	if result.Action != "proxy" {
		result.Allowed = false
		result.Reason = "not_proxyable"
		return nil, result
	}
	return target, result
}
