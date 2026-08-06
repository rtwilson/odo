package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"example.org/odo/internal/accesslog"
	"example.org/odo/internal/resources"
)

type TargetCheck func(ctx context.Context, rawURL string) (*url.URL, resources.TestResult)

type FetchOptions struct {
	Client       *http.Client
	Check        TargetCheck
	Sessions     *SessionStore
	DebugHeaders bool
	Diagnostics  *DiagnosticsStore
	MaxBodyBytes int64
}

const (
	recoveredContextKey      = "odo_recovered_from_referer"
	recoveryActionContextKey = "odo_recovery_action"
)

const DefaultProxyMaxBodyBytes int64 = 10 * 1024 * 1024

func DefaultHTTPClient() *http.Client {
	return DefaultHTTPClientWithResolver(net.DefaultResolver.LookupIPAddr)
}

func DefaultHTTPClientWithResolver(lookup IPLookupFunc) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext:           SafeDialContext(lookup),
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func FetchHandler(client *http.Client, check TargetCheck) http.HandlerFunc {
	return FetchHandlerWithOptions(FetchOptions{Client: client, Check: check})
}

func FetchHandlerWithOptions(options FetchOptions) http.HandlerFunc {
	client := options.Client
	if client == nil {
		client = DefaultHTTPClient()
	}
	sessions := options.Sessions
	if sessions == nil {
		sessions = NewSessionStore(2 * time.Hour)
	}
	maxBodyBytes := options.MaxBodyBytes
	if maxBodyBytes <= 0 {
		maxBodyBytes = ProxyMaxBodyBytes()
	}
	check := options.Check
	return func(w http.ResponseWriter, r *http.Request) {
		if !globallySupportedProxyMethod(r.Method) {
			writeProxyError(w, http.StatusMethodNotAllowed, "method not allowed", "")
			return
		}
		ctx, diagnostics := WithDiagnostics(r.Context())
		r = r.WithContext(ctx)
		session := sessions.GetOrCreate(r, w)

		parsedTarget, parsedMode, _, parseErr := ParseProxyRequest(r)
		rawURL := ""
		var target *url.URL
		var result resources.TestResult
		if parseErr != nil {
			result = resources.TestResult{Allowed: false, Reason: parseErr.Error()}
		} else {
			rawURL = parsedTarget.String()
			target, result = check(r.Context(), rawURL)
		}
		diagnostics.Method = r.Method
		if target != nil {
			diagnostics.TargetHost = strings.ToLower(strings.TrimSuffix(target.Hostname(), "."))
		} else if parsedTarget != nil {
			diagnostics.TargetHost = strings.ToLower(strings.TrimSuffix(parsedTarget.Hostname(), "."))
		}
		diagnostics.ProxyURLMode = parsedMode
		if diagnostics.ProxyURLMode == "" {
			diagnostics.ProxyURLMode = ProxyURLMode()
		}
		diagnostics.ResourceID = result.ResourceID
		diagnostics.MatchedDomain = result.RuleHost
		diagnostics.DomainBehavior = result.Behavior
		diagnostics.DomainRole = result.Role
		diagnostics.AnonymousRuleMatched = result.AnonymousRuleMatched
		diagnostics.AnonymousRulePattern = result.AnonymousRulePattern
		diagnostics.JavaScriptTextRewriteEnabled = result.JavaScriptTextRewriteEnabled
		if !result.Allowed && result.SafetyReason != "" {
			diagnostics.Type = "proxy_target_blocked"
			diagnostics.Reason = result.SafetyReason
		}
		defer func() {
			options.Diagnostics.Add(*diagnostics)
		}()
		setAccessLogMetadata(r, rawURL, result)
		if !result.Allowed {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":   "target URL is not allowed",
				"allowed": result.Allowed,
				"reason":  result.Reason,
			})
			return
		}
		diagnostics.MethodAllowed = resources.MethodAllowed(result, r.Method)
		if !diagnostics.MethodAllowed {
			writeProxyError(w, http.StatusMethodNotAllowed, "method not allowed", "")
			return
		}

		body, contentLength, ok := prepareUpstreamBody(w, r, maxBodyBytes, diagnostics)
		if !ok {
			return
		}
		upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), body)
		if err != nil {
			writeProxyError(w, http.StatusBadGateway, "upstream fetch failed", "request creation failed")
			return
		}
		if contentLength >= 0 {
			upstreamReq.ContentLength = contentLength
		}
		copySafeRequestHeaders(upstreamReq, r, target, result.RequestHeaderRules)
		diagnostics.HeaderRulesApplied = len(resources.RequestHeaderRemovals(result.RequestHeaderRules))
		if methodMayCarryBody(r.Method) {
			diagnostics.ProxiedPostCount = 1
		}

		sessionClient := clientWithJar(client, session.Jar)
		upstreamCookiesSent := len(session.Jar.Cookies(target))
		resp, err := sessionClient.Do(upstreamReq)
		if err != nil {
			if reason := SafetyReason(err); reason != "" {
				diagnostics.Type = "proxy_target_blocked"
				diagnostics.Reason = reason
			}
			writeProxyError(w, http.StatusBadGateway, "upstream fetch failed", safeFetchReason(err))
			return
		}
		defer resp.Body.Close()
		upstreamCookiesReceived := len(resp.Cookies())
		if options.DebugHeaders {
			w.Header().Set("X-Odo-Proxy-Session", "true")
			w.Header().Set("X-Odo-Proxy-Session-Created", boolString(session.Created))
			w.Header().Set("X-Odo-Upstream-Cookies-Sent", strconv.Itoa(upstreamCookiesSent))
			w.Header().Set("X-Odo-Upstream-Cookies-Stored", strconv.Itoa(upstreamCookiesReceived))
			if recoveredFromReferer(r) {
				w.Header().Set("X-Odo-Recovered-From-Referer", "true")
				if action := recoveryAction(r); action != "" {
					w.Header().Set("X-Odo-Recovery-Action", RecoveryActionHeader(action))
				}
				if target != nil {
					w.Header().Set("X-Odo-Target-Host", strings.ToLower(strings.TrimSuffix(target.Hostname(), ".")))
				}
			}
		}

		if metadata := accesslog.MetadataFrom(r.Context()); metadata != nil {
			metadata.UpstreamStatus = resp.StatusCode
		}
		diagnostics.UpstreamStatus = resp.StatusCode

		if isRedirect(resp.StatusCode) {
			handleRedirect(w, r, target, resp, check)
			return
		}

		copySafeResponseHeaders(w.Header(), resp.Header)
		applyContentTypeFallback(w.Header(), target)
		if r.Method != http.MethodHead && isTransformable(resp.Header.Get("Content-Type")) {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				writeProxyError(w, http.StatusBadGateway, "upstream fetch failed", "response read failed")
				return
			}
			transformed := transformBody(r.Context(), string(body), resp.Header.Get("Content-Type"), target, check, result)
			w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
			w.WriteHeader(resp.StatusCode)
			_, _ = io.WriteString(w, transformed)
			return
		}
		w.WriteHeader(resp.StatusCode)
		if r.Method != http.MethodHead {
			_, _ = io.Copy(w, resp.Body)
		}
	}
}

func WithRecoveredFromReferer(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), recoveredContextKey, true))
}

func WithRecoveryAction(r *http.Request, action string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), recoveryActionContextKey, action))
}

func recoveredFromReferer(r *http.Request) bool {
	value, _ := r.Context().Value(recoveredContextKey).(bool)
	return value
}

func recoveryAction(r *http.Request) string {
	value, _ := r.Context().Value(recoveryActionContextKey).(string)
	return value
}

func RecoveryActionHeader(action string) string {
	return strings.ReplaceAll(action, "_", "-")
}

func ProxyMaxBodyBytes() int64 {
	raw := strings.TrimSpace(os.Getenv("APP_PROXY_MAX_BODY_BYTES"))
	if raw == "" {
		return DefaultProxyMaxBodyBytes
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return DefaultProxyMaxBodyBytes
	}
	return value
}

func clientWithJar(base *http.Client, jar http.CookieJar) *http.Client {
	clone := *base
	clone.Jar = jar
	return &clone
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func globallySupportedProxyMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodOptions, http.MethodDelete:
		return true
	default:
		return false
	}
}

func methodMayCarryBody(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return true
	default:
		return false
	}
}

func writeProxyError(w http.ResponseWriter, status int, errText, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body := map[string]string{"error": errText}
	if reason != "" {
		body["reason"] = reason
	}
	_ = json.NewEncoder(w).Encode(body)
}

func prepareUpstreamBody(w http.ResponseWriter, r *http.Request, maxBodyBytes int64, diagnostics *Diagnostics) (io.Reader, int64, bool) {
	if !methodMayCarryBody(r.Method) {
		return nil, -1, true
	}
	if r.ContentLength > maxBodyBytes {
		diagnostics.RequestBodyLimited = true
		writeProxyError(w, http.StatusRequestEntityTooLarge, "request body too large", "")
		return nil, -1, false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		writeProxyError(w, http.StatusBadRequest, "request body read failed", "")
		return nil, -1, false
	}
	if int64(len(body)) > maxBodyBytes {
		diagnostics.RequestBodyLimited = true
		writeProxyError(w, http.StatusRequestEntityTooLarge, "request body too large", "")
		return nil, -1, false
	}
	return bytes.NewReader(body), int64(len(body)), true
}

func copySafeRequestHeaders(dst *http.Request, src *http.Request, target *url.URL, rules []resources.RequestHeaderRule) {
	for _, name := range []string{"Accept", "Accept-Language", "User-Agent"} {
		if values := src.Header.Values(name); len(values) > 0 {
			for _, value := range values {
				dst.Header.Add(name, value)
			}
		}
	}
	if methodMayCarryBody(src.Method) {
		if contentType := src.Header.Get("Content-Type"); contentType != "" {
			dst.Header.Set("Content-Type", contentType)
		}
		if target != nil && target.Scheme == "https" {
			dst.Header.Set("Referer", target.String())
			dst.Header.Set("Origin", target.Scheme+"://"+target.Host)
		}
	}
	for _, name := range resources.RequestHeaderRemovals(rules) {
		dst.Header.Del(name)
	}
}

func copySafeResponseHeaders(dst, src http.Header) {
	// MVP compatibility choice: transformed/proxied pages often fail if upstream
	// CSP/SRI policies refer to the vendor origin. Do not forward CSP headers
	// until Odo has fuller rewriting and policy handling.
	for _, name := range []string{"Content-Type", "Cache-Control", "Last-Modified", "ETag", "Expires"} {
		if values := src.Values(name); len(values) > 0 {
			for _, value := range values {
				dst.Add(name, value)
			}
		}
	}
}

func applyContentTypeFallback(headers http.Header, target *url.URL) {
	if headers.Get("Content-Type") != "" || target == nil {
		return
	}
	path := strings.ToLower(target.EscapedPath())
	switch {
	case strings.HasSuffix(path, ".js") || strings.HasSuffix(path, ".mjs"):
		headers.Set("Content-Type", "application/javascript; charset=utf-8")
	case strings.HasSuffix(path, ".json") || strings.Contains(path, "/manifest"):
		headers.Set("Content-Type", "application/json; charset=utf-8")
	case strings.HasSuffix(path, ".css"):
		headers.Set("Content-Type", "text/css; charset=utf-8")
	}
}

func isTransformable(contentType string) bool {
	contentType = strings.ToLower(contentType)
	for _, allowed := range []string{"text/html", "text/css", "application/javascript", "text/javascript", "application/json", "application/xml", "text/xml"} {
		if strings.Contains(contentType, allowed) {
			return true
		}
	}
	return false
}

func transformBody(ctx context.Context, body, contentType string, base *url.URL, check TargetCheck, result resources.TestResult) string {
	contentType = strings.ToLower(contentType)
	if strings.Contains(contentType, "text/css") {
		body = RewriteCSS(ctx, body, base, check)
		return ApplyContentRewriteRules(ctx, body, contentType, base, result)
	}
	if strings.Contains(contentType, "text/html") {
		transformed := RewriteHTML(ctx, body, base, check)
		if InjectJSShimEnabled() {
			targetOrigin := base.Scheme + "://" + base.Host
			var injected bool
			transformed, injected = InjectJSShim(transformed, targetOrigin, base.String())
			if diagnostics := DiagnosticsFrom(ctx); diagnostics != nil {
				diagnostics.JSShimInjected = injected
				diagnostics.JSFetchShimEnabled = injected
				diagnostics.JSXHRShimEnabled = injected
			}
		}
		return ApplyContentRewriteRules(ctx, transformed, contentType, base, result)
	}
	return ApplyContentRewriteRules(ctx, body, contentType, base, result)
}

func isRedirect(status int) bool {
	return status == http.StatusMovedPermanently ||
		status == http.StatusFound ||
		status == http.StatusSeeOther ||
		status == http.StatusTemporaryRedirect ||
		status == http.StatusPermanentRedirect
}

func handleRedirect(w http.ResponseWriter, r *http.Request, target *url.URL, resp *http.Response, check TargetCheck) {
	location := strings.TrimSpace(resp.Header.Get("Location"))
	if location == "" {
		writeProxyError(w, http.StatusBadGateway, "upstream fetch failed", "redirect missing location")
		return
	}
	parsed, err := url.Parse(location)
	if err != nil {
		writeProxyError(w, http.StatusBadGateway, "upstream fetch failed", "redirect location is invalid")
		return
	}
	resolved := target.ResolveReference(parsed)
	nextTarget, result := check(r.Context(), resolved.String())
	if !result.Allowed || nextTarget == nil {
		if diagnostics := DiagnosticsFrom(r.Context()); diagnostics != nil {
			diagnostics.Type = "proxy_target_blocked"
			diagnostics.Reason = "redirect_to_blocked_target"
		}
		writeProxyError(w, http.StatusBadGateway, "upstream fetch failed", "redirect target is not allowed")
		return
	}
	if diagnostics := DiagnosticsFrom(r.Context()); diagnostics != nil {
		diagnostics.RewrittenRedirectCount++
		if r.Method == http.MethodPost {
			diagnostics.RedirectedAfterPost = true
		}
	}
	w.Header().Set("Location", BuildProxyURL(nextTarget))
	w.WriteHeader(resp.StatusCode)
}

func safeFetchReason(err error) string {
	if err == nil {
		return ""
	}
	if strings.Contains(strings.ToLower(err.Error()), "timeout") {
		return "timeout"
	}
	return "request failed"
}

func setAccessLogMetadata(r *http.Request, rawURL string, result resources.TestResult) {
	metadata := accesslog.MetadataFrom(r.Context())
	if metadata == nil {
		return
	}
	if parsed, err := url.Parse(strings.TrimSpace(rawURL)); err == nil {
		metadata.TargetHost = strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	}
	metadata.ResourceID = result.ResourceID
	if result.Allowed {
		metadata.Decision = "allowed"
	} else {
		metadata.Decision = "denied"
		metadata.DenialReason = result.Reason
	}
	if result.Matched != nil {
		metadata.RuleHost = result.Matched.Host
		metadata.RuleMatch = result.Matched.Match
	}
}
