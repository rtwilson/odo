package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"example.org/odo/internal/accesslog"
	"example.org/odo/internal/resources"
)

type TargetCheck func(ctx context.Context, rawURL string) (*url.URL, resources.TestResult)

func DefaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func FetchHandler(client *http.Client, check TargetCheck) http.HandlerFunc {
	if client == nil {
		client = DefaultHTTPClient()
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeProxyError(w, http.StatusMethodNotAllowed, "method not allowed", "")
			return
		}

		rawURL := r.URL.Query().Get("url")
		target, result := check(r.Context(), rawURL)
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

		upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), nil)
		if err != nil {
			writeProxyError(w, http.StatusBadGateway, "upstream fetch failed", "request creation failed")
			return
		}
		copySafeRequestHeaders(upstreamReq.Header, r.Header)

		resp, err := client.Do(upstreamReq)
		if err != nil {
			writeProxyError(w, http.StatusBadGateway, "upstream fetch failed", safeFetchReason(err))
			return
		}
		defer resp.Body.Close()

		if metadata := accesslog.MetadataFrom(r.Context()); metadata != nil {
			metadata.UpstreamStatus = resp.StatusCode
		}

		if isRedirect(resp.StatusCode) {
			handleRedirect(w, r, target, resp, check)
			return
		}

		copySafeResponseHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		if r.Method != http.MethodHead {
			_, _ = io.Copy(w, resp.Body)
		}
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

func copySafeRequestHeaders(dst, src http.Header) {
	for _, name := range []string{"Accept", "Accept-Language", "User-Agent"} {
		if values := src.Values(name); len(values) > 0 {
			for _, value := range values {
				dst.Add(name, value)
			}
		}
	}
}

func copySafeResponseHeaders(dst, src http.Header) {
	for _, name := range []string{"Content-Type", "Cache-Control", "Last-Modified", "ETag", "Expires"} {
		if values := src.Values(name); len(values) > 0 {
			for _, value := range values {
				dst.Add(name, value)
			}
		}
	}
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
		writeProxyError(w, http.StatusBadGateway, "upstream fetch failed", "redirect target is not allowed")
		return
	}
	w.Header().Set("Location", "/p?url="+url.QueryEscape(nextTarget.String()))
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
