package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"example.org/odo/internal/proxy"
	"example.org/odo/internal/resources"
)

func (s *Server) listResources(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListResources()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"resources": items})
}

func (s *Server) upsertResource(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var resource resources.Resource
	if err := json.NewDecoder(r.Body).Decode(&resource); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	resource, err := resources.Validate(resource)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.UpsertResource(resource); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resource)
}

func (s *Server) validateResource(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var resource resources.Resource
	if err := json.NewDecoder(r.Body).Decode(&resource); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	result := resources.ValidateDetailed(resource)
	status := http.StatusOK
	if !result.Valid {
		status = http.StatusBadRequest
	}
	writeJSON(w, status, result)
}

func (s *Server) getResource(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	resource, found, err := s.store.GetResource(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "resource not found")
		return
	}
	writeJSON(w, http.StatusOK, resource)
}

func (s *Server) putResource(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	id := strings.TrimSpace(r.PathValue("id"))
	var resource resources.Resource
	if err := json.NewDecoder(r.Body).Decode(&resource); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if strings.TrimSpace(resource.ID) != id {
		writeError(w, http.StatusBadRequest, "resource id does not match URL id")
		return
	}
	resource, err := resources.Validate(resource)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.UpsertResource(resource); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resource)
}

func (s *Server) deleteResource(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	deleted, err := s.store.DeleteResource(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !deleted {
		writeError(w, http.StatusNotFound, "resource not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"deleted": true,
		"id":      id,
	})
}

func (s *Server) testURL(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var req struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	writeJSON(w, http.StatusOK, s.testRawURL(req.URL))
}

func (s *Server) testRawURL(rawURL string) resources.TestResult {
	if _, err := proxy.NormalizeAndValidateTargetURL(rawURL); err != nil {
		return resources.TestResult{Allowed: false, Reason: err.Error()}
	}
	items, err := s.store.ListResources()
	if err != nil {
		return resources.TestResult{Allowed: false, Reason: "resource lookup failed"}
	}
	return resources.TestURL(rawURL, items)
}

func (s *Server) proxyTestFetch(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var req struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	target, result := s.proxyTestTarget(r.Context(), req.URL)
	if !result.Allowed {
		response := map[string]any{
			"allowed": false,
			"error":   "target URL is not allowed",
			"reason":  result.Reason,
		}
		if result.Host != "" {
			response["target_host"] = result.Host
		}
		writeJSON(w, http.StatusOK, response)
		return
	}

	upstreamReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target.String(), nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, "upstream fetch failed")
		return
	}
	client := noRedirectClient(s.httpClient)
	resp, err := client.Do(upstreamReq)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error":  "upstream fetch failed",
			"reason": proxySafeFetchReason(err),
		})
		return
	}
	defer resp.Body.Close()

	const previewLimit = 16 * 1024
	previewBytes, err := io.ReadAll(io.LimitReader(resp.Body, previewLimit+1))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error":  "upstream fetch failed",
			"reason": "response read failed",
		})
		return
	}
	truncated := len(previewBytes) > previewLimit
	if truncated {
		previewBytes = previewBytes[:previewLimit]
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"allowed":                true,
		"status":                 resp.StatusCode,
		"target_host":            result.Host,
		"resource_id":            result.ResourceID,
		"content_type":           resp.Header.Get("Content-Type"),
		"body_preview":           string(previewBytes),
		"body_preview_truncated": truncated,
		"headers":                safeHeaderSummary(resp.Header),
	})
}

func (s *Server) proxyTestTarget(ctx context.Context, rawURL string) (*url.URL, resources.TestResult) {
	target, err := proxy.ValidateTargetURL(ctx, rawURL, s.ipLookup)
	if err != nil {
		return nil, resources.TestResult{Allowed: false, Reason: err.Error()}
	}
	items, err := s.store.ListResources()
	if err != nil {
		return nil, resources.TestResult{Allowed: false, Host: target.Hostname(), Reason: "resource lookup failed"}
	}
	result := resources.TestURL(target.String(), items)
	if result.Host == "" {
		result.Host = target.Hostname()
	}
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

func noRedirectClient(base *http.Client) *http.Client {
	if base == nil {
		base = proxy.DefaultHTTPClient()
	}
	clone := *base
	clone.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &clone
}

func safeHeaderSummary(headers http.Header) map[string]string {
	allowed := []string{"Cache-Control", "Content-Type", "ETag", "Expires", "Last-Modified"}
	summary := map[string]string{}
	for _, name := range allowed {
		if value := headers.Get(name); value != "" {
			summary[strings.ToLower(name)] = value
		}
	}
	return summary
}

func proxySafeFetchReason(err error) string {
	if err == nil {
		return ""
	}
	if strings.Contains(strings.ToLower(err.Error()), "timeout") {
		return "timeout"
	}
	return "request failed"
}
