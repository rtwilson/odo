package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"example.org/odo/internal/httperror"
	"example.org/odo/internal/proxy"
	"example.org/odo/internal/resources"
)

func (s *Server) listResources(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListResources()
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"resources": items})
}

func (s *Server) upsertResource(w http.ResponseWriter, r *http.Request) {
	var resource resources.Resource
	if !decodeResourceJSON(w, r, &resource) {
		return
	}
	resource, err := resources.Validate(resource)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.UpsertResource(resource); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, resource)
}

func (s *Server) validateResource(w http.ResponseWriter, r *http.Request) {
	var resource resources.Resource
	if !decodeResourceJSON(w, r, &resource) {
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
		s.internalError(w, r, err)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "resource not found")
		return
	}
	writeJSON(w, http.StatusOK, resource)
}

func (s *Server) putResource(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	var resource resources.Resource
	if !decodeResourceJSON(w, r, &resource) {
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
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, resource)
}

func (s *Server) deleteResource(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	deleted, err := s.store.DeleteResource(id)
	if err != nil {
		s.internalError(w, r, err)
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
	result := s.testRawURL(req.URL)
	if result.InternalError != nil {
		s.internalError(w, r, result.InternalError)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) testRawURL(rawURL string) resources.TestResult {
	if _, err := proxy.NormalizeAndValidateTargetURL(rawURL); err != nil {
		return resources.TestResult{Allowed: false, Reason: err.Error()}
	}
	items, err := s.store.ListResources()
	if err != nil {
		return resources.TestResult{Allowed: false, Reason: "resource lookup failed", InternalError: err}
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
	if result.InternalError != nil {
		s.internalError(w, r, result.InternalError)
		return
	}
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
		httperror.Write(w, r, s.logger, http.StatusBadGateway, fmt.Errorf("create upstream request: %w", err))
		return
	}
	client := noRedirectClient(s.httpClient)
	resp, err := client.Do(upstreamReq)
	if err != nil {
		httperror.Write(w, r, s.logger, http.StatusBadGateway, fmt.Errorf("fetch upstream: %w", err))
		return
	}
	defer resp.Body.Close()

	const previewLimit = 16 * 1024
	previewBytes, err := io.ReadAll(io.LimitReader(resp.Body, previewLimit+1))
	if err != nil {
		httperror.Write(w, r, s.logger, http.StatusBadGateway, fmt.Errorf("read upstream response: %w", err))
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
		return nil, resources.TestResult{Allowed: false, Host: target.Hostname(), Reason: "resource lookup failed", InternalError: err}
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

const maxResourceJSONBytes = 1 << 20

// Read the entire bounded body so trailing data cannot bypass the size limit
// or be silently ignored by decoding only the first JSON value.
func decodeResourceJSON(w http.ResponseWriter, r *http.Request, resource *resources.Resource) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxResourceJSONBytes)
	defer r.Body.Close()
	data, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "resource JSON must be at most 1 MiB")
		} else {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
		}
		return false
	}
	if err := json.Unmarshal(data, resource); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}
