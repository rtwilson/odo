package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"example.org/odo/internal/accesslog"
	"example.org/odo/internal/config"
	"example.org/odo/internal/db"
	"example.org/odo/internal/proxy"
	"example.org/odo/internal/resources"
	"example.org/odo/internal/ui"
	"example.org/odo/openapi"
)

type Server struct {
	store      *db.Store
	configDir  string
	adminKey   string
	logger     *slog.Logger
	accessLog  *accesslog.Logger
	ipLookup   proxy.IPLookupFunc
	httpClient *http.Client
	sessions   *proxy.SessionStore
	proxyDebug bool
}

func NewServer(store *db.Store, configDir, adminKey string, logger *slog.Logger) *Server {
	accessLogger, _ := accesslog.New(accesslog.FormatPrivacy, nil)
	return NewServerWithAccessLogger(store, configDir, adminKey, logger, accessLogger)
}

func NewServerWithAccessLogger(store *db.Store, configDir, adminKey string, logger *slog.Logger, accessLogger *accesslog.Logger) *Server {
	return NewServerWithAccessLoggerAndResolver(store, configDir, adminKey, logger, accessLogger, net.DefaultResolver.LookupIPAddr)
}

func NewServerWithAccessLoggerAndResolver(store *db.Store, configDir, adminKey string, logger *slog.Logger, accessLogger *accesslog.Logger, lookup proxy.IPLookupFunc) *Server {
	return NewServerWithAccessLoggerResolverAndHTTPClient(store, configDir, adminKey, logger, accessLogger, lookup, proxy.DefaultHTTPClient())
}

func NewServerWithAccessLoggerResolverAndHTTPClient(store *db.Store, configDir, adminKey string, logger *slog.Logger, accessLogger *accesslog.Logger, lookup proxy.IPLookupFunc, client *http.Client) *Server {
	return NewServerWithAccessLoggerResolverHTTPClientAndProxyDebug(store, configDir, adminKey, logger, accessLogger, lookup, client, false)
}

func NewServerWithAccessLoggerResolverHTTPClientAndProxyDebug(store *db.Store, configDir, adminKey string, logger *slog.Logger, accessLogger *accesslog.Logger, lookup proxy.IPLookupFunc, client *http.Client, proxyDebug bool) *Server {
	if lookup == nil {
		lookup = net.DefaultResolver.LookupIPAddr
	}
	if client == nil {
		client = proxy.DefaultHTTPClient()
	}
	return &Server{
		store:      store,
		configDir:  configDir,
		adminKey:   adminKey,
		logger:     logger,
		accessLog:  accessLogger,
		ipLookup:   lookup,
		httpClient: client,
		sessions:   proxy.NewSessionStore(2 * time.Hour),
		proxyDebug: proxyDebug,
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.root)
	mux.HandleFunc("GET /admin", s.admin)
	mux.HandleFunc("GET /openapi.yaml", s.openapi)
	mux.HandleFunc("GET /api/v1/health", s.health)
	mux.HandleFunc("GET /api/v1/resources", s.listResources)
	mux.HandleFunc("POST /api/v1/resources", s.requireAdminAPIKey(s.upsertResource))
	mux.HandleFunc("GET /api/v1/resources/{id}", s.getResource)
	mux.HandleFunc("PUT /api/v1/resources/{id}", s.requireAdminAPIKey(s.putResource))
	mux.HandleFunc("DELETE /api/v1/resources/{id}", s.requireAdminAPIKey(s.deleteResource))
	mux.HandleFunc("POST /api/v1/config/validate", s.requireAdminAPIKey(s.validateConfig))
	mux.HandleFunc("POST /api/v1/config/import", s.requireAdminAPIKey(s.importConfig))
	mux.HandleFunc("GET /api/v1/config/revisions", s.requireAdminAPIKey(s.listConfigRevisions))
	mux.HandleFunc("GET /api/v1/config/revisions/{id}", s.requireAdminAPIKey(s.getConfigRevision))
	mux.HandleFunc("POST /api/v1/rules/test-url", s.testURL)
	mux.HandleFunc("POST /api/v1/proxy/test-fetch", s.requireAdminAPIKey(s.proxyTestFetch))
	mux.HandleFunc("GET /api/v1/logs/access/recent", s.requireAdminAPIKey(s.recentAccessLogs))
	mux.HandleFunc("GET /api/v1/diagnostics/proxy/recent", s.requireAdminAPIKey(s.recentProxyDiagnostics))
	proxyHandler := proxy.FetchHandlerWithOptions(proxy.FetchOptions{
		Client:       s.httpClient,
		Check:        s.proxyTarget,
		Sessions:     s.sessions,
		DebugHeaders: s.proxyDebug,
	})
	mux.HandleFunc("GET /p", proxyHandler)
	mux.HandleFunc("POST /p", proxyHandler)
	mux.HandleFunc("PUT /p", proxyHandler)
	mux.HandleFunc("PATCH /p", proxyHandler)
	mux.HandleFunc("DELETE /p", proxyHandler)
	return s.logging(mux)
}

func (s *Server) root(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/admin", http.StatusFound)
}

func (s *Server) admin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(ui.AdminHTML()))
}

func (s *Server) openapi(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	_, _ = w.Write(openapi.Spec)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

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

func (s *Server) importConfig(w http.ResponseWriter, r *http.Request) {
	results, err := config.ImportResources(s.store, s.configDir)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

func (s *Server) validateConfig(w http.ResponseWriter, r *http.Request) {
	result, err := config.ValidateResources(s.configDir)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) listConfigRevisions(w http.ResponseWriter, r *http.Request) {
	revisions, err := s.store.ListConfigRevisions(25)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revisions": revisions})
}

func (s *Server) getConfigRevision(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid revision id")
		return
	}
	revision, found, err := s.store.GetConfigRevision(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "revision not found")
		return
	}
	writeJSON(w, http.StatusOK, revision)
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

func (s *Server) recentAccessLogs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"entries": s.accessLog.Recent()})
}

func (s *Server) recentProxyDiagnostics(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"entries": []any{}})
}

func (s *Server) proxyRawURL(rawURL string) resources.TestResult {
	_, result := s.proxyTarget(context.Background(), rawURL)
	return result
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

func (s *Server) proxyTarget(ctx context.Context, rawURL string) (*url.URL, resources.TestResult) {
	target, err := proxy.ValidateTargetURL(ctx, rawURL, s.ipLookup)
	if err != nil {
		return nil, resources.TestResult{Allowed: false, Reason: err.Error()}
	}
	items, err := s.store.ListResources()
	if err != nil {
		return nil, resources.TestResult{Allowed: false, Reason: "resource lookup failed"}
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

func (s *Server) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, metadata := accesslog.WithMetadata(r.Context())
		metadata.RequestID = accesslog.RequestID(r)
		r = r.WithContext(ctx)

		start := time.Now()
		recorder := &responseRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		s.accessLog.Log(r, recorder.status, recorder.bytes, time.Since(start))
	})
}

type responseRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *responseRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *responseRecorder) Write(data []byte) (int, error) {
	n, err := r.ResponseWriter.Write(data)
	r.bytes += n
	return n, err
}

func (s *Server) requireAdminAPIKey(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.adminKey == "" {
			next(w, r)
			return
		}
		token := bearerToken(r.Header.Get("Authorization"))
		if token == "" {
			writeError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.adminKey)) != 1 {
			writeError(w, http.StatusForbidden, "invalid bearer token")
			return
		}
		next(w, r)
	}
}

func bearerToken(header string) string {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, prefix))
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
