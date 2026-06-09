package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"example.org/odo/internal/accesslog"
	"example.org/odo/internal/auth/saml"
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
	proxyDiag  *proxy.DiagnosticsStore
	missedDiag *proxy.MissedRewriteStore
	proxyH     http.Handler
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
		proxyDiag:  proxy.NewDiagnosticsStore(200),
		missedDiag: proxy.NewMissedRewriteStore(200),
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.root)
	mux.HandleFunc("POST /", s.root)
	mux.HandleFunc("GET /admin", s.admin)
	mux.HandleFunc("GET /openapi.yaml", s.openapi)
	mux.HandleFunc("GET /auth/saml/metadata", s.samlMetadata)
	mux.HandleFunc("GET /auth/saml/login", s.samlLogin)
	mux.HandleFunc("POST /auth/saml/acs", s.samlACS)
	mux.HandleFunc("GET /api/v1/health", s.health)
	mux.HandleFunc("GET /api/v1/resources", s.listResources)
	mux.HandleFunc("POST /api/v1/resources", s.requireScopes(s.upsertResource, "resources:write"))
	mux.HandleFunc("GET /api/v1/resources/{id}", s.getResource)
	mux.HandleFunc("PUT /api/v1/resources/{id}", s.requireScopes(s.putResource, "resources:write"))
	mux.HandleFunc("DELETE /api/v1/resources/{id}", s.requireScopes(s.deleteResource, "resources:write"))
	mux.HandleFunc("POST /api/v1/config/validate", s.requireScopes(s.validateConfig, "config:write"))
	mux.HandleFunc("POST /api/v1/config/import", s.requireScopes(s.importConfig, "config:write"))
	mux.HandleFunc("GET /api/v1/config/revisions", s.requireScopes(s.listConfigRevisions, "config:read"))
	mux.HandleFunc("GET /api/v1/config/revisions/{id}", s.requireScopes(s.getConfigRevision, "config:read"))
	mux.HandleFunc("POST /api/v1/rules/test-url", s.testURL)
	mux.HandleFunc("POST /api/v1/proxy/test-fetch", s.requireScopes(s.proxyTestFetch, "diagnostics:read"))
	mux.HandleFunc("GET /api/v1/logs/access/recent", s.requireScopes(s.recentAccessLogs, "logs:read"))
	mux.HandleFunc("GET /api/v1/diagnostics/proxy/recent", s.requireScopes(s.recentProxyDiagnostics, "diagnostics:read"))
	mux.HandleFunc("GET /api/v1/diagnostics/missed-rewrites/recent", s.requireScopes(s.recentMissedRewrites, "diagnostics:read"))
	mux.HandleFunc("POST /api/v1/api-keys", s.requireScopes(s.createAPIKey, "auth:write"))
	mux.HandleFunc("GET /api/v1/api-keys", s.requireScopes(s.listAPIKeys, "auth:write"))
	mux.HandleFunc("GET /api/v1/api-keys/{id}", s.requireScopes(s.getAPIKey, "auth:write"))
	mux.HandleFunc("POST /api/v1/api-keys/{id}/rotate", s.requireScopes(s.rotateAPIKey, "auth:write"))
	mux.HandleFunc("POST /api/v1/api-keys/{id}/revoke", s.requireScopes(s.revokeAPIKey, "auth:write"))
	mux.HandleFunc("DELETE /api/v1/api-keys/{id}", s.requireScopes(s.deleteAPIKey, "auth:write"))
	mux.HandleFunc("GET /api/v1/auth/saml/providers", s.requireScopes(s.listSAMLProviders, "auth:read"))
	mux.HandleFunc("POST /api/v1/auth/saml/providers", s.requireScopes(s.upsertSAMLProvider, "auth:write"))
	mux.HandleFunc("GET /api/v1/auth/saml/providers/{id}", s.requireScopes(s.getSAMLProvider, "auth:read"))
	mux.HandleFunc("DELETE /api/v1/auth/saml/providers/{id}", s.requireScopes(s.deleteSAMLProvider, "auth:write"))
	proxyHandler := proxy.FetchHandlerWithOptions(proxy.FetchOptions{
		Client:       s.httpClient,
		Check:        s.proxyTarget,
		Sessions:     s.sessions,
		DebugHeaders: s.proxyDebug,
		Diagnostics:  s.proxyDiag,
	})
	s.proxyH = proxyHandler
	for _, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"} {
		mux.HandleFunc(method+" /odo", proxyHandler)
		mux.HandleFunc(method+" /odo/", proxyHandler)
	}
	mux.HandleFunc("GET /p", s.legacyProxyRedirect)
	mux.HandleFunc("HEAD /p", s.legacyProxyRedirect)
	return s.logging(mux)
}

func (s *Server) root(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		s.handleUnknownPath(w, r)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusFound)
}

func (s *Server) handleUnknownPath(w http.ResponseWriter, r *http.Request) {
	event := proxy.MissedRewriteEvent{
		Method:              r.Method,
		Path:                r.URL.Path,
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
		event.Recovered = true
		event.RecoveryAction = proxy.RecoveryActionRedirectedToCanonical
		event.Reason = "redirected to canonical proxy URL"
		s.missedDiag.Add(event)
		if s.proxyDebug {
			w.Header().Set("X-Odo-Recovered-From-Referer", "true")
			w.Header().Set("X-Odo-Recovery-Action", proxy.RecoveryActionHeader(event.RecoveryAction))
			w.Header().Set("X-Odo-Target-Host", event.RecoveredTargetHost)
		}
		http.Redirect(w, r, proxy.BuildProxyURL(validatedTarget), http.StatusFound)
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

	recorder := &recoveryRecorder{ResponseWriter: w}
	s.proxyH.ServeHTTP(recorder, recoveredReq)
	event.UpstreamStatus = recorder.status
	event.ContentType = recorder.Header().Get("Content-Type")
	if recorder.status >= http.StatusOK && recorder.status < http.StatusBadRequest {
		event.Recovered = true
		event.RecoveryAction = proxy.RecoveryActionSilentlyProxied
		event.Reason = "recovered from proxied referer"
	} else {
		event.RecoveryAction = proxy.RecoveryActionDenied
		event.Reason = "recovery target denied"
	}
	s.missedDiag.Add(event)
}

func (s *Server) admin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(ui.AdminHTML()))
}

func (s *Server) openapi(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	_, _ = w.Write(openapi.Spec)
}

func (s *Server) legacyProxyRedirect(w http.ResponseWriter, r *http.Request) {
	targetURL, err := proxy.ParseProxyRequest(r)
	if err != nil {
		http.Redirect(w, r, proxy.PublicProxyPath, http.StatusMovedPermanently)
		return
	}
	http.Redirect(w, r, proxy.BuildProxyURL(targetURL), http.StatusMovedPermanently)
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

type apiKeyCreateRequest struct {
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes"`
	ExpiresAt string   `json:"expires_at"`
}

type apiKeyResponse struct {
	db.APIKey
	Token string `json:"token,omitempty"`
}

func (s *Server) createAPIKey(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var req apiKeyCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	key, token, err := s.newStoredAPIKey(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.CreateAPIKey(key); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, apiKeyResponse{APIKey: key, Token: token})
}

func (s *Server) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.store.ListAPIKeys()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"api_keys": keys})
}

func (s *Server) getAPIKey(w http.ResponseWriter, r *http.Request) {
	key, found, err := s.store.GetAPIKey(strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "api key not found")
		return
	}
	writeJSON(w, http.StatusOK, key)
}

func (s *Server) rotateAPIKey(w http.ResponseWriter, r *http.Request) {
	token, err := generateAPIToken("odo_live_")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token generation failed")
		return
	}
	key, found, err := s.store.RotateAPIKey(strings.TrimSpace(r.PathValue("id")), s.hashAPIToken(token), keyPrefix(token))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "api key not found")
		return
	}
	writeJSON(w, http.StatusOK, apiKeyResponse{APIKey: key, Token: token})
}

func (s *Server) revokeAPIKey(w http.ResponseWriter, r *http.Request) {
	key, found, err := s.store.RevokeAPIKey(strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "api key not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": true, "api_key": key})
}

func (s *Server) deleteAPIKey(w http.ResponseWriter, r *http.Request) {
	key, found, err := s.store.DeleteAPIKey(strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "api key not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "api_key": key})
}

func (s *Server) listSAMLProviders(w http.ResponseWriter, r *http.Request) {
	providers, err := s.store.ListSAMLProviders()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"providers": providers})
}

func (s *Server) upsertSAMLProvider(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var provider saml.Provider
	if err := json.NewDecoder(r.Body).Decode(&provider); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	provider, err := saml.Validate(provider, publicBaseURL(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.UpsertSAMLProvider(provider); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, provider)
}

func (s *Server) getSAMLProvider(w http.ResponseWriter, r *http.Request) {
	provider, found, err := s.store.GetSAMLProvider(strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "saml provider not found")
		return
	}
	writeJSON(w, http.StatusOK, provider)
}

func (s *Server) deleteSAMLProvider(w http.ResponseWriter, r *http.Request) {
	deleted, err := s.store.DeleteSAMLProvider(strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !deleted {
		writeError(w, http.StatusNotFound, "saml provider not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "id": strings.TrimSpace(r.PathValue("id"))})
}

func (s *Server) samlMetadata(w http.ResponseWriter, r *http.Request) {
	provider, found, err := s.store.ActiveSAMLProvider()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "no active SAML provider configured")
		return
	}
	provider, err = saml.Validate(provider, publicBaseURL(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.store.Audit("saml_metadata_served", fmt.Sprintf(`{"provider_id":%q}`, provider.ID)); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml; charset=utf-8")
	_, _ = w.Write([]byte(spMetadataXML(provider)))
}

func (s *Server) samlLogin(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error": "SAML login initiation is not implemented yet",
	})
}

func (s *Server) samlACS(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error": "SAML assertion validation is not implemented yet",
	})
}

func (s *Server) newStoredAPIKey(req apiKeyCreateRequest) (db.APIKey, string, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return db.APIKey{}, "", fmt.Errorf("api key name is required")
	}
	scopes, err := validateAPIKeyScopes(req.Scopes)
	if err != nil {
		return db.APIKey{}, "", err
	}
	if req.ExpiresAt != "" {
		if _, err := time.Parse(time.RFC3339, req.ExpiresAt); err != nil {
			return db.APIKey{}, "", fmt.Errorf("expires_at must be RFC3339")
		}
	}
	token, err := generateAPIToken("odo_live_")
	if err != nil {
		return db.APIKey{}, "", err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	id, err := randomID("key_", 12)
	if err != nil {
		return db.APIKey{}, "", err
	}
	return db.APIKey{
		ID:        id,
		Name:      name,
		KeyHash:   s.hashAPIToken(token),
		KeyPrefix: keyPrefix(token),
		Scopes:    scopes,
		Status:    "active",
		ExpiresAt: strings.TrimSpace(req.ExpiresAt),
		CreatedAt: now,
		UpdatedAt: now,
	}, token, nil
}

func (s *Server) recentAccessLogs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"entries": s.accessLog.Recent()})
}

func (s *Server) recentProxyDiagnostics(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"entries": s.proxyDiag.Recent()})
}

func (s *Server) recentMissedRewrites(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"events": s.missedDiag.Recent()})
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
	return s.requireScopes(next)
}

func (s *Server) requireScopes(next http.HandlerFunc, scopes ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth, status, message := s.authenticateBearer(r, scopes...)
		if status != 0 {
			writeError(w, status, message)
			return
		}
		if !auth {
			next(w, r)
			return
		}
		next(w, r)
	}
}

func (s *Server) authenticateBearer(r *http.Request, requiredScopes ...string) (bool, int, string) {
	storedCount, err := s.store.CountAPIKeys()
	if err != nil {
		return false, http.StatusInternalServerError, err.Error()
	}
	if storedCount == 0 && s.adminKey == "" {
		return false, 0, ""
	}
	token := bearerToken(r.Header.Get("Authorization"))
	if token == "" {
		return false, http.StatusUnauthorized, "missing bearer token"
	}
	if s.adminKey != "" && subtle.ConstantTimeCompare([]byte(token), []byte(s.adminKey)) == 1 {
		return true, 0, ""
	}
	key, found, err := s.store.GetAPIKeyByHash(s.hashAPIToken(token))
	if err != nil {
		return false, http.StatusInternalServerError, err.Error()
	}
	if !found {
		return false, http.StatusForbidden, "invalid bearer token"
	}
	if key.Status != "active" || key.RevokedAt != "" {
		return false, http.StatusForbidden, "invalid bearer token"
	}
	if key.ExpiresAt != "" {
		expiresAt, err := time.Parse(time.RFC3339, key.ExpiresAt)
		if err != nil || time.Now().UTC().After(expiresAt) {
			return false, http.StatusForbidden, "invalid bearer token"
		}
	}
	if !hasRequiredScope(key.Scopes, requiredScopes) {
		return false, http.StatusForbidden, "insufficient scope"
	}
	if err := s.store.MarkAPIKeyUsed(key.ID); err != nil {
		return false, http.StatusInternalServerError, err.Error()
	}
	return true, 0, ""
}

func bearerToken(header string) string {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, prefix))
}

func (s *Server) hashAPIToken(token string) string {
	secret := os.Getenv("APP_KEY_HASH_SECRET")
	if secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write([]byte(token))
		return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil))
	}
	sum := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func generateAPIToken(prefix string) (string, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(random), nil
}

func randomID(prefix string, n int) (string, error) {
	random := make([]byte, n)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(random), nil
}

func keyPrefix(token string) string {
	if len(token) <= len("odo_live_")+8 {
		return token
	}
	return token[:len("odo_live_")+8]
}

func publicBaseURL(r *http.Request) string {
	if value := strings.TrimRight(strings.TrimSpace(os.Getenv("APP_PUBLIC_URL")), "/"); value != "" {
		return value
	}
	scheme := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	host := r.Host
	if host == "" {
		host = "127.0.0.1:8080"
	}
	return scheme + "://" + host
}

func spMetadataXML(provider saml.Provider) string {
	return `<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
		`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + xmlEscape(provider.EntityID) + `">` + "\n" +
		`  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="` + boolXML(provider.SignAuthnRequests) + `" WantAssertionsSigned="` + boolXML(provider.RequireSignedAssertions) + `">` + "\n" +
		`    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>` + "\n" +
		`    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="` + xmlEscape(provider.ACSURL) + `" index="1" isDefault="true"/>` + "\n" +
		`  </md:SPSSODescriptor>` + "\n" +
		`</md:EntityDescriptor>` + "\n"
}

func xmlEscape(value string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(value))
	return buf.String()
}

func boolXML(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

var validAPIKeyScopes = map[string]bool{
	"admin":            true,
	"resources:read":   true,
	"resources:write":  true,
	"config:read":      true,
	"config:write":     true,
	"diagnostics:read": true,
	"logs:read":        true,
	"auth:read":        true,
	"auth:write":       true,
}

func validateAPIKeyScopes(scopes []string) ([]string, error) {
	if len(scopes) == 0 {
		return []string{"admin"}, nil
	}
	seen := map[string]bool{}
	var out []string
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if !validAPIKeyScopes[scope] {
			return nil, fmt.Errorf("unknown scope %q", scope)
		}
		if !seen[scope] {
			out = append(out, scope)
			seen[scope] = true
		}
	}
	return out, nil
}

func hasRequiredScope(granted, required []string) bool {
	for _, scope := range granted {
		if scope == "admin" {
			return true
		}
	}
	if len(required) == 0 {
		return true
	}
	grantedSet := map[string]bool{}
	for _, scope := range granted {
		grantedSet[scope] = true
	}
	for _, scope := range required {
		if grantedSet[scope] {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
