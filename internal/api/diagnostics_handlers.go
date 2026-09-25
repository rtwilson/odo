package api

import (
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"example.org/odo/internal/proxy"
)

var (
	Version = "dev"
	Commit  = "unknown"
)

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) systemInfo(w http.ResponseWriter, r *http.Request) {
	publicURL := configuredPublicURL()
	writeJSON(w, http.StatusOK, map[string]any{
		"version":                      Version,
		"commit":                       Commit,
		"app_env":                      normalizedAppEnv(),
		"public_url":                   publicURL,
		"public_url_set":               publicURL != "",
		"data_dir":                     configuredDataDir(),
		"config_dir":                   s.configDir,
		"proxy_require_login":          s.proxyLoginRequired(),
		"trust_proxy_headers":          trustProxyHeaders(),
		"proxy_url_mode":               proxy.ProxyURLMode(),
		"session_persist_on_restart":   sessionPersistOnRestart(),
		"session_ttl_minutes":          int(sessionTTL() / time.Minute),
		"session_idle_timeout_minutes": int(sessionIdleTimeout() / time.Minute),
		"javascript_shim_enabled":      proxy.InjectJSShimEnabled(),
		"referer_recovery_enabled":     proxy.RefererRecoveryEnabled(),
	})
}

func (s *Server) systemRuntime(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	openSessions, _ := s.store.CountOpenSessions(now)
	activeSessions, _ := s.store.CountActiveSessionsSince(now.Add(-15*time.Minute), now)
	items, err := s.store.ListResources()
	resourceCount := 0
	if err == nil {
		resourceCount = len(items)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"goroutines":                runtime.NumGoroutine(),
		"memory_alloc_bytes":        mem.Alloc,
		"memory_sys_bytes":          mem.Sys,
		"open_sessions":             openSessions,
		"active_sessions_recent":    activeSessions,
		"proxy_cookie_jar_sessions": s.sessions.Count(),
		"resource_count":            resourceCount,
		"uptime_seconds":            int64(now.Sub(s.startedAt).Seconds()),
	})
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

func normalizedAppEnv() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("APP_ENV"))) {
	case "production":
		return "production"
	case "", "development":
		return "development"
	default:
		return "development"
	}
}

func configuredDataDir() string {
	if value := strings.TrimSpace(os.Getenv("APP_DATA_DIR")); value != "" {
		return value
	}
	if dbPath := strings.TrimSpace(os.Getenv("APP_DB_PATH")); dbPath != "" {
		return filepathDir(dbPath)
	}
	if normalizedAppEnv() == "production" {
		return "/var/lib/odo"
	}
	return "./data"
}

func filepathDir(path string) string {
	path = strings.TrimRight(path, "/")
	if path == "" {
		return "."
	}
	idx := strings.LastIndex(path, "/")
	if idx < 0 {
		return "."
	}
	if idx == 0 {
		return "/"
	}
	return path[:idx]
}
