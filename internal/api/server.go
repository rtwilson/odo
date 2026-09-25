package api

import (
	"log/slog"
	"net"
	"net/http"
	"time"

	"example.org/odo/internal/accesslog"
	"example.org/odo/internal/db"
	"example.org/odo/internal/proxy"
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
	startedAt  time.Time
	bootSecret string

	loginThrottle *loginThrottle
}

func NewServer(store *db.Store, configDir, adminKey string, logger *slog.Logger) *Server {
	accessLogger, _ := accesslog.New(accesslog.FormatPrivacy, nil)
	return NewServerWithAccessLogger(store, configDir, adminKey, logger, accessLogger)
}

func NewServerWithAccessLogger(store *db.Store, configDir, adminKey string, logger *slog.Logger, accessLogger *accesslog.Logger) *Server {
	return NewServerWithAccessLoggerAndResolver(store, configDir, adminKey, logger, accessLogger, net.DefaultResolver.LookupIPAddr)
}

func NewServerWithAccessLoggerAndResolver(store *db.Store, configDir, adminKey string, logger *slog.Logger, accessLogger *accesslog.Logger, lookup proxy.IPLookupFunc) *Server {
	return NewServerWithAccessLoggerResolverAndHTTPClient(store, configDir, adminKey, logger, accessLogger, lookup, nil)
}

func NewServerWithAccessLoggerResolverAndHTTPClient(store *db.Store, configDir, adminKey string, logger *slog.Logger, accessLogger *accesslog.Logger, lookup proxy.IPLookupFunc, client *http.Client) *Server {
	return NewServerWithAccessLoggerResolverHTTPClientAndProxyDebug(store, configDir, adminKey, logger, accessLogger, lookup, client, false)
}

func NewServerWithAccessLoggerResolverHTTPClientAndProxyDebug(store *db.Store, configDir, adminKey string, logger *slog.Logger, accessLogger *accesslog.Logger, lookup proxy.IPLookupFunc, client *http.Client, proxyDebug bool) *Server {
	if lookup == nil {
		lookup = net.DefaultResolver.LookupIPAddr
	}
	if client == nil {
		client = proxy.DefaultHTTPClientWithResolver(lookup)
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
		startedAt:  time.Now().UTC(),
		bootSecret: randomBootSecret(),

		loginThrottle: newLoginThrottle(),
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.root)
	mux.HandleFunc("POST /", s.root)
	mux.HandleFunc("GET /admin", s.admin)
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.loginPost)
	mux.HandleFunc("GET /logout", s.logout)
	mux.HandleFunc("POST /logout", s.logoutPost)
	mux.HandleFunc("GET /resources", s.userResources)
	mux.HandleFunc("GET /openapi.yaml", s.openapi)
	mux.HandleFunc("GET /auth/saml/metadata", s.samlMetadata)
	mux.HandleFunc("GET /auth/saml/login", s.samlLogin)
	mux.HandleFunc("POST /auth/saml/acs", s.samlACS)
	mux.HandleFunc("GET /api/v1", s.apiIndex)
	mux.HandleFunc("GET /api/v1/health", s.health)
	mux.HandleFunc("GET /api/v1/session/me", s.sessionMe)
	mux.HandleFunc("GET /api/v1/system", s.requireScopes(s.systemInfo, "system:read"))
	mux.HandleFunc("GET /api/v1/system/runtime", s.requireScopes(s.systemRuntime, "system:read"))
	mux.HandleFunc("GET /api/v1/resources", s.requireScopes(s.listResources, "resources:read"))
	mux.HandleFunc("POST /api/v1/resources", s.requireScopes(s.upsertResource, "resources:write"))
	mux.HandleFunc("POST /api/v1/resources/validate", s.requireScopes(s.validateResource, "resources:write"))
	mux.HandleFunc("GET /api/v1/resources/{id}", s.requireScopes(s.getResource, "resources:read"))
	mux.HandleFunc("PUT /api/v1/resources/{id}", s.requireScopes(s.putResource, "resources:write"))
	mux.HandleFunc("DELETE /api/v1/resources/{id}", s.requireScopes(s.deleteResource, "resources:write"))
	mux.HandleFunc("POST /api/v1/config/validate", s.requireScopes(s.validateConfig, "config:write"))
	mux.HandleFunc("POST /api/v1/config/import", s.requireScopes(s.importConfig, "config:write"))
	mux.HandleFunc("GET /api/v1/config/revisions", s.requireScopes(s.listConfigRevisions, "config:read"))
	mux.HandleFunc("GET /api/v1/config/revisions/{id}", s.requireScopes(s.getConfigRevision, "config:read"))
	mux.HandleFunc("POST /api/v1/rules/test-url", s.requireScopes(s.testURL, "resources:read", "diagnostics:read"))
	mux.HandleFunc("POST /api/v1/proxy/test-fetch", s.requireScopes(s.proxyTestFetch, "diagnostics:read"))
	mux.HandleFunc("GET /api/v1/logs/access/recent", s.requireScopes(s.recentAccessLogs, "logs:read"))
	mux.HandleFunc("GET /api/v1/diagnostics/proxy/recent", s.requireScopes(s.recentProxyDiagnostics, "diagnostics:read"))
	mux.HandleFunc("GET /api/v1/diagnostics/missed-rewrites/recent", s.requireScopes(s.recentMissedRewrites, "diagnostics:read"))
	mux.HandleFunc("POST /api/v1/api-keys", s.requireScopes(s.createAPIKey, "api_keys:write"))
	mux.HandleFunc("GET /api/v1/api-keys", s.requireScopes(s.listAPIKeys, "api_keys:read", "api_keys:write"))
	mux.HandleFunc("GET /api/v1/api-keys/{id}", s.requireScopes(s.getAPIKey, "api_keys:read", "api_keys:write"))
	mux.HandleFunc("POST /api/v1/api-keys/{id}/rotate", s.requireScopes(s.rotateAPIKey, "api_keys:write"))
	mux.HandleFunc("POST /api/v1/api-keys/{id}/revoke", s.requireScopes(s.revokeAPIKey, "api_keys:write"))
	mux.HandleFunc("DELETE /api/v1/api-keys/{id}", s.requireScopes(s.deleteAPIKey, "api_keys:write"))
	mux.HandleFunc("GET /api/v1/auth/saml/providers", s.requireScopes(s.listSAMLProviders, "auth:read"))
	mux.HandleFunc("POST /api/v1/auth/saml/providers", s.requireScopes(s.upsertSAMLProvider, "auth:write"))
	mux.HandleFunc("GET /api/v1/auth/saml/providers/{id}", s.requireScopes(s.getSAMLProvider, "auth:read"))
	mux.HandleFunc("DELETE /api/v1/auth/saml/providers/{id}", s.requireScopes(s.deleteSAMLProvider, "auth:write"))
	mux.HandleFunc("GET /api/v1/users", s.requireScopes(s.listUsers, "users:read", "users:write"))
	mux.HandleFunc("POST /api/v1/users", s.requireScopes(s.createUser, "users:write"))
	mux.HandleFunc("GET /api/v1/users/{id}", s.requireScopes(s.getUser, "users:read", "users:write"))
	mux.HandleFunc("PATCH /api/v1/users/{id}", s.requireScopes(s.patchUser, "users:write"))
	mux.HandleFunc("POST /api/v1/users/{id}/set-password", s.requireScopes(s.setUserPassword, "users:write"))
	mux.HandleFunc("POST /api/v1/users/{id}/disable", s.requireScopes(s.disableUser, "users:write"))
	mux.HandleFunc("POST /api/v1/users/{id}/enable", s.requireScopes(s.enableUser, "users:write"))
	mux.HandleFunc("POST /api/v1/users/{id}/lock", s.requireScopes(s.lockUser, "users:write"))
	mux.HandleFunc("POST /api/v1/users/{id}/unlock", s.requireScopes(s.unlockUser, "users:write"))
	mux.HandleFunc("POST /api/v1/users/{id}/revoke-sessions", s.requireScopes(s.revokeUserSessions, "users:write"))
	proxyHandler := proxy.FetchHandlerWithOptions(proxy.FetchOptions{
		Client:       s.httpClient,
		Check:        s.proxyTarget,
		Sessions:     s.sessions,
		DebugHeaders: s.proxyDebug,
		Diagnostics:  s.proxyDiag,
	})
	s.proxyH = proxyHandler
	for _, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"} {
		mux.HandleFunc(method+" /odo", s.requireProxySession(proxyHandler))
		mux.HandleFunc(method+" /odo/", s.requireProxySession(proxyHandler))
	}
	mux.HandleFunc("GET /p", s.legacyProxyRedirect)
	mux.HandleFunc("HEAD /p", s.legacyProxyRedirect)
	return s.logging(s.requireAPIAuthentication(mux))
}
