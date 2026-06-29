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
	"runtime"
	"strconv"
	"strings"
	"time"

	"example.org/odo/internal/accesslog"
	"example.org/odo/internal/auth/local"
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
	startedAt  time.Time
	bootSecret string
}

var (
	Version = "dev"
	Commit  = "unknown"
)

type AuthContext struct {
	SubjectType     string   `json:"subject_type"`
	SubjectID       string   `json:"id,omitempty"`
	Name            string   `json:"name,omitempty"`
	DisplayName     string   `json:"display_name,omitempty"`
	Username        string   `json:"username,omitempty"`
	Scopes          []string `json:"scopes,omitempty"`
	Roles           []string `json:"roles,omitempty"`
	IsAuthenticated bool     `json:"authenticated"`
	IsAdminLike     bool     `json:"is_admin_like,omitempty"`
	csrfToken       string
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
		startedAt:  time.Now().UTC(),
		bootSecret: randomBootSecret(),
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.root)
	mux.HandleFunc("POST /", s.root)
	mux.HandleFunc("GET /admin", s.admin)
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.loginPost)
	mux.HandleFunc("POST /logout", s.logoutPost)
	mux.HandleFunc("GET /resources", s.userResources)
	mux.HandleFunc("GET /openapi.yaml", s.openapi)
	mux.HandleFunc("GET /auth/saml/metadata", s.samlMetadata)
	mux.HandleFunc("GET /auth/saml/login", s.samlLogin)
	mux.HandleFunc("POST /auth/saml/acs", s.samlACS)
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

func (s *Server) admin(w http.ResponseWriter, r *http.Request) {
	auth, status, message := s.authorizeRequest(r, "resources:read", "config:read", "diagnostics:read", "logs:read", "system:read", "api_keys:read", "api_keys:write", "users:read", "users:write", "auth:read", "auth:write")
	if status != 0 {
		if status == http.StatusUnauthorized {
			http.Redirect(w, r, "/login?next="+url.QueryEscape("/admin"), http.StatusFound)
			return
		}
		writeAdminForbidden(w, message)
		return
	}
	if !auth.IsAuthenticated {
		http.Redirect(w, r, "/login?next="+url.QueryEscape("/admin"), http.StatusFound)
		return
	}
	if !auth.IsAdminLike {
		_ = s.store.Audit("admin_ui_login_denied_insufficient_role", fmt.Sprintf(`{"subject_type":%q,"subject_id":%q}`, auth.SubjectType, auth.SubjectID))
		writeAdminForbidden(w, "admin access requires an admin or staff role")
		return
	}
	if auth.SubjectType == "user" {
		http.SetCookie(w, csrfCookie(auth.csrfToken))
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(ui.AdminHTML()))
}

func writeAdminForbidden(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8"><title>odo admin forbidden</title></head><body><main><h1>Admin access denied</h1><p>%s</p><p><a href="/resources">Go to resources</a></p></main></body></html>`, htmlEscape(message))
}

func (s *Server) openapi(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	_, _ = w.Write(openapi.Spec)
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	next, _ := safeNextPath(r.URL.Query().Get("next"))
	_, _ = fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8"><title>odo login</title><style>:root{color-scheme:dark;font-family:system-ui;background:#101316;color:#f2f4f7}main{max-width:420px;margin:12vh auto;padding:24px}input,button{width:100%%;box-sizing:border-box;margin:8px 0;padding:10px;border-radius:6px;border:1px solid #39414b;background:#181d22;color:#f2f4f7}button{background:#245c45}</style></head><body><main><h1>odo login</h1><p>Sign in to continue</p><form method="post" action="/login"><input type="hidden" name="next" value="%s"><input name="username" autocomplete="username" placeholder="Username"><input name="password" type="password" autocomplete="current-password" placeholder="Password"><button>Sign in</button></form></main></body></html>`, htmlEscape(next))
}

func (s *Server) loginPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid login request")
		return
	}
	user, found, err := s.store.GetUserByUsername(strings.TrimSpace(r.Form.Get("username")))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !found || user.Status != "active" || !local.CheckPassword(user.PasswordHash, r.Form.Get("password")) {
		_ = s.store.Audit("login_failed", fmt.Sprintf(`{"username":%q}`, strings.TrimSpace(r.Form.Get("username"))))
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	token, session, err := s.newBrowserSession(user.ID, r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session creation failed")
		return
	}
	if err := s.store.CreateSession(session); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.MarkUserLogin(user.ID)
	next := r.Form.Get("next")
	if next == "" {
		next = r.URL.Query().Get("next")
	}
	rawNext := next
	next, ok := safeNextPath(next)
	if !ok && strings.TrimSpace(rawNext) != "" {
		_ = s.store.Audit("login_next_rejected", `{"path":"/login"}`)
	}
	if next == "/admin" && !authContextForUser(user, csrfTokenForSessionToken(token)).IsAdminLike {
		_ = s.store.Audit("admin_ui_login_denied_insufficient_role", fmt.Sprintf(`{"subject_type":"user","subject_id":%q}`, user.ID))
		next = "/resources"
	} else if next == "/admin" {
		_ = s.store.Audit("admin_ui_login_success", fmt.Sprintf(`{"subject_type":"user","subject_id":%q}`, user.ID))
	}
	_ = s.store.Audit("login_success", fmt.Sprintf(`{"subject_type":"user","subject_id":%q,"next_path":%q}`, user.ID, pathOnly(next)))
	http.SetCookie(w, sessionCookie(r, token, session.ExpiresAt))
	http.SetCookie(w, csrfCookie(csrfTokenForSessionToken(token)))
	http.Redirect(w, r, next, http.StatusFound)
}

func (s *Server) logoutPost(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(browserSessionCookieName); err == nil {
		_ = s.store.RevokeSession(local.SessionIDFromToken(cookie.Value))
	}
	clear := &http.Cookie{Name: browserSessionCookieName, Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: sessionCookieSecure(r)}
	http.SetCookie(w, clear)
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *Server) userResources(w http.ResponseWriter, r *http.Request) {
	user, _, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		return
	}
	items, err := s.store.ListResources()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var b strings.Builder
	b.WriteString(`<!doctype html><html><head><meta charset="utf-8"><title>odo resources</title><style>:root{color-scheme:dark;font-family:system-ui;background:#101316;color:#f2f4f7}main{max-width:920px;margin:0 auto;padding:28px}a{color:#8cc7ff}li{margin:12px 0}button{padding:8px 10px}</style></head><body><main>`)
	b.WriteString("<h1>Resources</h1><p>Signed in as " + htmlEscape(displayUser(user)) + `</p><form method="post" action="/logout"><button>Logout</button></form><ul>`)
	for _, resource := range items {
		if resource.Status != "active" {
			continue
		}
		entry := ""
		if len(resource.EntryURLs) > 0 {
			entry = resource.EntryURLs[0]
		} else if len(resource.SampleURLs) > 0 {
			entry = resource.SampleURLs[0]
		}
		if entry == "" {
			continue
		}
		parsed, _ := url.Parse(entry)
		b.WriteString(`<li><a href="` + htmlEscape(proxy.BuildProxyURL(parsed)) + `">` + htmlEscape(resource.Title) + `</a></li>`)
	}
	b.WriteString("</ul></main></body></html>")
	_, _ = w.Write([]byte(b.String()))
}

func (s *Server) legacyProxyRedirect(w http.ResponseWriter, r *http.Request) {
	targetURL, _, _, err := proxy.ParseProxyRequest(r)
	if err != nil {
		http.Redirect(w, r, proxy.PublicProxyPath, http.StatusMovedPermanently)
		return
	}
	http.Redirect(w, r, proxy.BuildProxyURL(targetURL), http.StatusMovedPermanently)
}

const browserSessionCookieName = "odo_session"
const csrfCookieName = "odo_csrf"

func (s *Server) newBrowserSession(userID string, r *http.Request) (string, db.Session, error) {
	idPart, err := local.NewToken("", 16)
	if err != nil {
		return "", db.Session{}, err
	}
	secret, err := local.NewToken("", 32)
	if err != nil {
		return "", db.Session{}, err
	}
	id := "sess_" + idPart
	token := id + "." + secret
	now := time.Now().UTC()
	session := db.Session{
		ID:            id,
		UserID:        userID,
		SessionHash:   s.browserSessionHash(token),
		CreatedAt:     now.Format(time.RFC3339),
		LastSeenAt:    now.Format(time.RFC3339),
		ExpiresAt:     now.Add(sessionTTL()).Format(time.RFC3339),
		UserAgentHash: local.HashToken(r.UserAgent()),
		IPHash:        local.HashToken(remoteIPOnly(r.RemoteAddr)),
	}
	return token, session, nil
}

func (s *Server) browserSessionHash(token string) string {
	if sessionPersistOnRestart() {
		return local.HashToken(token)
	}
	return local.HashToken(s.bootSecret + ":" + token)
}

func randomBootSecret() string {
	token, err := local.NewToken("", 32)
	if err != nil {
		return time.Now().UTC().Format(time.RFC3339Nano)
	}
	return token
}

func sessionCookie(r *http.Request, token, expires string) *http.Cookie {
	expiresAt, _ := time.Parse(time.RFC3339, expires)
	return &http.Cookie{
		Name:     browserSessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   sessionCookieSecure(r),
		Expires:  expiresAt,
	}
}

func sessionCookieSecure(r *http.Request) bool {
	return r.TLS != nil || strings.HasPrefix(strings.ToLower(os.Getenv("APP_PUBLIC_URL")), "https://")
}

func csrfCookie(token string) *http.Cookie {
	return &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
	}
}

func csrfTokenForSessionToken(token string) string {
	return local.HashToken("csrf:" + token)
}

func sessionTTL() time.Duration {
	return minutesEnv("APP_SESSION_TTL_MINUTES", 480) * time.Minute
}

func sessionIdleTimeout() time.Duration {
	return minutesEnv("APP_SESSION_IDLE_TIMEOUT_MINUTES", 60) * time.Minute
}

func sessionTouchInterval() time.Duration {
	return time.Minute
}

func minutesEnv(name string, fallback int) time.Duration {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return time.Duration(fallback)
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return time.Duration(fallback)
	}
	return time.Duration(parsed)
}

func sessionPersistOnRestart() bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv("APP_SESSION_PERSIST_ON_RESTART")))
	if value != "" {
		return value == "true" || value == "1" || value == "yes" || value == "on"
	}
	return normalizedAppEnv() == "production"
}

func (s *Server) currentUser(r *http.Request) (db.User, db.Session, bool) {
	cookie, err := r.Cookie(browserSessionCookieName)
	if err != nil || cookie.Value == "" {
		return db.User{}, db.Session{}, false
	}
	sessionID := local.SessionIDFromToken(cookie.Value)
	session, found, err := s.store.GetSession(sessionID)
	if err != nil || !found {
		return db.User{}, db.Session{}, false
	}
	if session.RevokedAt != "" {
		_ = s.store.Audit("session_rejected_revoked", fmt.Sprintf(`{"session_id":%q}`, session.ID))
		return db.User{}, db.Session{}, false
	}
	if session.SessionHash != s.browserSessionHash(cookie.Value) {
		event := "session_rejected_restart_generation"
		if sessionPersistOnRestart() {
			event = "session_rejected_hash_mismatch"
		}
		_ = s.store.Audit(event, fmt.Sprintf(`{"session_id":%q}`, session.ID))
		return db.User{}, db.Session{}, false
	}
	now := time.Now().UTC()
	expiresAt, err := time.Parse(time.RFC3339, session.ExpiresAt)
	if err != nil || now.After(expiresAt) {
		_ = s.store.Audit("session_rejected_expired", fmt.Sprintf(`{"session_id":%q}`, session.ID))
		return db.User{}, db.Session{}, false
	}
	lastSeenAt, lastSeenErr := time.Parse(time.RFC3339, session.LastSeenAt)
	if lastSeenErr == nil && now.Sub(lastSeenAt) > sessionIdleTimeout() {
		_ = s.store.Audit("session_rejected_idle_timeout", fmt.Sprintf(`{"session_id":%q}`, session.ID))
		return db.User{}, db.Session{}, false
	}
	user, found, err := s.store.GetUser(session.UserID)
	if err != nil || !found || user.Status != "active" {
		_ = s.store.RevokeSession(session.ID)
		return db.User{}, db.Session{}, false
	}
	if lastSeenErr != nil || now.Sub(lastSeenAt) >= sessionTouchInterval() {
		_ = s.store.TouchSession(session.ID)
	}
	if metadata := accesslog.MetadataFrom(r.Context()); metadata != nil {
		metadata.UserID = user.ID
		metadata.SessionID = session.ID
	}
	return user, session, true
}

func (s *Server) currentUserAuth(r *http.Request) (AuthContext, bool) {
	cookie, err := r.Cookie(browserSessionCookieName)
	if err != nil || cookie.Value == "" {
		return AuthContext{}, false
	}
	user, _, ok := s.currentUser(r)
	if !ok {
		return AuthContext{}, false
	}
	return authContextForUser(user, csrfTokenForSessionToken(cookie.Value)), true
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
	if _, _, ok := s.currentUser(r); ok {
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
		return resources.TestResult{Allowed: false, Reason: "resource lookup failed"}
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

func safeNextPath(raw string) (string, bool) {
	if raw == "" {
		return "/resources", false
	}
	if strings.Contains(raw, "\\") || hasControlCharacter(raw) {
		return "/resources", false
	}
	if strings.Contains(raw, "://") {
		return "/resources", false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || !strings.HasPrefix(parsed.Path, "/") || strings.HasPrefix(parsed.Path, "//") {
		return "/resources", false
	}
	if parsed.Path != "/resources" && parsed.Path != "/admin" && parsed.Path != proxy.PublicProxyPath && !strings.HasPrefix(parsed.Path, proxy.PublicProxyPath+"/") {
		return "/resources", false
	}
	return parsed.RequestURI(), true
}

func pathOnly(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Path == "" {
		return "/resources"
	}
	return parsed.Path
}

func hasControlCharacter(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func htmlEscape(value string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&#34;", "'", "&#39;")
	return replacer.Replace(value)
}

func displayUser(user db.User) string {
	if user.DisplayName != "" {
		return user.DisplayName
	}
	return user.Username
}

func remoteIPOnly(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

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

func (s *Server) sessionMe(w http.ResponseWriter, r *http.Request) {
	auth, status, message := s.authorizeRequest(r)
	if status != 0 && status != http.StatusUnauthorized {
		writeError(w, status, message)
		return
	}
	if !auth.IsAuthenticated {
		writeJSON(w, http.StatusOK, map[string]bool{"authenticated": false})
		return
	}
	if auth.SubjectType == "user" {
		http.SetCookie(w, csrfCookie(auth.csrfToken))
	}
	writeJSON(w, http.StatusOK, auth)
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

type userCreateRequest struct {
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	DisplayName string   `json:"display_name"`
	Password    string   `json:"password"`
	Roles       []string `json:"roles"`
	Status      string   `json:"status"`
}

type userPatchRequest struct {
	Email       *string  `json:"email"`
	DisplayName *string  `json:"display_name"`
	Roles       []string `json:"roles"`
	Status      string   `json:"status"`
}

type userPasswordRequest struct {
	Password string `json:"password"`
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var req userCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(req.Roles) > 0 && !s.requestHasAdminScope(r) {
		writeError(w, http.StatusForbidden, "admin scope is required to set roles")
		return
	}
	user, err := s.newStoredUser(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.CreateUser(user); err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			status = http.StatusConflict
		}
		writeError(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, user)
}

func (s *Server) getUser(w http.ResponseWriter, r *http.Request) {
	user, found, err := s.store.GetUser(strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) patchUser(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	id := strings.TrimSpace(r.PathValue("id"))
	existing, found, err := s.store.GetUser(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	var req userPatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Email != nil {
		existing.Email = strings.TrimSpace(*req.Email)
	}
	if req.DisplayName != nil {
		existing.DisplayName = strings.TrimSpace(*req.DisplayName)
	}
	if len(req.Roles) > 0 {
		if !s.requestHasAdminScope(r) {
			writeError(w, http.StatusForbidden, "admin scope is required to change roles")
			return
		}
		roles, err := validateUserRoles(req.Roles)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if hasSuperAdminRole(existing.Roles) && !hasSuperAdminRole(roles) && s.activeSuperAdminCount() <= 1 {
			writeError(w, http.StatusBadRequest, "cannot remove the last admin account")
			return
		}
		existing.Roles = roles
	}
	if strings.TrimSpace(req.Status) != "" {
		status, err := validateUserStatus(req.Status)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		existing.Status = status
	}
	user, found, err := s.store.UpdateUser(existing)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	_ = s.store.Audit("user_updated", fmt.Sprintf(`{"id":%q,"username":%q}`, user.ID, user.Username))
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) setUserPassword(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var req userPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}
	hash, err := local.HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "password hashing failed")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	updated, err := s.store.SetUserPassword(id, hash)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !updated {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	_ = s.store.RevokeUserSessions(id)
	_ = s.store.Audit("user_password_set", fmt.Sprintf(`{"id":%q}`, id))
	writeJSON(w, http.StatusOK, map[string]any{"password_set": true, "id": id})
}

func (s *Server) disableUser(w http.ResponseWriter, r *http.Request) {
	s.setUserStatus(w, r, "disabled")
}

func (s *Server) enableUser(w http.ResponseWriter, r *http.Request) {
	s.setUserStatus(w, r, "active")
}

func (s *Server) lockUser(w http.ResponseWriter, r *http.Request) {
	s.setUserStatus(w, r, "locked")
}

func (s *Server) unlockUser(w http.ResponseWriter, r *http.Request) {
	s.setUserStatus(w, r, "active")
}

func (s *Server) revokeUserSessions(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if _, found, err := s.store.GetUser(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	} else if !found {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	if err := s.store.RevokeUserSessions(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.Audit("user_sessions_revoked", fmt.Sprintf(`{"id":%q}`, id))
	writeJSON(w, http.StatusOK, map[string]any{"sessions_revoked": true, "id": id})
}

func (s *Server) setUserStatus(w http.ResponseWriter, r *http.Request, status string) {
	id := strings.TrimSpace(r.PathValue("id"))
	if status == "disabled" || status == "locked" {
		existing, found, err := s.store.GetUser(id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		if hasSuperAdminRole(existing.Roles) && s.activeSuperAdminCount() <= 1 {
			writeError(w, http.StatusBadRequest, "cannot disable or lock the last admin account")
			return
		}
	}
	user, found, err := s.store.SetUserStatus(id, status)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	_ = s.store.Audit("user_status_set", fmt.Sprintf(`{"id":%q,"status":%q}`, user.ID, status))
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) requestHasAdminScope(r *http.Request) bool {
	auth, status, _ := s.authorizeRequest(r, "admin")
	return status == 0 && auth.IsAuthenticated
}

func (s *Server) activeSuperAdminCount() int {
	users, err := s.store.ListUsers()
	if err != nil {
		return 0
	}
	count := 0
	for _, user := range users {
		if user.Status == "active" && hasSuperAdminRole(user.Roles) {
			count++
		}
	}
	return count
}

func hasSuperAdminRole(roles []string) bool {
	for _, role := range roles {
		switch strings.ToLower(strings.TrimSpace(role)) {
		case "admin", "super_admin":
			return true
		}
	}
	return false
}

func (s *Server) newStoredUser(req userCreateRequest) (db.User, error) {
	username := strings.TrimSpace(req.Username)
	if username == "" {
		return db.User{}, fmt.Errorf("username is required")
	}
	if strings.ContainsAny(username, " \t\r\n") {
		return db.User{}, fmt.Errorf("username must not contain whitespace")
	}
	if len(req.Password) < 8 {
		return db.User{}, fmt.Errorf("password must be at least 8 characters")
	}
	status, err := validateUserStatus(req.Status)
	if err != nil {
		return db.User{}, err
	}
	roles, err := validateUserRoles(req.Roles)
	if err != nil {
		return db.User{}, err
	}
	hash, err := local.HashPassword(req.Password)
	if err != nil {
		return db.User{}, err
	}
	id, err := randomID("user_", 12)
	if err != nil {
		return db.User{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	return db.User{
		ID:           id,
		Username:     username,
		Email:        strings.TrimSpace(req.Email),
		DisplayName:  strings.TrimSpace(req.DisplayName),
		PasswordHash: hash,
		Status:       status,
		Roles:        roles,
		CreatedAt:    now,
		UpdatedAt:    now,
	}, nil
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
		auth, status, message := s.authorizeRequest(r, scopes...)
		if status != 0 {
			if status == http.StatusForbidden && auth.SubjectType == "user" && unsafeMethod(r.Method) && message == "csrf token is invalid or missing" {
				_ = s.store.Audit("csrf_failure", fmt.Sprintf(`{"subject_type":"user","subject_id":%q,"path":%q}`, auth.SubjectID, r.URL.Path))
			}
			writeError(w, status, message)
			return
		}
		if !auth.IsAuthenticated {
			next(w, r)
			return
		}
		if auth.SubjectType == "user" {
			_ = s.store.Audit("admin_api_call_by_user", fmt.Sprintf(`{"subject_id":%q,"path":%q,"method":%q}`, auth.SubjectID, r.URL.Path, r.Method))
		} else if auth.SubjectType == "api_key" {
			_ = s.store.Audit("admin_api_call_by_api_key", fmt.Sprintf(`{"subject_id":%q,"path":%q,"method":%q}`, auth.SubjectID, r.URL.Path, r.Method))
		}
		next(w, r)
	}
}

func (s *Server) authorizeRequest(r *http.Request, requiredScopes ...string) (AuthContext, int, string) {
	if token := bearerToken(r.Header.Get("Authorization")); token != "" {
		return s.authenticateBearerToken(token, requiredScopes...)
	}
	if auth, ok := s.currentUserAuth(r); ok {
		if !hasRequiredScope(auth.Scopes, requiredScopes) {
			return auth, http.StatusForbidden, "insufficient scope"
		}
		if unsafeMethod(r.Method) && r.Header.Get("X-Odo-CSRF") != auth.csrfToken {
			return auth, http.StatusForbidden, "csrf token is invalid or missing"
		}
		return auth, 0, ""
	}
	storedCount, err := s.store.CountAPIKeys()
	if err != nil {
		return anonymousAuthContext(), http.StatusInternalServerError, err.Error()
	}
	if storedCount == 0 && s.adminKey == "" {
		return anonymousAuthContext(), 0, ""
	}
	return anonymousAuthContext(), http.StatusUnauthorized, "missing bearer token"
}

func (s *Server) authenticateBearerToken(token string, requiredScopes ...string) (AuthContext, int, string) {
	if s.adminKey != "" && subtle.ConstantTimeCompare([]byte(token), []byte(s.adminKey)) == 1 {
		auth := AuthContext{
			SubjectType:     "api_key",
			SubjectID:       "bootstrap",
			Name:            "Bootstrap admin API key",
			Scopes:          []string{"admin"},
			IsAuthenticated: true,
			IsAdminLike:     true,
		}
		return auth, 0, ""
	}
	key, found, err := s.store.GetAPIKeyByHash(s.hashAPIToken(token))
	if err != nil {
		return anonymousAuthContext(), http.StatusInternalServerError, err.Error()
	}
	if !found {
		return anonymousAuthContext(), http.StatusForbidden, "invalid bearer token"
	}
	if key.Status != "active" || key.RevokedAt != "" {
		return anonymousAuthContext(), http.StatusForbidden, "invalid bearer token"
	}
	if key.ExpiresAt != "" {
		expiresAt, err := time.Parse(time.RFC3339, key.ExpiresAt)
		if err != nil || time.Now().UTC().After(expiresAt) {
			return anonymousAuthContext(), http.StatusForbidden, "invalid bearer token"
		}
	}
	auth := AuthContext{
		SubjectType:     "api_key",
		SubjectID:       key.ID,
		Name:            key.Name,
		Scopes:          key.Scopes,
		IsAuthenticated: true,
		IsAdminLike:     hasRequiredScope(key.Scopes, nil),
	}
	if !hasRequiredScope(auth.Scopes, requiredScopes) {
		return auth, http.StatusForbidden, "insufficient scope"
	}
	if err := s.store.MarkAPIKeyUsed(key.ID); err != nil {
		return auth, http.StatusInternalServerError, err.Error()
	}
	return auth, 0, ""
}

func anonymousAuthContext() AuthContext {
	return AuthContext{SubjectType: "anonymous", IsAuthenticated: false}
}

func unsafeMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
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
	if value := configuredPublicURL(); value != "" {
		return value
	}
	scheme := ""
	host := r.Host
	if trustProxyHeaders() {
		scheme = firstForwardedValue(r.Header.Get("X-Forwarded-Proto"))
		if forwardedHost := firstForwardedValue(r.Header.Get("X-Forwarded-Host")); forwardedHost != "" {
			host = forwardedHost
		}
	}
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	if host == "" {
		host = "127.0.0.1:8080"
	}
	return scheme + "://" + host
}

func configuredPublicURL() string {
	return strings.TrimRight(strings.TrimSpace(os.Getenv("APP_PUBLIC_URL")), "/")
}

func trustProxyHeaders() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("APP_TRUST_PROXY_HEADERS"))) {
	case "true", "1", "yes", "on":
		return true
	default:
		return false
	}
}

func firstForwardedValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if idx := strings.Index(value, ","); idx >= 0 {
		value = value[:idx]
	}
	return strings.TrimSpace(value)
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
	"api_keys:read":    true,
	"api_keys:write":   true,
	"resources:read":   true,
	"resources:write":  true,
	"config:read":      true,
	"config:write":     true,
	"diagnostics:read": true,
	"logs:read":        true,
	"auth:read":        true,
	"auth:write":       true,
	"system:read":      true,
	"users:read":       true,
	"users:write":      true,
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

var validUserRoles = map[string]bool{
	"admin":          true,
	"super_admin":    true,
	"systems_admin":  true,
	"resource_admin": true,
	"support_staff":  true,
	"security_admin": true,
	"viewer":         true,
	"user":           true,
	"staff":          true,
	"test":           true,
}

func validateUserRoles(roles []string) ([]string, error) {
	if len(roles) == 0 {
		return []string{"user"}, nil
	}
	seen := map[string]bool{}
	var out []string
	for _, role := range roles {
		role = strings.TrimSpace(strings.ToLower(role))
		if !validUserRoles[role] {
			return nil, fmt.Errorf("unknown role %q", role)
		}
		if !seen[role] {
			out = append(out, role)
			seen[role] = true
		}
	}
	return out, nil
}

func validateUserStatus(status string) (string, error) {
	status = strings.TrimSpace(strings.ToLower(status))
	if status == "" {
		return "active", nil
	}
	switch status {
	case "active", "disabled", "locked":
		return status, nil
	default:
		return "", fmt.Errorf("unknown user status %q", status)
	}
}

func authContextForUser(user db.User, csrfToken string) AuthContext {
	scopes := scopesForRoles(user.Roles)
	return AuthContext{
		SubjectType:     "user",
		SubjectID:       user.ID,
		DisplayName:     displayUser(user),
		Username:        user.Username,
		Roles:           user.Roles,
		Scopes:          scopes,
		IsAuthenticated: true,
		IsAdminLike:     hasRequiredScope(scopes, []string{"resources:read", "config:read", "diagnostics:read", "logs:read", "system:read", "api_keys:read", "api_keys:write", "users:read", "users:write", "auth:read", "auth:write"}),
		csrfToken:       csrfToken,
	}
}

func scopesForRoles(roles []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(scopes ...string) {
		for _, scope := range scopes {
			if !seen[scope] {
				out = append(out, scope)
				seen[scope] = true
			}
		}
	}
	for _, role := range roles {
		switch strings.ToLower(strings.TrimSpace(role)) {
		case "admin", "super_admin":
			add("admin")
		case "systems_admin":
			add("resources:read", "resources:write", "config:read", "config:write", "diagnostics:read", "logs:read", "system:read")
		case "resource_admin":
			add("resources:read", "resources:write", "config:read", "config:write", "diagnostics:read")
		case "support_staff":
			add("resources:read", "diagnostics:read", "logs:read")
		case "security_admin":
			add("users:read", "users:write", "logs:read", "diagnostics:read")
		case "viewer":
			add("resources:read", "config:read", "diagnostics:read", "system:read")
		}
	}
	return out
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
