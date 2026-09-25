package api

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"example.org/odo/internal/accesslog"
	"example.org/odo/internal/auth/local"
	"example.org/odo/internal/cookiepolicy"
	"example.org/odo/internal/db"
	"example.org/odo/internal/proxy"
)

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
	// Source attribution intentionally uses the connection peer: there is no
	// existing trusted client-IP extraction policy for forwarded headers.
	attempt, reason, audit := s.loginThrottle.begin(r.Form.Get("username"), loginSourceKey(r.RemoteAddr), time.Now())
	if attempt == nil {
		if audit {
			_ = s.store.Audit("login_throttled", fmt.Sprintf(`{"path":"/login","reason":%q}`, reason))
		}
		writeError(w, http.StatusTooManyRequests, "invalid username or password")
		return
	}
	failed, success := false, false
	defer func() {
		if s.loginThrottle.finish(attempt, failed, success, time.Now()) {
			_ = s.store.Audit("login_failures_excessive", `{"path":"/login"}`)
		}
	}()
	user, found, err := s.store.GetUserByUsername(strings.TrimSpace(r.Form.Get("username")))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !found || user.Status != "active" || !local.CheckPassword(user.PasswordHash, r.Form.Get("password")) {
		failed = true
		_ = s.store.Audit("login_failed", `{"path":"/login"}`)
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	token, session, err := s.newBrowserSession(user.ID, r)
	if err != nil {
		s.internalError(w, r, fmt.Errorf("session creation failed: %w", err))
		return
	}
	if err := s.store.CreateSession(session); err != nil {
		s.internalError(w, r, err)
		return
	}
	success = true
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
	http.SetCookie(w, csrfCookie(r, csrfTokenForSessionToken(token)))
	http.Redirect(w, r, next, http.StatusFound)
}

func (s *Server) logoutPost(w http.ResponseWriter, r *http.Request) {
	s.logout(w, r)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(browserSessionCookieName); err == nil {
		_ = s.store.RevokeSession(local.SessionIDFromToken(cookie.Value))
	}
	http.SetCookie(w, clearSessionCookie(r, browserSessionCookieName, true))
	http.SetCookie(w, clearSessionCookie(r, csrfCookieName, false))
	http.Redirect(w, r, "/login", http.StatusFound)
}

func clearSessionCookie(r *http.Request, name string, httpOnly bool) *http.Cookie {
	return cookiepolicy.Apply(r, &http.Cookie{Name: name, MaxAge: -1, HttpOnly: httpOnly})
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
	return cookiepolicy.Apply(r, &http.Cookie{
		Name:     browserSessionCookieName,
		Value:    token,
		HttpOnly: true,
		Expires:  expiresAt,
	})
}

func csrfCookie(r *http.Request, token string) *http.Cookie {
	return cookiepolicy.Apply(r, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		HttpOnly: false,
		MaxAge:   int(sessionTTL() / time.Second),
		Expires:  time.Now().UTC().Add(sessionTTL()),
	})
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

func (s *Server) currentUser(r *http.Request) (db.User, db.Session, bool, error) {
	cookie, err := r.Cookie(browserSessionCookieName)
	if err != nil || cookie.Value == "" {
		return db.User{}, db.Session{}, false, nil
	}
	sessionID := local.SessionIDFromToken(cookie.Value)
	session, found, err := s.store.GetSession(sessionID)
	if err != nil {
		return db.User{}, db.Session{}, false, fmt.Errorf("load browser session: %w", err)
	}
	if !found {
		return db.User{}, db.Session{}, false, nil
	}
	if session.RevokedAt != "" {
		_ = s.store.Audit("session_rejected_revoked", fmt.Sprintf(`{"session_id":%q}`, session.ID))
		return db.User{}, db.Session{}, false, nil
	}
	if session.SessionHash != s.browserSessionHash(cookie.Value) {
		event := "session_rejected_restart_generation"
		if sessionPersistOnRestart() {
			event = "session_rejected_hash_mismatch"
		}
		_ = s.store.Audit(event, fmt.Sprintf(`{"session_id":%q}`, session.ID))
		return db.User{}, db.Session{}, false, nil
	}
	now := time.Now().UTC()
	expiresAt, err := time.Parse(time.RFC3339, session.ExpiresAt)
	if err != nil || now.After(expiresAt) {
		_ = s.store.Audit("session_rejected_expired", fmt.Sprintf(`{"session_id":%q}`, session.ID))
		return db.User{}, db.Session{}, false, nil
	}
	lastSeenAt, lastSeenErr := time.Parse(time.RFC3339, session.LastSeenAt)
	if lastSeenErr == nil && now.Sub(lastSeenAt) > sessionIdleTimeout() {
		_ = s.store.Audit("session_rejected_idle_timeout", fmt.Sprintf(`{"session_id":%q}`, session.ID))
		return db.User{}, db.Session{}, false, nil
	}
	user, found, err := s.store.GetUser(session.UserID)
	if err != nil {
		return db.User{}, db.Session{}, false, fmt.Errorf("load session user: %w", err)
	}
	if !found || user.Status != "active" {
		_ = s.store.RevokeSession(session.ID)
		return db.User{}, db.Session{}, false, nil
	}
	if lastSeenErr != nil || now.Sub(lastSeenAt) >= sessionTouchInterval() {
		if err := s.store.TouchSession(session.ID); err != nil {
			return db.User{}, db.Session{}, false, fmt.Errorf("touch browser session: %w", err)
		}
	}
	if metadata := accesslog.MetadataFrom(r.Context()); metadata != nil {
		metadata.UserID = user.ID
		metadata.SessionID = session.ID
	}
	return user, session, true, nil
}

func (s *Server) currentUserAuth(r *http.Request) (AuthContext, bool, error) {
	cookie, err := r.Cookie(browserSessionCookieName)
	if err != nil || cookie.Value == "" {
		return AuthContext{}, false, nil
	}
	user, _, ok, err := s.currentUser(r)
	if err != nil {
		return AuthContext{}, false, err
	}
	if !ok {
		return AuthContext{}, false, nil
	}
	return authContextForUser(user, csrfTokenForSessionToken(cookie.Value)), true, nil
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

func (s *Server) sessionMe(w http.ResponseWriter, r *http.Request) {
	auth, status, message, err := s.authorizeRequest(r)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if status != 0 && status != http.StatusUnauthorized {
		writeError(w, status, message)
		return
	}
	if !auth.IsAuthenticated {
		writeJSON(w, http.StatusOK, map[string]bool{"authenticated": false})
		return
	}
	if auth.SubjectType == "user" {
		http.SetCookie(w, csrfCookie(r, auth.csrfToken))
	}
	writeJSON(w, http.StatusOK, auth)
}

func randomID(prefix string, n int) (string, error) {
	random := make([]byte, n)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(random), nil
}
