package api

import (
	"bytes"
	"database/sql"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"example.org/odo/internal/accesslog"
	"example.org/odo/internal/auth/local"
	"example.org/odo/internal/db"
)

// A second connection to the temporary database injects failures without adding
// datastore hooks to production code. Revocation can fail while reads still work.
func newLogoutTestServer(t *testing.T, guarded bool) (*Server, *sql.DB, *http.Cookie, *bytes.Buffer) {
	t.Helper()
	flag := "false"
	if guarded {
		flag = "true"
	}
	t.Setenv("APP_HOST_GUARD", flag)
	t.Setenv("APP_PUBLIC_URL", "https://odo.example")
	t.Setenv("APP_PROXY_BASE_DOMAIN", "proxy.example")
	t.Setenv("APP_SESSION_IDLE_TIMEOUT_MINUTES", "60")
	t.Setenv("APP_SESSION_PERSIST_ON_RESTART", "false")
	path := filepath.Join(t.TempDir(), "logout.db")
	store, err := db.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(); err != nil {
		t.Fatal(err)
	}
	control, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	logs := new(bytes.Buffer)
	server := NewServer(store, t.TempDir(), "secret", slog.New(slog.NewJSONHandler(logs, nil)))
	server.accessLog, _ = accesslog.New(accesslog.FormatPrivacy, logs)
	user := createLocalTestUser(t, server, "alice", "correct horse battery")
	req := httptest.NewRequest("POST", "/login", nil)
	token, session, err := server.newBrowserSession(user.ID, req)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateSession(session); err != nil {
		t.Fatal(err)
	}
	return server, control, server.sessionCookie(req, token, session.ExpiresAt), logs
}

func requestLogout(server *Server, cookie *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/logout?search=private-search", strings.NewReader("password=private-password"))
	req.Host = "odo.example"
	req.Header.Set("Origin", "https://odo.example")
	req.Header.Set("X-Request-ID", "logout-support-123")
	req.Header.Set("Authorization", "Bearer private-authorization")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	return rec
}

func assertLogoutCleared(t *testing.T, rec *httptest.ResponseRecorder, prefix string) {
	t.Helper()
	if rec.Code != 302 || rec.Header().Get("Location") != "/login" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("logout response: %d %s", rec.Code, rec.Body.String())
	}
	for _, name := range []string{prefix + "odo_session", prefix + "odo_csrf"} {
		cookie := findCookie(rec.Result().Cookies(), name)
		if cookie == nil || cookie.MaxAge >= 0 || !cookie.Secure || cookie.Path != "/" || cookie.Domain != "" ||
			cookie.SameSite != http.SameSiteLaxMode || cookie.HttpOnly != strings.HasSuffix(name, "odo_session") {
			t.Fatalf("wrong clearing attributes for %q: %+v", name, cookie)
		}
	}
}

func TestLogoutRevokesValidatedSessionWithoutTouch(t *testing.T) {
	for _, guarded := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "guarded"}[guarded], func(t *testing.T) {
			server, control, cookie, _ := newLogoutTestServer(t, guarded)
			id := local.SessionIDFromToken(cookie.Value)
			lastSeen := time.Now().UTC().Add(-30 * time.Minute).Format(time.RFC3339)
			if _, err := control.Exec(`UPDATE sessions SET last_seen_at = ? WHERE id = ?`, lastSeen, id); err != nil {
				t.Fatal(err)
			}
			if _, err := control.Exec(`CREATE TRIGGER prevent_logout_touch BEFORE UPDATE OF last_seen_at ON sessions BEGIN SELECT RAISE(ABORT, 'unexpected session touch'); END`); err != nil {
				t.Fatal(err)
			}
			prefix := ""
			if guarded {
				prefix = "__Host-"
			}
			assertLogoutCleared(t, requestLogout(server, cookie), prefix)
			session, found, err := server.store.GetSession(id)
			if err != nil || !found || session.RevokedAt == "" || session.LastSeenAt != lastSeen {
				t.Fatalf("revocation/touch state: %+v found=%v err=%v", session, found, err)
			}
			req := httptest.NewRequest("GET", "/resources", nil)
			req.Host = "odo.example"
			req.AddCookie(cookie)
			rec := httptest.NewRecorder()
			server.Routes().ServeHTTP(rec, req)
			if rec.Code != 302 || !strings.HasPrefix(rec.Header().Get("Location"), "/login?") {
				t.Fatalf("revoked session authenticated: %d", rec.Code)
			}
			events, err := server.store.ListAuditEvents(20)
			if err != nil {
				t.Fatal(err)
			}
			foundSuccess := false
			for _, event := range events {
				if event.Event == "logout_success" && strings.Contains(event.Detail, `"outcome":"revoked"`) && strings.Contains(event.Detail, "logout-support-123") {
					foundSuccess = true
				}
				if strings.Contains(event.Detail, cookie.Value) {
					t.Fatal("audit leaked session token")
				}
			}
			if !foundSuccess {
				t.Fatal("missing successful revocation audit")
			}
		})
	}
}

func TestLogoutInvalidAndInactiveSessionsAreIdempotent(t *testing.T) {
	for _, state := range []string{"missing", "empty", "malformed", "unknown", "forged secret", "restart generation", "revoked", "expired", "idle expired", "invalid expiry"} {
		t.Run(state, func(t *testing.T) {
			server, control, cookie, _ := newLogoutTestServer(t, false)
			id := local.SessionIDFromToken(cookie.Value)
			supplied := *cookie
			switch state {
			case "missing":
				cookie = nil
			case "empty":
				supplied.Value = ""
			case "malformed":
				supplied.Value = "not-a-session"
			case "unknown":
				supplied.Value = "sess_unknown.secret"
			case "forged secret":
				supplied.Value = id + ".wrong-secret"
			case "restart generation":
				server.bootSecret = "new-generation"
			case "revoked":
				if err := server.store.RevokeSession(id); err != nil {
					t.Fatal(err)
				}
			case "expired", "invalid expiry":
				expires := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
				if state == "invalid expiry" {
					expires = "invalid"
				}
				if _, err := control.Exec(`UPDATE sessions SET expires_at = ? WHERE id = ?`, expires, id); err != nil {
					t.Fatal(err)
				}
			case "idle expired":
				if _, err := control.Exec(`UPDATE sessions SET last_seen_at = ? WHERE id = ?`, time.Now().UTC().Add(-2*time.Hour).Format(time.RFC3339), id); err != nil {
					t.Fatal(err)
				}
			}
			before, _, err := server.store.GetSession(id)
			if err != nil {
				t.Fatal(err)
			}
			if cookie != nil {
				cookie = &supplied
			}
			for range 2 {
				assertLogoutCleared(t, requestLogout(server, cookie), "")
			}
			after, _, err := server.store.GetSession(id)
			if err != nil || after != before {
				t.Fatalf("invalid token changed a session: err=%v", err)
			}
			events, err := server.store.ListAuditEvents(20)
			if err != nil {
				t.Fatal(err)
			}
			for _, event := range events {
				if event.Event == "logout_success" && !strings.Contains(event.Detail, `"outcome":"no_active_session"`) {
					t.Fatalf("invalid session reported a revocation: %s", event.Detail)
				}
			}
		})
	}
}

func TestLogoutMissingOrMalformedCookieNeedsNoSessionLookup(t *testing.T) {
	server, control, _, _ := newLogoutTestServer(t, false)
	if _, err := control.Exec(`DROP TABLE sessions`); err != nil {
		t.Fatal(err)
	}
	for _, cookie := range []*http.Cookie{nil, {Name: "odo_session", Value: "malformed"}} {
		assertLogoutCleared(t, requestLogout(server, cookie), "")
	}
}

func TestLogoutDatabaseFailuresDoNotReportSuccess(t *testing.T) {
	for _, failure := range []string{"lookup", "revocation"} {
		t.Run(failure, func(t *testing.T) {
			server, control, cookie, logs := newLogoutTestServer(t, false)
			if failure == "lookup" {
				if _, err := control.Exec(`DROP TABLE sessions`); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := control.Exec(`CREATE TRIGGER fail_revocation BEFORE UPDATE OF revoked_at ON sessions BEGIN SELECT RAISE(ABORT, 'private-revocation-db-detail'); END`); err != nil {
					t.Fatal(err)
				}
			}
			rec := requestLogout(server, cookie)
			id := assertInternalResponse(t, rec, 500, false, cookie.Value, "private-revocation-db-detail", "no such table", "private-search")
			if rec.Header().Get("Location") != "" || len(rec.Result().Cookies()) != 0 {
				t.Fatal("failed revocation reported a successful logout")
			}
			if id != "logout-support-123" || !strings.Contains(logs.String(), id) || !strings.Contains(logs.String(), "logout session") {
				t.Fatalf("missing correlated internal error: %s", logs.String())
			}
			for _, secret := range []string{cookie.Value, "private-password", "private-authorization", "private-search"} {
				if strings.Contains(logs.String(), secret) {
					t.Fatalf("logout log leaked %q", secret)
				}
			}
			events, err := server.store.ListAuditEvents(20)
			if err != nil {
				t.Fatal(err)
			}
			foundFailure := false
			for _, event := range events {
				if event.Event == "logout_success" {
					t.Fatal("failed logout recorded success")
				}
				if event.Event == "logout_failed" && strings.Contains(event.Detail, failure+"_failed") {
					foundFailure = true
				}
				if strings.Contains(event.Detail, cookie.Value) {
					t.Fatal("audit leaked session token")
				}
			}
			if !foundFailure {
				t.Fatal("missing logout failure audit")
			}
			if failure == "revocation" {
				session, found, err := server.store.GetSession(local.SessionIDFromToken(cookie.Value))
				if err != nil || !found || session.RevokedAt != "" {
					t.Fatalf("failed revocation falsely persisted: %+v found=%v err=%v", session, found, err)
				}
				req := httptest.NewRequest("GET", "/resources", nil)
				req.AddCookie(cookie)
				result := httptest.NewRecorder()
				server.Routes().ServeHTTP(result, req)
				if result.Code != 200 {
					t.Fatal("failure test did not leave the session valid")
				}
			}
		})
	}
}

func TestLogoutAuditFailureDoesNotUndoRevocation(t *testing.T) {
	server, control, cookie, logs := newLogoutTestServer(t, false)
	if _, err := control.Exec(`CREATE TRIGGER fail_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'audit-write-failed'); END`); err != nil {
		t.Fatal(err)
	}
	assertLogoutCleared(t, requestLogout(server, cookie), "")
	session, found, err := server.store.GetSession(local.SessionIDFromToken(cookie.Value))
	if err != nil || !found || session.RevokedAt == "" {
		t.Fatal("audit failure undid revocation")
	}
	if !strings.Contains(logs.String(), "logout audit write failed") || !strings.Contains(logs.String(), "logout-support-123") {
		t.Fatalf("audit persistence failure not reported: %s", logs.String())
	}
	events, err := server.store.ListAuditEvents(20)
	if err != nil {
		t.Fatal(err)
	}
	if auditEventsContain(events, "logout_success") {
		t.Fatal("claimed an audit record that did not persist")
	}
}

func TestLogoutGuardedCookieCannotBeReplacedByLegacyCookie(t *testing.T) {
	server, _, cookie, _ := newLogoutTestServer(t, true)
	if cookie.Name != "__Host-odo_session" {
		t.Fatalf("wrong guarded cookie: %q", cookie.Name)
	}
	foreign := httptest.NewRequest("POST", "https://vendor.proxy.example/logout", nil)
	foreign.Header.Set("Origin", "https://odo.example")
	foreign.AddCookie(cookie)
	denied := httptest.NewRecorder()
	server.Routes().ServeHTTP(denied, foreign)
	if denied.Code != 421 || len(denied.Result().Cookies()) != 0 {
		t.Fatal("vendor Host reached central logout")
	}
	legacy := &http.Cookie{Name: "odo_session", Value: cookie.Value}
	assertLogoutCleared(t, requestLogout(server, legacy), "__Host-")
	session, _, err := server.store.GetSession(local.SessionIDFromToken(cookie.Value))
	if err != nil || session.RevokedAt != "" {
		t.Fatal("legacy cookie revoked guarded session")
	}
	assertLogoutCleared(t, requestLogout(server, cookie), "__Host-")
}

func TestLogoutLookupFailureStillReturnsErrorWhenAuditAlsoFails(t *testing.T) {
	server, control, cookie, logs := newLogoutTestServer(t, false)
	if err := server.store.Close(); err != nil {
		t.Fatal(err)
	}
	rec := requestLogout(server, cookie)
	assertInternalResponse(t, rec, 500, false, cookie.Value, "database is closed")
	if rec.Header().Get("Location") != "" || len(rec.Result().Cookies()) != 0 {
		t.Fatal("database outage reported successful logout")
	}
	if !strings.Contains(logs.String(), "logout audit write failed") || !strings.Contains(logs.String(), "load logout session") || !strings.Contains(logs.String(), "logout-support-123") {
		t.Fatalf("missing audit/lookup failure diagnostics: %s", logs.String())
	}
	var revoked string
	if err := control.QueryRow(`SELECT coalesce(revoked_at, '') FROM sessions WHERE id = ?`, local.SessionIDFromToken(cookie.Value)).Scan(&revoked); err != nil || revoked != "" {
		t.Fatalf("outage changed persisted session state: revoked=%q err=%v", revoked, err)
	}
}
