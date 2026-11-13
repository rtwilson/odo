package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"example.org/odo/internal/auth/local"
)

func TestSetUserPasswordAPIRevokesSessions(t *testing.T) {
	server := newTestServer(t, "secret")
	createLocalTestUserWithRoles(t, server, "admin", "original admin password", []string{"super_admin"})
	user := createLocalTestUser(t, server, "patron", "original patron password")
	adminCookie, csrf := loginTestUserWithCSRF(t, server, "admin", "original admin password", "/admin")
	first := loginTestUser(t, server, "patron", "original patron password", "/resources")
	second := loginTestUser(t, server, "patron", "original patron password", "/resources")
	rec := userLifecycleRequest(server, "POST", "/api/v1/users/"+user.ID+"/set-password", `{"password":"replacement patron password"}`, "", adminCookie, csrf)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"password_set":true`) {
		t.Fatalf("password reset: %d %s", rec.Code, rec.Body.String())
	}
	stored, found, err := server.store.GetUser(user.ID)
	if err != nil || !found || !local.CheckPassword(stored.PasswordHash, "replacement patron password") || local.CheckPassword(stored.PasswordHash, "original patron password") {
		t.Fatal("password replacement not persisted")
	}
	if strings.Contains(rec.Body.String(), stored.PasswordHash) || strings.Contains(rec.Body.String(), "replacement patron password") {
		t.Fatal("response exposed password or hash")
	}
	for _, cookie := range []*http.Cookie{first, second} {
		session, found, err := server.store.GetSession(local.SessionIDFromToken(cookie.Value))
		if err != nil || !found || session.RevokedAt == "" {
			t.Fatal("old session not revoked")
		}
		if response := userLifecycleRequest(server, "GET", "/api/v1/session/me", "", "", cookie, ""); response.Code != 401 {
			t.Fatalf("old session authenticated: %d", response.Code)
		}
	}
	if response := userLifecycleRequest(server, "GET", "/api/v1/session/me", "", "", adminCookie, ""); response.Code != 200 {
		t.Fatal("another account's session was invalidated")
	}
	form := url.Values{"username": {"patron"}, "password": {"original patron password"}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(loginRec, req)
	if loginRec.Code != 401 {
		t.Fatalf("old password authenticated: %d", loginRec.Code)
	}
	loginTestUser(t, server, "patron", "replacement patron password", "/resources")
	events, err := server.store.ListAuditEvents(50)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, event := range events {
		if event.Event == "user_password_set" {
			count++
			if event.Detail != `{"id":"`+user.ID+`"}` {
				t.Fatalf("unexpected password audit metadata: %s", event.Detail)
			}
		}
	}
	if count != 1 {
		t.Fatalf("password audit count: %d", count)
	}
}

func TestSetUserPasswordAPIRollsBackDatabaseFailures(t *testing.T) {
	for _, failure := range []string{"password", "revocation"} {
		t.Run(failure, func(t *testing.T) {
			server, control, cookie, logs := newLogoutTestServer(t, false)
			session, _, err := server.store.GetSession(local.SessionIDFromToken(cookie.Value))
			if err != nil {
				t.Fatal(err)
			}
			before, _, err := server.store.GetUser(session.UserID)
			if err != nil {
				t.Fatal(err)
			}
			trigger := `CREATE TRIGGER fail_password BEFORE UPDATE OF password_hash ON users BEGIN SELECT RAISE(ABORT, 'private-password-db-failure'); END`
			if failure == "revocation" {
				trigger = `CREATE TRIGGER fail_revocation BEFORE UPDATE OF revoked_at ON sessions BEGIN SELECT RAISE(ABORT, 'private-password-db-failure'); END`
			}
			if _, err := control.Exec(trigger); err != nil {
				t.Fatal(err)
			}
			rec := userLifecycleRequest(server, "POST", "/api/v1/users/"+session.UserID+"/set-password", `{"password":"private-replacement-password"}`, "secret", nil, "")
			assertInternalResponse(t, rec, 500, false, "private-password-db-failure", "private-replacement-password", before.PasswordHash, cookie.Value)
			if strings.Contains(rec.Body.String(), `"password_set":true`) {
				t.Fatal("falsely reported success")
			}
			after, _, err := server.store.GetUser(session.UserID)
			if err != nil || after.PasswordHash != before.PasswordHash || after.UpdatedAt != before.UpdatedAt {
				t.Fatal("failed reset changed password or timestamp")
			}
			afterSession, _, err := server.store.GetSession(session.ID)
			if err != nil || afterSession != session {
				t.Fatal("failed reset changed session state")
			}
			if response := userLifecycleRequest(server, "GET", "/api/v1/session/me", "", "", cookie, ""); response.Code != 200 {
				t.Fatal("failed reset invalidated existing session")
			}
			if !local.CheckPassword(after.PasswordHash, "correct horse battery") {
				t.Fatal("failed reset invalidated original password")
			}
			events, err := server.store.ListAuditEvents(50)
			if err != nil {
				t.Fatal(err)
			}
			if auditEventsContain(events, "user_password_set") {
				t.Fatal("failed reset produced success audit")
			}
			if !strings.Contains(logs.String(), "user-lifecycle-test") || !strings.Contains(logs.String(), "private-password-db-failure") {
				t.Fatal("missing internal cause or request ID")
			}
			for _, secret := range []string{"private-replacement-password", before.PasswordHash, cookie.Value} {
				if strings.Contains(logs.String(), secret) {
					t.Fatal("credentials leaked into logs")
				}
			}
		})
	}
}

func TestSetUserPasswordAPIStillRequiresScopeAndCSRF(t *testing.T) {
	server := newTestServer(t, "secret")
	user := createLocalTestUserWithRoles(t, server, "admin", "original admin password", []string{"super_admin"})
	cookie, csrf := loginTestUserWithCSRF(t, server, "admin", "original admin password", "/admin")
	reader, _ := createTestAPIKey(t, server, "secret", []string{"users:read"})
	path := "/api/v1/users/" + user.ID + "/set-password"
	for _, tc := range []struct {
		name, token, csrf string
		cookie            *http.Cookie
		want              int
	}{
		{name: "anonymous", want: 401},
		{name: "read-only key", token: reader, want: 403},
		{name: "missing CSRF", cookie: cookie, want: 403},
		{name: "incorrect CSRF", cookie: cookie, csrf: "incorrect", want: 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := userLifecycleRequest(server, "POST", path, `{"password":"replacement password"}`, tc.token, tc.cookie, tc.csrf)
			if rec.Code != tc.want {
				t.Fatalf("got %d want %d", rec.Code, tc.want)
			}
		})
	}
	// Resetting one's own password is allowed; its requesting session is revoked.
	rec := userLifecycleRequest(server, "POST", path, `{"password":"replacement password"}`, "", cookie, csrf)
	if rec.Code != 200 {
		t.Fatalf("own password reset failed: %d %s", rec.Code, rec.Body.String())
	}
	if response := userLifecycleRequest(server, "GET", "/api/v1/session/me", "", "", cookie, ""); response.Code != 401 {
		t.Fatal("self reset did not revoke requesting session")
	}
}
