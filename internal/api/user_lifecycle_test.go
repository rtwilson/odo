package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"example.org/odo/internal/auth/local"
	"example.org/odo/internal/db"
)

func userLifecycleRequest(server *Server, method, path, body, token string, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", "user-lifecycle-test")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if csrf != "" {
		req.Header.Set("X-Odo-CSRF", csrf)
	}
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	return rec
}

func TestUserLifecycleAPI(t *testing.T) {
	server := newTestServer(t, "secret")
	admin := createLocalTestUserWithRoles(t, server, "admin", "original admin password", []string{"super_admin"})
	patron := createLocalTestUser(t, server, "patron", "original patron password")
	adminCookie, csrf := loginTestUserWithCSRF(t, server, "admin", "original admin password", "/admin")
	oldCookie := loginTestUser(t, server, "patron", "original patron password", "/resources")
	path := "/api/v1/users/" + patron.ID
	request := func(method, target, body string, want int) *httptest.ResponseRecorder {
		t.Helper()
		rec := userLifecycleRequest(server, method, target, body, "", adminCookie, csrf)
		if rec.Code != want {
			t.Fatalf("%s %s: got %d want %d: %s", method, target, rec.Code, want, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "password_hash") || strings.Contains(rec.Body.String(), "original patron password") || strings.Contains(rec.Body.String(), "new patron password") {
			t.Fatal("response exposed credentials")
		}
		return rec
	}
	request("DELETE", path, `{"actor_id":"spoofed-actor"}`, 200)
	request("DELETE", path, "", 200)
	session, found, err := server.store.GetSession(local.SessionIDFromToken(oldCookie.Value))
	if err != nil || !found || session.RevokedAt == "" {
		t.Fatalf("old session not revoked: %v %v", found, err)
	}
	if rec := userLifecycleRequest(server, "GET", "/api/v1/session/me", "", "", oldCookie, ""); rec.Code != 401 {
		t.Fatalf("deleted session authenticated: %d", rec.Code)
	}
	login := func(password string, want int) {
		t.Helper()
		form := url.Values{"username": {"patron"}, "password": {password}}
		req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		server.Routes().ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("login: got %d want %d", rec.Code, want)
		}
	}
	login("original patron password", 401)
	var normal, deleted struct {
		Users []db.User `json:"users"`
	}
	if err := json.Unmarshal(request("GET", "/api/v1/users", "", 200).Body.Bytes(), &normal); err != nil {
		t.Fatal(err)
	}
	if len(normal.Users) != 1 || normal.Users[0].ID != admin.ID {
		t.Fatalf("default list included deleted user: %+v", normal.Users)
	}
	if err := json.Unmarshal(request("GET", "/api/v1/users?deleted=true", "", 200).Body.Bytes(), &deleted); err != nil {
		t.Fatal(err)
	}
	if len(deleted.Users) != 1 || deleted.Users[0].ID != patron.ID || deleted.Users[0].Status != "deleted" {
		t.Fatalf("deleted list: %+v", deleted.Users)
	}
	request("GET", "/api/v1/users?deleted=invalid", "", 400)
	request("PATCH", path, `{"status":"active"}`, 409)
	request("POST", path+"/enable", "", 409)
	request("POST", path+"/restore", `{"password":"new patron password"}`, 200)
	login("new patron password", 401) // Restoration deliberately leaves it disabled.
	request("POST", path+"/restore", `{"password":"new patron password"}`, 409)
	request("POST", path+"/enable", "", 200)
	if rec := userLifecycleRequest(server, "GET", "/api/v1/session/me", "", "", oldCookie, ""); rec.Code != 401 {
		t.Fatalf("restore revived old session: %d", rec.Code)
	}
	login("original patron password", 401)
	login("new patron password", 302)
	events, err := server.store.ListAuditEvents(100)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, event := range events {
		if event.Event != "user_deleted" && event.Event != "user_restored" {
			continue
		}
		counts[event.Event]++
		var detail map[string]string
		if err := json.Unmarshal([]byte(event.Detail), &detail); err != nil {
			t.Fatal(err)
		}
		if len(detail) != 2 || detail["id"] != patron.ID || detail["actor_id"] != admin.ID {
			t.Fatalf("incorrect lifecycle audit: %s", event.Detail)
		}
	}
	if counts["user_deleted"] != 1 || counts["user_restored"] != 1 {
		t.Fatalf("audit counts: %v", counts)
	}
}

func TestUserLifecycleAPIPermissionsAndCSRF(t *testing.T) {
	server := newTestServer(t, "secret")
	admin := createLocalTestUserWithRoles(t, server, "admin", "correct horse battery", []string{"super_admin"})
	patron := createLocalTestUser(t, server, "patron", "correct horse battery")
	security := createLocalTestUserWithRoles(t, server, "security", "correct horse battery", []string{"security_admin"})
	adminCookie, csrf := loginTestUserWithCSRF(t, server, "admin", "correct horse battery", "/admin")
	patronCookie := loginTestUser(t, server, "patron", "correct horse battery", "/resources")
	securityCookie, securityCSRF := loginTestUserWithCSRF(t, server, "security", "correct horse battery", "/admin")
	reader, _ := createTestAPIKey(t, server, "secret", []string{"users:read"})
	writer, _ := createTestAPIKey(t, server, "secret", []string{"users:write"})
	for _, method := range []string{"DELETE", "POST"} {
		path := "/api/v1/users/" + patron.ID
		if method == "POST" {
			path += "/restore"
		}
		for _, tc := range []struct {
			name, token, csrf string
			cookie            *http.Cookie
			want              int
		}{
			{name: "anonymous", want: 401},
			{name: "patron", cookie: patronCookie, want: 403},
			{name: "read-only key", token: reader, want: 403},
			{name: "missing CSRF", cookie: adminCookie, want: 403},
			{name: "wrong CSRF", cookie: adminCookie, csrf: "wrong", want: 403},
		} {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				rec := userLifecycleRequest(server, method, path, `{"password":"replacement password"}`, tc.token, tc.cookie, tc.csrf)
				if rec.Code != tc.want {
					t.Fatalf("got %d want %d: %s", rec.Code, tc.want, rec.Body.String())
				}
			})
		}
	}
	for _, tc := range []struct {
		method, path, token string
		cookie              *http.Cookie
		csrf                string
		want                int
	}{
		{"DELETE", "/api/v1/users/" + admin.ID, "", adminCookie, csrf, 403},
		{"DELETE", "/api/v1/users/" + security.ID, "", securityCookie, securityCSRF, 403},
		// A users:write key cannot delete what it cannot demote.
		{"DELETE", "/api/v1/users/" + admin.ID, writer, nil, "", 403},
		{"DELETE", "/api/v1/users/" + security.ID, writer, nil, "", 403},
		{"DELETE", "/api/v1/users/" + admin.ID, "secret", nil, "", 409},
		{"DELETE", "/api/v1/users/missing", "secret", nil, "", 404},
		{"POST", "/api/v1/users/missing/restore", "secret", nil, "", 404},
		{"DELETE", "/api/v1/users/" + patron.ID, writer, nil, "", 200},
		{"POST", "/api/v1/users/" + patron.ID + "/restore", writer, nil, "", 200},
		{"DELETE", "/api/v1/users/" + patron.ID, "", securityCookie, securityCSRF, 200},
		{"POST", "/api/v1/users/" + patron.ID + "/restore", "", securityCookie, securityCSRF, 200},
	} {
		rec := userLifecycleRequest(server, tc.method, tc.path, `{"password":"replacement password"}`, tc.token, tc.cookie, tc.csrf)
		if rec.Code != tc.want {
			t.Fatalf("%s %s: got %d want %d: %s", tc.method, tc.path, rec.Code, tc.want, rec.Body.String())
		}
	}
	// A users:write key must not restore retained administrative roles.
	if _, err := server.store.DeleteUser(security.ID, admin.ID); err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/users/" + security.ID + "/restore"
	if rec := userLifecycleRequest(server, "POST", path, `{"password":"replacement password"}`, writer, nil, ""); rec.Code != 403 {
		t.Fatalf("non-admin restored roles: %d", rec.Code)
	}
	if rec := userLifecycleRequest(server, "POST", path, `{"password":"replacement password"}`, "secret", nil, ""); rec.Code != 200 {
		t.Fatalf("admin restore failed: %d %s", rec.Code, rec.Body.String())
	}
}

func TestUserLifecycleAPILookupFailure(t *testing.T) {
	for _, method := range []string{"DELETE", "POST"} {
		t.Run(method, func(t *testing.T) {
			server, control, _, _ := newLogoutTestServer(t, false)
			if _, err := control.Exec(`DROP TABLE users`); err != nil {
				t.Fatal(err)
			}
			path := "/api/v1/users/unknown"
			if method == "POST" {
				path += "/restore"
			}
			rec := userLifecycleRequest(server, method, path, `{"password":"private-password"}`, "secret", nil, "")
			assertInternalResponse(t, rec, 500, false, "no such table", "private-password")
		})
	}
}

func TestUserRestoreRejectsInvalidPasswordBodies(t *testing.T) {
	server := newTestServer(t, "secret")
	user := createLocalTestUser(t, server, "patron", "original password")
	if _, err := server.store.DeleteUser(user.ID, ""); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{"", "null", "{}", `{"password":"short"}`, `{"password":"` + strings.Repeat("x", 73) + `"}`, `{"password":"valid password","roles":["admin"]}`, `{"password":"valid password"} {}`, strings.Repeat(" ", 4097) + `{}`} {
		rec := userLifecycleRequest(server, "POST", "/api/v1/users/"+user.ID+"/restore", body, "secret", nil, "")
		if rec.Code != 400 {
			t.Fatalf("invalid restore body returned %d", rec.Code)
		}
		stored, found, err := server.store.GetUser(user.ID)
		if err != nil || !found || stored.Status != "deleted" || stored.PasswordHash != "" {
			t.Fatalf("invalid restore changed user: found=%v err=%v", found, err)
		}
	}
}

func TestUserLifecycleAPIRollsBackDatabaseFailures(t *testing.T) {
	for _, operation := range []string{"delete", "restore"} {
		for _, failure := range []string{"revocation", "audit"} {
			t.Run(operation+"/"+failure, func(t *testing.T) {
				// Reuse the existing real-SQLite failure fixture with a second
				// connection; no production failure hooks or mocks are needed.
				server, control, cookie, logs := newLogoutTestServer(t, false)
				sessionID := local.SessionIDFromToken(cookie.Value)
				session, _, err := server.store.GetSession(sessionID)
				if err != nil {
					t.Fatal(err)
				}
				if operation == "restore" {
					if _, err := server.store.DeleteUser(session.UserID, ""); err != nil {
						t.Fatal(err)
					}
				}
				before, _, err := server.store.GetUser(session.UserID)
				if err != nil {
					t.Fatal(err)
				}
				sessionBefore, _, err := server.store.GetSession(sessionID)
				if err != nil {
					t.Fatal(err)
				}
				trigger := `CREATE TRIGGER fail_lifecycle BEFORE UPDATE OF revoked_at ON sessions BEGIN SELECT RAISE(ABORT, 'private-database-detail'); END`
				if failure == "audit" {
					trigger = `CREATE TRIGGER fail_lifecycle BEFORE INSERT ON audit_events WHEN NEW.event IN ('user_deleted','user_restored') BEGIN SELECT RAISE(ABORT, 'private-database-detail'); END`
				}
				if _, err := control.Exec(trigger); err != nil {
					t.Fatal(err)
				}
				// An unrevoked row ensures restoration exercises the UPDATE too.
				if operation == "restore" && failure == "revocation" {
					if _, err := control.Exec(`DROP TRIGGER fail_lifecycle; UPDATE sessions SET revoked_at = NULL; CREATE TRIGGER fail_lifecycle BEFORE UPDATE OF revoked_at ON sessions BEGIN SELECT RAISE(ABORT, 'private-database-detail'); END`); err != nil {
						t.Fatal(err)
					}
					sessionBefore, _, err = server.store.GetSession(sessionID)
					if err != nil {
						t.Fatal(err)
					}
				}
				method, path := "DELETE", "/api/v1/users/"+session.UserID
				if operation == "restore" {
					method, path = "POST", path+"/restore"
				}
				rec := userLifecycleRequest(server, method, path, `{"password":"private-replacement-password"}`, "secret", nil, "")
				assertInternalResponse(t, rec, 500, false, "private-database-detail", "private-replacement-password", cookie.Value)
				if !strings.Contains(logs.String(), "user-lifecycle-test") || !strings.Contains(logs.String(), "private-database-detail") {
					t.Fatal("missing request ID or internal failure cause")
				}
				if strings.Contains(logs.String(), "private-replacement-password") || strings.Contains(logs.String(), cookie.Value) {
					t.Fatal("credentials in logs")
				}
				after, _, err := server.store.GetUser(session.UserID)
				if err != nil || after.Status != before.Status || after.PasswordHash != before.PasswordHash {
					t.Fatalf("account change escaped rollback: %v", err)
				}
				afterSession, _, err := server.store.GetSession(sessionID)
				if err != nil || afterSession != sessionBefore {
					t.Fatalf("session change escaped rollback: %v", err)
				}
				events, err := server.store.ListAuditEvents(50)
				if err != nil {
					t.Fatal(err)
				}
				for _, event := range events {
					if (operation == "delete" && event.Event == "user_deleted") || (operation == "restore" && event.Event == "user_restored") {
						t.Fatalf("false successful audit event: %s", event.Event)
					}
				}
			})
		}
	}
}

// Status changes on a deleted account answer like PATCH does: the account
// exists (GET still returns it) and must be restored first.
func TestUserStatusChangeOnDeletedUserConflicts(t *testing.T) {
	server := newTestServer(t, "secret")
	patron := createLocalTestUser(t, server, "patron", "correct horse battery")
	if rec := userLifecycleRequest(server, "DELETE", "/api/v1/users/"+patron.ID, "", "secret", nil, ""); rec.Code != 200 {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	for _, action := range []string{"enable", "disable", "lock", "unlock"} {
		rec := userLifecycleRequest(server, "POST", "/api/v1/users/"+patron.ID+"/"+action, "", "secret", nil, "")
		if rec.Code != http.StatusConflict {
			t.Fatalf("%s on deleted user: %d %s", action, rec.Code, rec.Body.String())
		}
	}
	if rec := userLifecycleRequest(server, "POST", "/api/v1/users/missing/disable", "", "secret", nil, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("missing user: %d", rec.Code)
	}
}
