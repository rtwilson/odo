package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"example.org/odo/internal/auth/local"
)

var statusMutationCases = []struct{ name, method, suffix, body, status, event string }{
	{"disable", "POST", "/disable", "", "disabled", "user_status_set"},
	{"lock", "POST", "/lock", "", "locked", "user_status_set"},
	{"patch-disable", "PATCH", "", `{"status":"disabled","display_name":"Updated","email":"updated@example.invalid","roles":["viewer"]}`, "disabled", "user_updated"},
	{"patch-lock", "PATCH", "", `{"status":"locked","display_name":"Updated","email":"updated@example.invalid","roles":["viewer"]}`, "locked", "user_updated"},
}

func TestUserStatusChangeRevokesSessionsAcrossReenable(t *testing.T) {
	for _, tc := range statusMutationCases {
		t.Run(tc.name, func(t *testing.T) {
			server, _, cookie, _ := newLogoutTestServer(t, false)
			session, _, err := server.store.GetSession(local.SessionIDFromToken(cookie.Value))
			if err != nil {
				t.Fatal(err)
			}
			other := createLocalTestUser(t, server, "other", "other account password")
			otherCookie := loginTestUser(t, server, other.Username, "other account password", "/resources")
			secondCookie := loginTestUser(t, server, "alice", "correct horse battery", "/resources")
			path := "/api/v1/users/" + session.UserID
			rec := userLifecycleRequest(server, tc.method, path+tc.suffix, tc.body, "secret", nil, "")
			if rec.Code != 200 {
				t.Fatalf("status change: %d %s", rec.Code, rec.Body.String())
			}
			user, _, err := server.store.GetUser(session.UserID)
			if err != nil || user.Status != tc.status {
				t.Fatal("status not persisted")
			}
			if (tc.status == "disabled" && (user.DisabledAt == "" || user.LockedAt != "")) || (tc.status == "locked" && (user.LockedAt == "" || user.DisabledAt != "")) {
				t.Fatal("incorrect status timestamps")
			}
			if tc.method == "PATCH" && user.DisplayName != "Updated" {
				t.Fatal("PATCH metadata not persisted")
			}
			for _, old := range []*http.Cookie{cookie, secondCookie} {
				stored, found, err := server.store.GetSession(local.SessionIDFromToken(old.Value))
				if err != nil || !found || stored.RevokedAt == "" {
					t.Fatal("session not revoked")
				}
			}
			form := url.Values{"username": {"alice"}, "password": {"correct horse battery"}}
			loginReq := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
			loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			loginRec := httptest.NewRecorder()
			server.Routes().ServeHTTP(loginRec, loginReq)
			if loginRec.Code != 401 {
				t.Fatal("inactive account logged in")
			}
			action := "/enable"
			if tc.status == "locked" {
				action = "/unlock"
			}
			if response := userLifecycleRequest(server, "POST", path+action, "", "secret", nil, ""); response.Code != 200 {
				t.Fatal("reactivation failed")
			}
			for _, old := range []*http.Cookie{cookie, secondCookie} {
				if response := userLifecycleRequest(server, "GET", "/api/v1/session/me", "", "", old, ""); response.Code != 401 {
					t.Fatal("reactivation revived old session")
				}
			}
			if response := userLifecycleRequest(server, "GET", "/api/v1/session/me", "", "", otherCookie, ""); response.Code != 200 {
				t.Fatal("another account's session was revoked")
			}
			loginTestUser(t, server, "alice", "correct horse battery", "/resources")
			events, err := server.store.ListAuditEvents(100)
			if err != nil || !auditEventsContain(events, tc.event) {
				t.Fatal("missing status success audit")
			}
		})
	}
}

func TestUserStatusChangeRollsBackWriteFailures(t *testing.T) {
	for _, tc := range statusMutationCases {
		for _, failure := range []string{"status", "revocation"} {
			t.Run(tc.name+"/"+failure, func(t *testing.T) {
				server, control, cookie, logs := newLogoutTestServer(t, false)
				session, _, err := server.store.GetSession(local.SessionIDFromToken(cookie.Value))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := control.Exec(`UPDATE users SET updated_at = '2020-01-01T00:00:00Z' WHERE id = ?`, session.UserID); err != nil {
					t.Fatal(err)
				}
				before, _, err := server.store.GetUser(session.UserID)
				if err != nil {
					t.Fatal(err)
				}
				trigger := `CREATE TRIGGER fail_status BEFORE UPDATE OF status ON users BEGIN SELECT RAISE(ABORT, 'private-status-db-failure'); END`
				if failure == "revocation" {
					trigger = `CREATE TRIGGER fail_revocation BEFORE UPDATE OF revoked_at ON sessions BEGIN SELECT RAISE(ABORT, 'private-status-db-failure'); END`
				}
				if _, err := control.Exec(trigger); err != nil {
					t.Fatal(err)
				}
				rec := userLifecycleRequest(server, tc.method, "/api/v1/users/"+session.UserID+tc.suffix, tc.body, "secret", nil, "")
				assertInternalResponse(t, rec, 500, false, "private-status-db-failure", before.PasswordHash, cookie.Value)
				after, _, err := server.store.GetUser(session.UserID)
				if err != nil || !reflect.DeepEqual(after, before) {
					t.Fatal("status/metadata change escaped rollback")
				}
				afterSession, _, err := server.store.GetSession(session.ID)
				if err != nil || afterSession != session {
					t.Fatal("session change escaped rollback")
				}
				if response := userLifecycleRequest(server, "GET", "/api/v1/session/me", "", "", cookie, ""); response.Code != 200 {
					t.Fatal("failed change invalidated old session")
				}
				events, err := server.store.ListAuditEvents(50)
				if err != nil || auditEventsContain(events, tc.event) {
					t.Fatal("failure produced success audit")
				}
				if !strings.Contains(logs.String(), "private-status-db-failure") || !strings.Contains(logs.String(), "user-lifecycle-test") {
					t.Fatal("missing cause or request ID")
				}
				if strings.Contains(logs.String(), cookie.Value) || strings.Contains(logs.String(), before.PasswordHash) {
					t.Fatal("credentials leaked into logs")
				}
			})
		}
	}
}

func TestUserStatusMutationPermissionsAndLastAdmin(t *testing.T) {
	server := newTestServer(t, "secret")
	admin := createLocalTestUserWithRoles(t, server, "admin", "admin account password", []string{"super_admin"})
	patron := createLocalTestUser(t, server, "patron", "patron account password")
	cookie, csrf := loginTestUserWithCSRF(t, server, "admin", "admin account password", "/admin")
	reader, _ := createTestAPIKey(t, server, "secret", []string{"users:read"})
	for _, tc := range statusMutationCases {
		for _, auth := range []struct {
			name, token, csrf string
			cookie            *http.Cookie
			want              int
		}{
			{name: "anonymous", want: 401}, {name: "reader", token: reader, want: 403},
			{name: "missing CSRF", cookie: cookie, want: 403}, {name: "wrong CSRF", cookie: cookie, csrf: "wrong", want: 403},
		} {
			t.Run(tc.name+"/"+auth.name, func(t *testing.T) {
				rec := userLifecycleRequest(server, tc.method, "/api/v1/users/"+patron.ID+tc.suffix, tc.body, auth.token, auth.cookie, auth.csrf)
				if rec.Code != auth.want {
					t.Fatalf("got %d want %d", rec.Code, auth.want)
				}
			})
		}
		rec := userLifecycleRequest(server, tc.method, "/api/v1/users/"+admin.ID+tc.suffix, tc.body, "secret", nil, "")
		if rec.Code != 400 {
			t.Fatalf("%s allowed last-admin status change: %d", tc.name, rec.Code)
		}
		// Browser mutations still work when both permissions and CSRF are valid.
		rec = userLifecycleRequest(server, tc.method, "/api/v1/users/"+patron.ID+tc.suffix, tc.body, "", cookie, csrf)
		if rec.Code != 200 {
			t.Fatalf("%s valid browser mutation failed: %d", tc.name, rec.Code)
		}
	}
}

func TestActiveUserMetadataPatchDoesNotRevokeSession(t *testing.T) {
	server, control, cookie, _ := newLogoutTestServer(t, false)
	session, _, err := server.store.GetSession(local.SessionIDFromToken(cookie.Value))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.Exec(`CREATE TRIGGER fail_revocation BEFORE UPDATE OF revoked_at ON sessions BEGIN SELECT RAISE(ABORT, 'unnecessary revocation'); END`); err != nil {
		t.Fatal(err)
	}
	rec := userLifecycleRequest(server, "PATCH", "/api/v1/users/"+session.UserID, `{"display_name":"Updated"}`, "secret", nil, "")
	if rec.Code != 200 {
		t.Fatalf("metadata PATCH: %d %s", rec.Code, rec.Body.String())
	}
	after, _, err := server.store.GetSession(session.ID)
	if err != nil || after != session {
		t.Fatal("metadata patch changed session")
	}
}
