package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"example.org/odo/internal/auth/local"
	"example.org/odo/internal/db"
)

// Run a competing edit when PATCH starts reading its body. This deterministically
// catches the old read-before-body/replace-whole-user behavior without adding
// datastore hooks or relying on goroutine timing.
type beforePatchBody struct {
	reader io.Reader
	before func()
}

func (b *beforePatchBody) Read(p []byte) (int, error) {
	if b.before != nil {
		before := b.before
		b.before = nil
		before()
	}
	return b.reader.Read(p)
}

func TestUserPatchPreservesConcurrentOmittedFields(t *testing.T) {
	for _, change := range []string{"disable", "lock", "roles", "delete", "profile"} {
		t.Run(change, func(t *testing.T) {
			server, _, cookie, _ := newLogoutTestServer(t, false)
			session, _, err := server.store.GetSession(local.SessionIDFromToken(cookie.Value))
			if err != nil {
				t.Fatal(err)
			}
			var current db.User
			body := &beforePatchBody{reader: strings.NewReader(`{"display_name":"Updated"}`), before: func() {
				switch change {
				case "disable":
					_, _, err = server.store.SetUserStatus(session.UserID, "disabled")
				case "lock":
					_, _, err = server.store.SetUserStatus(session.UserID, "locked")
				case "roles":
					_, _, err = server.store.PatchUser(session.UserID, db.UserPatch{Roles: []string{"viewer"}})
				case "delete":
					_, err = server.store.DeleteUser(session.UserID, "")
				case "profile":
					email := "new@example.invalid"
					_, _, err = server.store.PatchUser(session.UserID, db.UserPatch{Email: &email})
				}
				if err != nil {
					t.Fatal(err)
				}
				current, _, err = server.store.GetUser(session.UserID)
				if err != nil {
					t.Fatal(err)
				}
			}}
			req := httptest.NewRequest("PATCH", "/api/v1/users/"+session.UserID, body)
			req.Header.Set("Authorization", "Bearer secret")
			rec := httptest.NewRecorder()
			server.Routes().ServeHTTP(rec, req)
			want := 200
			if change == "delete" {
				want = 409
			}
			if rec.Code != want {
				t.Fatalf("PATCH: got %d want %d: %s", rec.Code, want, rec.Body.String())
			}
			stored, _, err := server.store.GetUser(session.UserID)
			if err != nil || stored.Status != current.Status || !reflect.DeepEqual(stored.Roles, current.Roles) || stored.Email != current.Email {
				t.Fatal("PATCH overwrote omitted fields")
			}
			if change != "delete" && stored.DisplayName != "Updated" {
				t.Fatal("requested field not applied")
			}
		})
	}
}

func TestRoleChangesRevokeSessionsAtomically(t *testing.T) {
	for _, tc := range []struct {
		name          string
		before, after []string
		revoke        bool
	}{
		{"promotion", []string{"user"}, []string{"security_admin"}, true},
		{"demotion", []string{"security_admin"}, []string{"user"}, true},
		{"replacement", []string{"security_admin"}, []string{"resource_admin"}, true},
		{"reordering", []string{"user", "viewer"}, []string{"viewer", "user"}, false},
	} {
		for _, fail := range []bool{false, true} {
			if fail && !tc.revoke {
				continue
			}
			name := tc.name
			if fail {
				name += "/rollback"
			}
			t.Run(name, func(t *testing.T) {
				server, control, cookie, logs := newLogoutTestServer(t, false)
				session, _, err := server.store.GetSession(local.SessionIDFromToken(cookie.Value))
				if err != nil {
					t.Fatal(err)
				}
				roles, err := json.Marshal(tc.before)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := control.Exec(`UPDATE users SET roles_json = ? WHERE id = ?`, string(roles), session.UserID); err != nil {
					t.Fatal(err)
				}
				before, _, err := server.store.GetUser(session.UserID)
				if err != nil {
					t.Fatal(err)
				}
				if fail {
					if _, err := control.Exec(`CREATE TRIGGER fail_role_revocation BEFORE UPDATE OF revoked_at ON sessions BEGIN SELECT RAISE(ABORT, 'private-role-db-error'); END`); err != nil {
						t.Fatal(err)
					}
				}
				payload, err := json.Marshal(map[string]any{"roles": tc.after, "display_name": "Changed"})
				if err != nil {
					t.Fatal(err)
				}
				rec := userLifecycleRequest(server, "PATCH", "/api/v1/users/"+session.UserID, string(payload), "secret", nil, "")
				stored, _, err := server.store.GetUser(session.UserID)
				if err != nil {
					t.Fatal(err)
				}
				persisted, _, err := server.store.GetSession(session.ID)
				if err != nil {
					t.Fatal(err)
				}
				if fail {
					assertInternalResponse(t, rec, 500, false, "private-role-db-error", cookie.Value, before.PasswordHash)
					if !reflect.DeepEqual(before, stored) || persisted != session {
						t.Fatal("role/profile/version/session change escaped rollback")
					}
					events, err := server.store.ListAuditEvents(50)
					if err != nil || auditEventsContain(events, "user_updated") {
						t.Fatal("false success audit")
					}
				} else {
					if rec.Code != 200 || !reflect.DeepEqual(stored.Roles, tc.after) || stored.DisplayName != "Changed" {
						t.Fatalf("role update failed: %d", rec.Code)
					}
					if (persisted.RevokedAt != "") != tc.revoke {
						t.Fatal("incorrect session revocation")
					}
					if (stored.AuthVersion > before.AuthVersion) != tc.revoke {
						t.Fatal("incorrect version change")
					}
					response := userLifecycleRequest(server, "GET", "/api/v1/session/me", "", "", cookie, "")
					want := 200
					if tc.revoke {
						want = 401
					}
					if response.Code != want {
						t.Fatalf("session authentication: got %d want %d", response.Code, want)
					}
				}
				for _, output := range []string{rec.Body.String(), logs.String()} {
					if strings.Contains(output, cookie.Value) || strings.Contains(output, before.PasswordHash) || strings.Contains(output, "auth_version") {
						t.Fatal("sensitive security data exposed")
					}
				}
			})
		}
	}
}

func TestAuthenticatedSessionInsertFailureIsGeneric(t *testing.T) {
	server, control, _, logs := newLogoutTestServer(t, false)
	if _, err := control.Exec(`CREATE TRIGGER fail_session_insert BEFORE INSERT ON sessions BEGIN SELECT RAISE(ABORT, 'private-session-insert-error'); END`); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"username": {"alice"}, "password": {"correct horse battery"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Request-ID", "login-insert-failure")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	assertInternalResponse(t, rec, 500, true, "private-session-insert-error", "correct horse battery")
	if rec.Header().Get("Location") != "" || len(rec.Result().Cookies()) != 0 {
		t.Fatal("failed login issued cookies or redirected")
	}
	events, err := server.store.ListAuditEvents(50)
	if err != nil || auditEventsContain(events, "login_success") {
		t.Fatal("failed insertion reported login success")
	}
	if !strings.Contains(logs.String(), "login-insert-failure") || strings.Contains(logs.String(), "correct horse battery") {
		t.Fatal("unsafe failure logging")
	}
}
