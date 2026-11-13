package api

import (
	"net/http"
	"testing"
)

// users:write alone (an API key, or the security_admin role) must not act on
// accounts holding non-default roles. Resetting an administrator's password
// would let it sign in as that administrator; locking would deny service.
func TestUsersWriteCannotActOnPrivilegedAccounts(t *testing.T) {
	server := newTestServer(t, "secret")
	admin := createLocalTestUserWithRoles(t, server, "admin", "admin account password", []string{"super_admin"})
	security := createLocalTestUserWithRoles(t, server, "security", "security account password", []string{"security_admin"})
	staff := createLocalTestUserWithRoles(t, server, "staff", "staff account password", []string{"viewer"})
	patron := createLocalTestUser(t, server, "patron", "patron account password")
	writer, _ := createTestAPIKey(t, server, "secret", []string{"users:write"})
	securityCookie, securityCSRF := loginTestUserWithCSRF(t, server, "security", "security account password", "/admin")

	mutations := []struct{ name, method, suffix, body string }{
		{"set-password", "POST", "/set-password", `{"password":"attacker chosen password"}`},
		{"disable", "POST", "/disable", ""},
		{"lock", "POST", "/lock", ""},
		{"enable", "POST", "/enable", ""},
		{"unlock", "POST", "/unlock", ""},
		{"revoke-sessions", "POST", "/revoke-sessions", ""},
		{"patch-email", "PATCH", "", `{"email":"attacker@example.invalid"}`},
		{"patch-status", "PATCH", "", `{"status":"locked"}`},
	}
	callers := []struct {
		name, token, csrf string
		cookie            *http.Cookie
	}{
		{name: "users:write key", token: writer},
		{name: "security_admin session", cookie: securityCookie, csrf: securityCSRF},
	}
	for _, target := range []struct{ name, id string }{{"admin", admin.ID}, {"staff", staff.ID}} {
		for _, caller := range callers {
			for _, m := range mutations {
				rec := userLifecycleRequest(server, m.method, "/api/v1/users/"+target.id+m.suffix, m.body, caller.token, caller.cookie, caller.csrf)
				if rec.Code != http.StatusForbidden {
					t.Fatalf("%s %s on %s: got %d want 403: %s", caller.name, m.name, target.name, rec.Code, rec.Body.String())
				}
			}
		}
	}
	// Nothing changed: the administrator still signs in with the original password.
	loginTestUser(t, server, "admin", "admin account password", "/admin")
	if user, _, _ := server.store.GetUser(admin.ID); user.Status != "active" || user.Email == "attacker@example.invalid" {
		t.Fatalf("privileged account modified: %+v", user)
	}

	// Default-role accounts remain manageable with users:write.
	for _, caller := range callers {
		for _, m := range mutations {
			rec := userLifecycleRequest(server, m.method, "/api/v1/users/"+patron.ID+m.suffix, m.body, caller.token, caller.cookie, caller.csrf)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s %s on patron: got %d: %s", caller.name, m.name, rec.Code, rec.Body.String())
			}
		}
	}
	// Admin scope may act on privileged accounts.
	if rec := userLifecycleRequest(server, "POST", "/api/v1/users/"+staff.ID+"/lock", "", "secret", nil, ""); rec.Code != http.StatusOK {
		t.Fatalf("admin lock of staff: %d", rec.Code)
	}
	// A security_admin may still change its own password.
	rec := userLifecycleRequest(server, "POST", "/api/v1/users/"+security.ID+"/set-password", `{"password":"new security password"}`, "", securityCookie, securityCSRF)
	if rec.Code != http.StatusOK {
		t.Fatalf("self password change: %d %s", rec.Code, rec.Body.String())
	}
}
