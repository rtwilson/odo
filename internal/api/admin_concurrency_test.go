package api

import "testing"

func TestAdministratorCountFailureReturnsGenericServerError(t *testing.T) {
	for _, tc := range []struct{ method, suffix, body string }{
		{"DELETE", "", ""}, {"POST", "/disable", ""}, {"POST", "/lock", ""},
		{"PATCH", "", `{"roles":["user"]}`}, {"PATCH", "", `{"status":"disabled"}`},
	} {
		t.Run(tc.method+tc.suffix+tc.body, func(t *testing.T) {
			server, control, _, _ := newLogoutTestServer(t, false)
			admin := createLocalTestUserWithRoles(t, server, "admin", "admin account password", []string{"super_admin"})
			if _, err := control.Exec(`UPDATE users SET roles_json = 'private-invalid-json' WHERE username = 'alice'`); err != nil {
				t.Fatal(err)
			}
			rec := userLifecycleRequest(server, tc.method, "/api/v1/users/"+admin.ID+tc.suffix, tc.body, "secret", nil, "")
			assertInternalResponse(t, rec, 500, false, "private-invalid-json", admin.PasswordHash)
			stored, found, err := server.store.GetUser(admin.ID)
			if err != nil || !found || stored.Status != "active" || len(stored.Roles) != 1 || stored.Roles[0] != "super_admin" {
				t.Fatal("count failure changed administrator")
			}
		})
	}
}
