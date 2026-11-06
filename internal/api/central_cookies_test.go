package api

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"example.org/odo/internal/auth/local"
)

func TestCentralCookieNamespacesAndLogout(t *testing.T) {
	for _, tc := range []struct{ name, flag, prefix string }{
		{"legacy", "false", ""}, {"guarded", "true", "__Host-"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("APP_HOST_GUARD", tc.flag)
			t.Setenv("APP_PUBLIC_URL", "https://odo.example")
			t.Setenv("APP_PROXY_BASE_DOMAIN", "proxy.example")
			server := newTestServer(t, "secret")
			createLocalTestUserWithRoles(t, server, "admin", "correct horse battery", []string{"resource_admin"})
			handler := server.Routes()
			form := url.Values{"username": {"admin"}, "password": {"correct horse battery"}, "next": {"/admin"}}
			req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
			req.Host = "odo.example"
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != 302 {
				t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
			}
			session := findCookie(rec.Result().Cookies(), tc.prefix+"odo_session")
			csrf := findCookie(rec.Result().Cookies(), tc.prefix+"odo_csrf")
			if session == nil || csrf == nil || !session.HttpOnly || csrf.HttpOnly {
				t.Fatalf("cookie names or HttpOnly policy: %v", rec.Result().Cookies())
			}
			for _, cookie := range []*http.Cookie{session, csrf} {
				if !cookie.Secure || cookie.Domain != "" || cookie.Path != "/" || cookie.SameSite != http.SameSiteLaxMode {
					t.Fatalf("unsafe central cookie: %+v", cookie)
				}
			}
			// A guarded server must ignore a valid token under the legacy name.
			if tc.prefix != "" {
				legacy := httptest.NewRequest("GET", "/api/v1/session/me", nil)
				legacy.Host = "odo.example"
				legacy.AddCookie(&http.Cookie{Name: "odo_session", Value: session.Value})
				result := httptest.NewRecorder()
				handler.ServeHTTP(result, legacy)
				if result.Code != 401 {
					t.Fatalf("guarded auth accepted legacy cookie: %s", result.Body.String())
				}
			}
			admin := httptest.NewRequest("GET", "/admin", nil)
			admin.Host = "odo.example"
			admin.AddCookie(session)
			page := httptest.NewRecorder()
			handler.ServeHTTP(page, admin)
			if page.Code != 200 || !strings.Contains(page.Body.String(), `<meta name="odo-csrf-cookie" content="`+tc.prefix+`odo_csrf">`) {
				t.Fatalf("admin selected wrong CSRF cookie: %d", page.Code)
			}
			_, script, _ := strings.Cut(page.Body.String(), "<script>")
			script, _, _ = strings.Cut(script, "</script>")
			hash := sha256.Sum256([]byte(script))
			if !strings.Contains(page.Header().Get("Content-Security-Policy"), "'sha256-"+base64.StdEncoding.EncodeToString(hash[:])+"'") {
				t.Fatal("CSP hash does not match the served script")
			}
			for _, header := range []string{"", csrf.Value} {
				write := httptest.NewRequest("POST", "/api/v1/resources", strings.NewReader(`{"id":"cookie-check","name":"Cookie check","domains":[{"host":"vendor.example"}]}`))
				write.Host = "odo.example"
				write.AddCookie(session)
				write.Header.Set("X-Odo-CSRF", header)
				result := httptest.NewRecorder()
				handler.ServeHTTP(result, write)
				want := 403
				if header != "" {
					want = 200
				}
				if result.Code != want {
					t.Fatalf("CSRF write: got %d want %d: %s", result.Code, want, result.Body.String())
				}
			}
			logout := httptest.NewRequest("POST", "/logout", nil)
			logout.Host = "odo.example"
			logout.AddCookie(session)
			logout.Header.Set("X-Odo-CSRF", csrf.Value)
			result := httptest.NewRecorder()
			handler.ServeHTTP(result, logout)
			for _, name := range []string{session.Name, csrf.Name} {
				cleared := findCookie(result.Result().Cookies(), name)
				if cleared == nil || cleared.MaxAge >= 0 || !cleared.Secure || cleared.Domain != "" || cleared.Path != "/" {
					t.Fatalf("logout did not clear active cookie %q", name)
				}
			}
			stored, found, err := server.store.GetSession(local.SessionIDFromToken(session.Value))
			if err != nil || !found || stored.RevokedAt == "" {
				t.Fatalf("logout did not revoke session: found=%v err=%v", found, err)
			}
		})
	}
}
