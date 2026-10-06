package api

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOwnedResponsesHaveSecurityHeaders(t *testing.T) {
	server := newTestServer(t, "secret")
	createLocalTestUserWithRoles(t, server, "admin", "correct horse battery", []string{"super_admin"})
	cookie := loginTestUser(t, server, "admin", "correct horse battery", "/admin")
	handler := server.Routes()
	for _, path := range []string{"/", "/login", "/admin", "/resources", "/api/v1", "/api/v1/health", "/openapi.yaml", "/missing", "/logout"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			if path != "/login" {
				req.AddCookie(cookie)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			for name, want := range map[string]string{"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=(), microphone=(), geolocation=()"} {
				if got := rec.Header().Get(name); got != want {
					t.Errorf("%s = %q, want %q", name, got, want)
				}
			}
			csp := rec.Header().Get("Content-Security-Policy")
			if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") {
				t.Fatalf("missing app CSP: %q", csp)
			}
			if path == "/admin" {
				if rec.Code != http.StatusOK {
					t.Fatalf("admin returned %d", rec.Code)
				}
				_, script, found := strings.Cut(rec.Body.String(), "<script>")
				if !found {
					t.Fatal("admin script missing")
				}
				script, _, _ = strings.Cut(script, "</script>")
				hash := sha256.Sum256([]byte(script))
				if !strings.Contains(csp, "script-src 'sha256-"+base64.StdEncoding.EncodeToString(hash[:])+"'") {
					t.Fatal("CSP does not authorize the served admin script")
				}
			} else if !strings.Contains(csp, "script-src 'none'") {
				t.Fatalf("unexpected script policy: %q", csp)
			}
		})
	}
	// Authentication failures are still Odo-owned responses.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/users", nil))
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("unprotected auth failure: %d %v", rec.Code, rec.Header())
	}
}

func TestVendorResponsesDoNotReceiveAppSecurityHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Content-Security-Policy-Report-Only", "script-src 'none'")
		_, _ = w.Write([]byte("<!doctype html><html><body>vendor</body></html>"))
	}))
	defer upstream.Close()
	server := newProxyFetchTestServer(t, upstream.URL)
	handler := server.Routes()
	for _, path := range []string{"/odo/https/www.jstor.org/", "/odo?url=https://www.jstor.org/", "/mfe-header/remoteEntry.js"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Header.Set("Referer", "http://127.0.0.1:8080/odo/https/www.jstor.org/")
			req.Header.Set("Sec-Fetch-Dest", "script")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "vendor") {
				t.Fatalf("vendor fetch failed: %d %s", rec.Code, rec.Body.String())
			}
			for _, name := range []string{"Content-Security-Policy", "Content-Security-Policy-Report-Only", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Permissions-Policy"} {
				if got := rec.Header().Get(name); got != "" {
					t.Errorf("vendor response received %s: %s", name, got)
				}
			}
		})
	}
}
