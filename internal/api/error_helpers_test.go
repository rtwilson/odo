package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"example.org/odo/internal/accesslog"
	"example.org/odo/internal/resources"
)

func assertInternalResponse(t *testing.T, rec *httptest.ResponseRecorder, status int, html bool, forbidden ...string) string {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status=%d, want %d: %s", rec.Code, status, rec.Body.String())
	}
	id := rec.Header().Get("X-Request-ID")
	if id == "" {
		t.Fatal("missing request ID header")
	}
	if html {
		if !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") || !strings.Contains(rec.Body.String(), id) || !strings.Contains(rec.Body.String(), "An internal error occurred.") {
			t.Fatalf("unexpected browser error: %s", rec.Body.String())
		}
	} else {
		var body map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if len(body) != 3 || body["error"] != "internal_error" || body["message"] != "An internal error occurred." || body["request_id"] != id {
			t.Fatalf("unexpected public error: %#v", body)
		}
	}
	for _, value := range forbidden {
		if strings.Contains(rec.Body.String(), value) {
			t.Errorf("response leaked %q", value)
		}
	}
	return id
}

func TestInternalDatabaseErrorsAreSanitized(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, body, token string
		session, html                   bool
	}{
		{"login", "POST", "/login", "username=alice&password=private-password", "", false, true},
		{"resources", "GET", "/api/v1/resources", "", "secret", false, false},
		{"api keys", "GET", "/api/v1/api-keys", "", "secret", false, false},
		{"users", "GET", "/api/v1/users", "", "secret", false, false},
		{"config revisions", "GET", "/api/v1/config/revisions", "", "secret", false, false},
		{"SAML providers", "GET", "/api/v1/auth/saml/providers", "", "secret", false, false},
		{"bearer authentication", "GET", "/api/v1/resources", "", "private-bearer", false, false},
		{"session authentication", "GET", "/api/v1/session/me", "", "", true, false},
		{"resource page session", "GET", "/resources", "", "", true, true},
		{"admin authentication", "GET", "/admin", "", "private-bearer", false, true},
		{"public discovery authentication", "GET", "/api/v1", "", "private-bearer", false, false},
		{"resource rules", "POST", "/api/v1/rules/test-url", `{"url":"https://www.jstor.org/"}`, "secret", false, false},
		{"proxy test resources", "POST", "/api/v1/proxy/test-fetch", `{"url":"https://www.jstor.org/"}`, "secret", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := newTestServer(t, "secret")
			var cookie *http.Cookie
			if tc.session {
				createLocalTestUser(t, server, "alice", "correct-password")
				cookie = loginTestUser(t, server, "alice", "correct-password", "/resources")
			}
			var logs, access bytes.Buffer
			server.logger = slog.New(slog.NewJSONHandler(&logs, nil))
			server.accessLog, _ = accesslog.New(accesslog.FormatPrivacy, &access)
			if err := server.store.Close(); err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(tc.method, tc.path+"?search=private-search", strings.NewReader(tc.body))
			if tc.path == "/login" {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			req.Header.Set("X-Request-ID", "support-ticket_123")
			req.Header.Set("Cookie", "unrelated=private-cookie")
			if cookie != nil {
				req.AddCookie(cookie)
			}
			rec := httptest.NewRecorder()
			server.Routes().ServeHTTP(rec, req)
			id := assertInternalResponse(t, rec, 500, tc.html, "database is closed", "sql:", "private-password", "private-bearer", "private-cookie", "private-search")
			var event map[string]any
			if err := json.Unmarshal(logs.Bytes(), &event); err != nil {
				t.Fatalf("invalid error log %s: %v", logs.String(), err)
			}
			if event["request_id"] != id || event["method"] != tc.method || event["status"] != float64(500) || !strings.Contains(fmt.Sprint(event["error"]), "database is closed") || event["route"] == "" {
				t.Fatalf("missing error log context: %#v", event)
			}
			if !strings.Contains(access.String(), "request_id="+id) {
				t.Fatalf("request ID missing from access log: %s", access.String())
			}
			for _, secret := range []string{"private-password", "private-bearer", "private-cookie", "private-search"} {
				if strings.Contains(logs.String()+access.String(), secret) {
					t.Errorf("logs leaked %q", secret)
				}
			}
		})
	}
}

func TestConfigInternalFailuresAreNotEmbeddedInSuccessfulResponses(t *testing.T) {
	for _, kind := range []string{"read validation", "read import", "database import", "glob validation"} {
		t.Run(kind, func(t *testing.T) {
			server := newTestServer(t, "secret")
			var logs bytes.Buffer
			server.logger = slog.New(slog.NewJSONHandler(&logs, nil))
			dir := filepath.Join(server.configDir, "resources")
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := "/api/v1/config/validate"
			cause := "is a directory"
			if kind == "database import" {
				if err := os.WriteFile(filepath.Join(dir, "valid.json"), []byte(`{"id":"valid","name":"Valid","domains":[{"host":"example.org"}]}`), 0600); err != nil {
					t.Fatal(err)
				}
				if err := server.store.Close(); err != nil {
					t.Fatal(err)
				}
				cause = "database is closed"
			} else if kind == "glob validation" {
				server.configDir = filepath.Join(server.configDir, "[")
				cause = "syntax error in pattern"
			} else {
				if err := os.Mkdir(filepath.Join(dir, "unreadable.json"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if strings.Contains(kind, "import") {
				path = "/api/v1/config/import"
			}
			req := httptest.NewRequest("POST", path, nil)
			req.Header.Set("Authorization", "Bearer secret")
			rec := httptest.NewRecorder()
			server.Routes().ServeHTTP(rec, req)
			id := assertInternalResponse(t, rec, 500, false, server.configDir, "unreadable.json", cause)
			if !strings.Contains(logs.String(), cause) || !strings.Contains(logs.String(), id) {
				t.Fatalf("internal cause or request ID missing: %s", logs.String())
			}
		})
	}
}

func TestSafeValidationErrorsRemainUseful(t *testing.T) {
	server := newTestServer(t, "secret")
	createLocalTestUser(t, server, "existing", "valid-password")
	handler := server.Routes()
	for _, tc := range []struct {
		path, body, message string
		status              int
	}{
		{"/api/v1/resources", "{", "invalid JSON body", 400},
		{"/api/v1/resources", `{}`, "resource id is required", 400},
		{"/api/v1/api-keys", `{}`, "api key name is required", 400},
		{"/api/v1/users", `{"username":"new","password":"` + strings.Repeat("x", 73) + `"}`, "password must be at most 72 bytes", 400},
		{"/api/v1/users", `{"username":"existing","password":"valid-password"}`, "user already exists", 409},
	} {
		t.Run(tc.message, func(t *testing.T) {
			req := httptest.NewRequest("POST", tc.path, strings.NewReader(tc.body))
			req.Header.Set("Authorization", "Bearer secret")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.status || !strings.Contains(rec.Body.String(), tc.message) || strings.Contains(rec.Body.String(), "UNIQUE") || rec.Header().Get("X-Request-ID") == "" {
				t.Fatalf("unsafe or unhelpful validation: %d %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestUnexpectedCreationErrorsAreNotValidationErrors(t *testing.T) {
	server := newTestServer(t, "secret")
	req := httptest.NewRequest("POST", "/api/v1/users", nil)
	rec := httptest.NewRecorder()
	server.validationError(rec, req, internalFailure{fmt.Errorf("generate credentials: %w", errors.New("private generator failure"))})
	assertInternalResponse(t, rec, 500, false, "private generator failure")
}

func TestUpstreamErrorsHaveSafeResponsesAndLogs(t *testing.T) {
	for _, path := range []string{"/odo/https/www.jstor.org/search?query=patron-secret", "/api/v1/proxy/test-fetch"} {
		t.Run(path, func(t *testing.T) {
			server := newTestServer(t, "secret")
			if err := server.store.UpsertResource(resources.Resource{
				ID: "jstor", Name: "JSTOR", Status: "active", Domains: []resources.DomainRule{{Host: "www.jstor.org", Match: "exact"}},
			}); err != nil {
				t.Fatal(err)
			}
			var logs bytes.Buffer
			server.logger = slog.New(slog.NewJSONHandler(&logs, nil))
			server.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return nil, errors.New("dial private-backend: connection refused")
			})}
			method, body := "GET", ""
			if strings.HasPrefix(path, "/api/") {
				method, body = "POST", `{"url":"https://www.jstor.org/search?query=patron-secret"}`
			}
			req := httptest.NewRequest(method, path, strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer secret")
			req.Header.Set("Cookie", "private-cookie=credential")
			rec := httptest.NewRecorder()
			server.Routes().ServeHTTP(rec, req)
			id := assertInternalResponse(t, rec, 502, false, "private-backend", "patron-secret", "connection refused")
			if !strings.Contains(logs.String(), "connection refused") || !strings.Contains(logs.String(), id) {
				t.Fatalf("missing upstream cause: %s", logs.String())
			}
			for _, secret := range []string{"patron-secret", "private-cookie", "https://www.jstor.org/search", "Bearer"} {
				if strings.Contains(logs.String(), secret) {
					t.Errorf("log leaked %q", secret)
				}
			}
		})
	}
}

func TestRequestIDsOnSuccessAndFailure(t *testing.T) {
	server := newTestServer(t, "secret")
	handler := server.Routes()
	seen := map[string]bool{}
	for _, path := range []string{"/api/v1/health", "/api/v1/resources", "/login", "/missing"} {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("X-Request-ID", "unsafe\nlog-injection")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		id := rec.Header().Get("X-Request-ID")
		if !strings.HasPrefix(id, "req_") || seen[id] {
			t.Fatalf("missing/duplicate generated ID: %q", id)
		}
		seen[id] = true
	}
}
