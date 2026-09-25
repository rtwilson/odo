package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"example.org/odo/internal/resources"
)

const resourceImportJSON = `{"id":"import-demo","title":"Import Demo","status":"active","entry_urls":["https://example.org/"],"domains":[{"host":"example.org","behavior":"proxy"}]}`

func TestResourceJSONReviewAndPublish(t *testing.T) {
	server := newTestServer(t, "secret")
	handler := server.Routes()
	request := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer secret")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	preview := request("POST", "/api/v1/resources/validate", resourceImportJSON)
	if preview.Code != 200 {
		t.Fatalf("preview: %d %s", preview.Code, preview.Body.String())
	}
	var validation resources.ValidationResult
	if err := json.Unmarshal(preview.Body.Bytes(), &validation); err != nil {
		t.Fatal(err)
	}
	if !validation.Valid || validation.Normalized.ID != "import-demo" {
		t.Fatalf("invalid preview: %#v", validation)
	}
	if rec := request("GET", "/api/v1/resources/import-demo", ""); rec.Code != 404 {
		t.Fatalf("preview wrote resource: %d", rec.Code)
	}
	payload, err := json.Marshal(validation.Normalized)
	if err != nil {
		t.Fatal(err)
	}
	if rec := request("POST", "/api/v1/resources", string(payload)); rec.Code != 200 {
		t.Fatalf("publish: %d %s", rec.Code, rec.Body.String())
	}
	if rec := request("GET", "/api/v1/resources/import-demo", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Import Demo") {
		t.Fatalf("existing resource detection: %d %s", rec.Code, rec.Body.String())
	}
	updated := strings.ReplaceAll(resourceImportJSON, "Import Demo", "Updated Import")
	if rec := request("POST", "/api/v1/resources/validate", updated); rec.Code != 200 {
		t.Fatalf("update validation: %s", rec.Body.String())
	}
	if rec := request("GET", "/api/v1/resources/import-demo", ""); strings.Contains(rec.Body.String(), "Updated Import") {
		t.Fatal("update preview changed saved resource")
	}
	if rec := request("PUT", "/api/v1/resources/import-demo", updated); rec.Code != 200 {
		t.Fatalf("update: %d %s", rec.Code, rec.Body.String())
	}
	if rec := request("GET", "/api/v1/resources", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Updated Import") {
		t.Fatalf("list after import: %d %s", rec.Code, rec.Body.String())
	}
	events, err := server.store.ListAuditEvents(100)
	if err != nil {
		t.Fatal(err)
	}
	writes := 0
	for _, event := range events {
		if event.Event == "resource.upsert" {
			writes++
		}
		if strings.Contains(event.Detail, "https://example.org/") {
			t.Fatal("audit contains pasted resource content")
		}
	}
	if writes != 2 {
		t.Fatalf("expected only create/update audit events, got %d", writes)
	}
}

func TestResourceJSONBodyLimitsAndSyntax(t *testing.T) {
	for _, route := range []struct{ method, path string }{
		{"POST", "/api/v1/resources/validate"}, {"POST", "/api/v1/resources"}, {"PUT", "/api/v1/resources/import-demo"},
	} {
		t.Run(route.method+route.path, func(t *testing.T) {
			server := newTestServer(t, "secret")
			handler := server.Routes()
			for _, tc := range []struct {
				name, payload string
				status        int
			}{
				{"exact byte limit", resourceImportJSON + strings.Repeat(" ", maxResourceJSONBytes-len(resourceImportJSON)), 200},
				{"over limit including trailing whitespace", resourceImportJSON + strings.Repeat(" ", maxResourceJSONBytes-len(resourceImportJSON)+1), 413},
				{"large value", `{"description":"` + strings.Repeat("x", maxResourceJSONBytes) + `"}`, 413},
				{"malformed", `{"id":`, 400},
				{"two objects", resourceImportJSON + `{}`, 400},
				{"array", `[` + resourceImportJSON + `]`, 400},
				{"invalid domain", strings.ReplaceAll(resourceImportJSON, `"host":"example.org"`, `"host":"localhost"`), 400},
			} {
				t.Run(tc.name, func(t *testing.T) {
					req := httptest.NewRequest(route.method, route.path, strings.NewReader(tc.payload))
					req.ContentLength = -1 // Also enforce limits on streamed/chunked bodies.
					req.Header.Set("Authorization", "Bearer secret")
					rec := httptest.NewRecorder()
					handler.ServeHTTP(rec, req)
					if rec.Code != tc.status {
						t.Fatalf("got %d want %d: %s", rec.Code, tc.status, rec.Body.String())
					}
					if tc.status == 413 && !strings.Contains(rec.Body.String(), "at most 1 MiB") {
						t.Fatal("missing useful size error")
					}
					if tc.name == "invalid domain" && (!strings.Contains(rec.Body.String(), "domains") || !strings.Contains(rec.Body.String(), "localhost")) {
						t.Fatalf("missing field validation: %s", rec.Body.String())
					}
				})
			}
		})
	}
}

func TestResourceImportRequiresScopesAndCSRF(t *testing.T) {
	server := newTestServer(t, "secret")
	createLocalTestUserWithRoles(t, server, "resource-admin", "correct-password", []string{"resource_admin"})
	cookie, csrf := loginTestUserWithCSRF(t, server, "resource-admin", "correct-password", "/admin")
	readToken, _ := createTestAPIKey(t, server, "secret", []string{"resources:read"})
	handler := server.Routes()
	for _, route := range []struct{ method, path string }{
		{"POST", "/api/v1/resources/validate"}, {"POST", "/api/v1/resources"}, {"PUT", "/api/v1/resources/import-demo"},
	} {
		for _, tc := range []struct {
			name        string
			session     bool
			csrf, token string
			status      int
		}{
			{"anonymous", false, "", "", 401},
			{"read-only API key", false, "", readToken, 403},
			{"session without CSRF", true, "", "", 403},
			{"session with wrong CSRF", true, "wrong", "", 403},
			{"session with CSRF", true, csrf, "", 200},
		} {
			t.Run(route.path+tc.name, func(t *testing.T) {
				req := httptest.NewRequest(route.method, route.path, strings.NewReader(resourceImportJSON))
				if tc.session {
					req.AddCookie(cookie)
				}
				if tc.csrf != "" {
					req.Header.Set("X-Odo-CSRF", tc.csrf)
				}
				if tc.token != "" {
					req.Header.Set("Authorization", "Bearer "+tc.token)
				}
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code != tc.status {
					t.Fatalf("got %d want %d: %s", rec.Code, tc.status, rec.Body.String())
				}
			})
		}
	}
}

func TestResourceReviewControlsAreAvailable(t *testing.T) {
	server := newTestServer(t, "secret")
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	for _, want := range []string{
		`accept=".json,application/json" multiple`, `id="resource-preview"`, `id="confirm-resource-publish" type="checkbox" disabled`,
		`id="save-resource" disabled`, `id="resource-advanced" hidden`, "Resource repositories — planned", "This will update existing resource:",
		"This will create a new resource:", "JSON that will be saved", "Domain count", "Warnings", "Errors", "Pending review", "X-Odo-CSRF",
	} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("missing UI control %q", want)
		}
	}
}
