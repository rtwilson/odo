package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"example.org/odo/internal/db"
)

func TestHealthDoesNotRequireAPIKey(t *testing.T) {
	server := newTestServer(t, "secret")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected public health endpoint to return 200, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestManagementEndpointWorksWithoutConfiguredAPIKey(t *testing.T) {
	server := newTestServer(t, "")
	body := bytes.NewBufferString(`{
  "id": "jstor",
  "name": "JSTOR",
  "domains": [{"host": "www.jstor.org"}]
}`)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/resources", body)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected unset API key to allow dev management request, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestManagementEndpointAllowsValidAPIKey(t *testing.T) {
	server := newTestServer(t, "secret")
	body := bytes.NewBufferString(`{
  "id": "jstor",
  "name": "JSTOR",
  "domains": [{"host": "www.jstor.org"}]
}`)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/resources", body)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected valid API key to return 200, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestManagementEndpointRejectsMissingAPIKey(t *testing.T) {
	server := newTestServer(t, "secret")
	body := bytes.NewBufferString(`{"id":"jstor","name":"JSTOR"}`)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/resources", body)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected missing API key to return 401, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestManagementEndpointRejectsInvalidAPIKey(t *testing.T) {
	server := newTestServer(t, "secret")
	body := bytes.NewBufferString(`{"id":"jstor","name":"JSTOR"}`)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/resources", body)
	req.Header.Set("Authorization", "Bearer wrong")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected invalid API key to return 403, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigImportRequiresAPIKey(t *testing.T) {
	server := newTestServer(t, "secret")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/import", nil)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected config import without API key to return 401, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestValidateConfigEndpointSucceedsWithValidConfig(t *testing.T) {
	configDir := t.TempDir()
	writeAPIResourceConfig(t, configDir, "jstor.json", `{
  "id": "jstor",
  "name": "JSTOR",
  "domains": [{"host": "www.jstor.org"}]
}`)
	server := newTestServerWithConfig(t, "secret", configDir)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/validate", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected validation endpoint to return 200, got %d with body %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Valid   bool `json:"valid"`
		Results []struct {
			Valid      bool   `json:"valid"`
			ResourceID string `json:"resource_id"`
		} `json:"results"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode validation response: %v", err)
	}
	if !body.Valid || len(body.Results) != 1 || !body.Results[0].Valid || body.Results[0].ResourceID != "jstor" {
		t.Fatalf("unexpected validation response: %#v", body)
	}
}

func TestValidateConfigEndpointReturnsInvalidConfig(t *testing.T) {
	configDir := t.TempDir()
	writeAPIResourceConfig(t, configDir, "bad.json", `{
  "id": "",
  "name": "Bad",
  "domains": []
}`)
	server := newTestServerWithConfig(t, "secret", configDir)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/validate", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected validation endpoint to return 200, got %d with body %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Valid   bool `json:"valid"`
		Results []struct {
			Valid  bool     `json:"valid"`
			Errors []string `json:"errors"`
		} `json:"results"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode validation response: %v", err)
	}
	if body.Valid || len(body.Results) != 1 || body.Results[0].Valid || len(body.Results[0].Errors) == 0 {
		t.Fatalf("unexpected validation response: %#v", body)
	}
}

func TestValidateConfigEndpointRequiresAPIKey(t *testing.T) {
	server := newTestServer(t, "secret")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/validate", nil)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected validate config without API key to return 401, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func newTestServer(t *testing.T, adminKey string) *Server {
	return newTestServerWithConfig(t, adminKey, t.TempDir())
}

func newTestServerWithConfig(t *testing.T, adminKey, configDir string) *Server {
	t.Helper()

	store, err := db.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatalf("open temp store: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close temp store: %v", err)
		}
	})
	if err := store.Migrate(); err != nil {
		t.Fatalf("migrate temp store: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewServer(store, configDir, adminKey, logger)
}

func writeAPIResourceConfig(t *testing.T, configDir, name, body string) {
	t.Helper()

	resourcesDir := filepath.Join(configDir, "resources")
	if err := os.MkdirAll(resourcesDir, 0o755); err != nil {
		t.Fatalf("create resources dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(resourcesDir, name), []byte(body), 0o644); err != nil {
		t.Fatalf("write config %s: %v", name, err)
	}
}
