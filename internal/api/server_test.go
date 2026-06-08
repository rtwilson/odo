package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"example.org/odo/internal/accesslog"
	"example.org/odo/internal/db"
	"example.org/odo/internal/proxy"
	"example.org/odo/internal/resources"
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

func TestOpenAPIYAML(t *testing.T) {
	server := newTestServer(t, "secret")

	req := httptest.NewRequest(http.MethodGet, "/openapi.yaml", nil)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected openapi.yaml to return 200, got %d with body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "openapi: 3.1.0") {
		t.Fatalf("expected OpenAPI 3.1 marker in response, got %q", rec.Body.String())
	}
}

func TestPrivacyAccessLogForProxyStubUsesSafeMetadata(t *testing.T) {
	var logs bytes.Buffer
	accessLogger, err := accesslog.New(accesslog.FormatPrivacy, &logs)
	if err != nil {
		t.Fatalf("create access logger: %v", err)
	}
	server := newTestServerWithConfigAndAccessLog(t, "", t.TempDir(), accessLogger)
	if err := server.store.UpsertResource(resources.Resource{
		ID:     "jstor",
		Name:   "JSTOR",
		Status: "active",
		Domains: []resources.DomainRule{
			{Host: "www.jstor.org", Match: "exact"},
		},
	}); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/p?url=https://www.jstor.org/stable/example", nil)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected proxy stub to return 200, got %d with body %s", rec.Code, rec.Body.String())
	}
	line := logs.String()
	if strings.Contains(line, "https://www.jstor.org/stable/example") || strings.Contains(line, "?url=") {
		t.Fatalf("privacy proxy log leaked full target URL: %q", line)
	}
	for _, want := range []string{"route=/p", "target_host=www.jstor.org", "resource_id=jstor", "decision=allowed"} {
		if !strings.Contains(line, want) {
			t.Fatalf("expected proxy access log to contain %q, got %q", want, line)
		}
	}
}

func TestProxyStubAllowsSafeMatchedURLWithPublicDNS(t *testing.T) {
	server := newTestServerWithResolver(t, "", t.TempDir(), func(ctx context.Context, host string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
	})
	if err := server.store.UpsertResource(resources.Resource{
		ID:      "jstor",
		Name:    "JSTOR",
		Status:  "active",
		Domains: []resources.DomainRule{{Host: "www.jstor.org", Match: "exact"}},
	}); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/p?url=https://www.jstor.org/stable/example", nil)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected safe matched proxy URL to return 200, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestProxyStubRejectsPrivateResolvedIP(t *testing.T) {
	server := newTestServerWithResolver(t, "", t.TempDir(), func(ctx context.Context, host string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	})

	req := httptest.NewRequest(http.MethodGet, "/p?url=https://www.jstor.org/stable/example", nil)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected private resolved proxy URL to return 403, got %d with body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "target URL is not allowed") || !strings.Contains(rec.Body.String(), "hostname resolves to private IP") {
		t.Fatalf("expected safe denial response, got %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "https://www.jstor.org/stable/example") {
		t.Fatalf("denial response leaked full target URL: %s", rec.Body.String())
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

	revisions, err := server.store.ListConfigRevisions(10)
	if err != nil {
		t.Fatalf("list revisions after validation: %v", err)
	}
	if len(revisions) != 0 {
		t.Fatalf("validation endpoint should not create revisions, got %#v", revisions)
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

func TestConfigRevisionEndpointsReturnListAndDetail(t *testing.T) {
	configDir := t.TempDir()
	writeAPIResourceConfig(t, configDir, "jstor.json", `{
  "id": "jstor",
  "name": "JSTOR",
  "domains": [{"host": "www.jstor.org"}]
}`)
	server := newTestServerWithConfig(t, "secret", configDir)

	importReq := httptest.NewRequest(http.MethodPost, "/api/v1/config/import", nil)
	importReq.Header.Set("Authorization", "Bearer secret")
	importRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(importRec, importReq)
	if importRec.Code != http.StatusOK {
		t.Fatalf("expected import to return 200, got %d with body %s", importRec.Code, importRec.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/config/revisions", nil)
	listReq.Header.Set("Authorization", "Bearer secret")
	listRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("expected revision list to return 200, got %d with body %s", listRec.Code, listRec.Body.String())
	}

	var listBody struct {
		Revisions []map[string]any `json:"revisions"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &listBody); err != nil {
		t.Fatalf("decode revision list: %v", err)
	}
	if len(listBody.Revisions) != 1 {
		t.Fatalf("expected one revision in list, got %#v", listBody)
	}
	if _, exists := listBody.Revisions[0]["config_json"]; exists {
		t.Fatalf("revision list should not include config_json: %#v", listBody.Revisions[0])
	}
	id, ok := listBody.Revisions[0]["id"].(float64)
	if !ok || id <= 0 {
		t.Fatalf("expected numeric revision id, got %#v", listBody.Revisions[0]["id"])
	}

	detailReq := httptest.NewRequest(http.MethodGet, "/api/v1/config/revisions/"+strconv.FormatInt(int64(id), 10), nil)
	detailReq.Header.Set("Authorization", "Bearer secret")
	detailRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(detailRec, detailReq)
	if detailRec.Code != http.StatusOK {
		t.Fatalf("expected revision detail to return 200, got %d with body %s", detailRec.Code, detailRec.Body.String())
	}

	var detailBody map[string]any
	if err := json.Unmarshal(detailRec.Body.Bytes(), &detailBody); err != nil {
		t.Fatalf("decode revision detail: %v", err)
	}
	if detailBody["config_json"] == "" {
		t.Fatalf("revision detail should include config_json: %#v", detailBody)
	}
}

func TestConfigRevisionEndpointsRequireAPIKey(t *testing.T) {
	server := newTestServer(t, "secret")

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/config/revisions", nil)
	listRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected revision list without API key to return 401, got %d with body %s", listRec.Code, listRec.Body.String())
	}

	detailReq := httptest.NewRequest(http.MethodGet, "/api/v1/config/revisions/1", nil)
	detailRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(detailRec, detailReq)
	if detailRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected revision detail without API key to return 401, got %d with body %s", detailRec.Code, detailRec.Body.String())
	}
}

func newTestServer(t *testing.T, adminKey string) *Server {
	return newTestServerWithConfig(t, adminKey, t.TempDir())
}

func newTestServerWithConfig(t *testing.T, adminKey, configDir string) *Server {
	accessLogger, err := accesslog.New(accesslog.FormatPrivacy, io.Discard)
	if err != nil {
		t.Fatalf("create access logger: %v", err)
	}
	return newTestServerWithConfigAndAccessLog(t, adminKey, configDir, accessLogger)
}

func newTestServerWithConfigAndAccessLog(t *testing.T, adminKey, configDir string, accessLogger *accesslog.Logger) *Server {
	return newTestServerWithConfigAccessLogAndResolver(t, adminKey, configDir, accessLogger, publicTestResolver)
}

func newTestServerWithResolver(t *testing.T, adminKey, configDir string, lookup proxy.IPLookupFunc) *Server {
	accessLogger, err := accesslog.New(accesslog.FormatPrivacy, io.Discard)
	if err != nil {
		t.Fatalf("create access logger: %v", err)
	}
	return newTestServerWithConfigAccessLogAndResolver(t, adminKey, configDir, accessLogger, lookup)
}

func newTestServerWithConfigAccessLogAndResolver(t *testing.T, adminKey, configDir string, accessLogger *accesslog.Logger, lookup proxy.IPLookupFunc) *Server {
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
	return NewServerWithAccessLoggerAndResolver(store, configDir, adminKey, logger, accessLogger, lookup)
}

func publicTestResolver(ctx context.Context, host string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
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
