package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"example.org/odo/internal/db"
)

func TestImportResourcesImportsValidFilesAndReportsInvalidFiles(t *testing.T) {
	configDir := t.TempDir()
	resourcesDir := filepath.Join(configDir, "resources")
	if err := os.MkdirAll(resourcesDir, 0o755); err != nil {
		t.Fatalf("create resources dir: %v", err)
	}

	valid := `{
  "id": "jstor",
  "name": "JSTOR",
  "domains": [
    {"host": "www.jstor.org"},
    {"host": "jstor.org", "match": "subdomain"}
  ],
  "sample_urls": ["https://www.jstor.org/stable/example"]
}`
	invalid := `{"id":"broken","domains":[{"host":"example.org"}]}`

	if err := os.WriteFile(filepath.Join(resourcesDir, "jstor.json"), []byte(valid), 0o644); err != nil {
		t.Fatalf("write valid config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(resourcesDir, "broken.json"), []byte(invalid), 0o644); err != nil {
		t.Fatalf("write invalid config: %v", err)
	}

	store := openTempStore(t)
	defer store.Close()

	results, err := ImportResources(store, configDir)
	if err != nil {
		t.Fatalf("ImportResources returned error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected two import results, got %d: %#v", len(results), results)
	}

	var imported, failed bool
	for _, result := range results {
		switch filepath.Base(result.File) {
		case "jstor.json":
			imported = true
			if !result.Imported {
				t.Fatalf("expected jstor import to succeed: %#v", result)
			}
			if result.ResourceID != "jstor" {
				t.Fatalf("expected jstor resource id, got %q", result.ResourceID)
			}
		case "broken.json":
			failed = true
			if result.Imported {
				t.Fatalf("expected broken import to fail: %#v", result)
			}
			if result.Error == "" {
				t.Fatalf("expected broken import to include error: %#v", result)
			}
		default:
			t.Fatalf("unexpected import result file: %#v", result)
		}
	}
	if !imported || !failed {
		t.Fatalf("expected one imported and one failed result: %#v", results)
	}

	resources, err := store.ListResources()
	if err != nil {
		t.Fatalf("list resources: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected one persisted resource, got %d: %#v", len(resources), resources)
	}
	if resources[0].ID != "jstor" || resources[0].Status != "active" {
		t.Fatalf("unexpected persisted resource: %#v", resources[0])
	}
}

func TestImportResourcesReturnsEmptyResultsWhenNoFilesExist(t *testing.T) {
	configDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(configDir, "resources"), 0o755); err != nil {
		t.Fatalf("create resources dir: %v", err)
	}

	store := openTempStore(t)
	defer store.Close()

	results, err := ImportResources(store, configDir)
	if err != nil {
		t.Fatalf("ImportResources returned error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected no results, got %#v", results)
	}
}

func TestValidateResourcesReturnsValidResultsWithoutWritingToDatabase(t *testing.T) {
	configDir := t.TempDir()
	writeResourceConfig(t, configDir, "jstor.json", `{
  "id": "jstor",
  "name": "JSTOR",
  "domains": [{"host": "www.jstor.org"}]
}`)

	store := openTempStore(t)
	defer store.Close()

	response, err := ValidateResources(configDir)
	if err != nil {
		t.Fatalf("ValidateResources returned error: %v", err)
	}
	if !response.Valid {
		t.Fatalf("expected validation to succeed: %#v", response)
	}
	if response.ConfigDir != configDir {
		t.Fatalf("expected config dir %q, got %q", configDir, response.ConfigDir)
	}
	if len(response.Results) != 1 {
		t.Fatalf("expected one result, got %#v", response.Results)
	}
	if !response.Results[0].Valid || response.Results[0].ResourceID != "jstor" {
		t.Fatalf("unexpected validation result: %#v", response.Results[0])
	}

	resources, err := store.ListResources()
	if err != nil {
		t.Fatalf("list resources: %v", err)
	}
	if len(resources) != 0 {
		t.Fatalf("expected validation not to write resources, got %#v", resources)
	}
}

func TestValidateResourcesReturnsInvalidResults(t *testing.T) {
	configDir := t.TempDir()
	writeResourceConfig(t, configDir, "bad.json", `{
  "id": "",
  "name": "",
  "domains": []
}`)

	response, err := ValidateResources(configDir)
	if err != nil {
		t.Fatalf("ValidateResources returned error: %v", err)
	}
	if response.Valid {
		t.Fatalf("expected validation to fail: %#v", response)
	}
	if len(response.Results) != 1 {
		t.Fatalf("expected one result, got %#v", response.Results)
	}
	result := response.Results[0]
	if result.Valid {
		t.Fatalf("expected result to be invalid: %#v", result)
	}
	if !containsError(result.Errors, "resource id is required") {
		t.Fatalf("expected missing id error, got %#v", result.Errors)
	}
	if !containsError(result.Errors, "resource name is required") {
		t.Fatalf("expected missing name error, got %#v", result.Errors)
	}
	if !containsError(result.Errors, "at least one domain is required") {
		t.Fatalf("expected missing domain error, got %#v", result.Errors)
	}
}

func TestValidateResourcesRejectsUnsafeDomains(t *testing.T) {
	configDir := t.TempDir()
	writeResourceConfig(t, configDir, "unsafe.json", `{
  "id": "unsafe",
  "name": "Unsafe",
  "domains": [
    {"host": "https://example.org"},
    {"host": "example.org/path"},
    {"host": "*.example.org"},
    {"host": "localhost"},
    {"host": "192.0.2.10"}
  ]
}`)

	response, err := ValidateResources(configDir)
	if err != nil {
		t.Fatalf("ValidateResources returned error: %v", err)
	}
	if response.Valid {
		t.Fatalf("expected unsafe config to be invalid: %#v", response)
	}
	errors := response.Results[0].Errors
	expected := []string{
		"must not contain a scheme",
		"must not contain path slashes",
		"must not contain wildcards",
		"must not be localhost",
		"must not be an IP address",
	}
	for _, want := range expected {
		if !containsError(errors, want) {
			t.Fatalf("expected error containing %q, got %#v", want, errors)
		}
	}
}

func TestImportResourcesStillWorksAfterValidationChanges(t *testing.T) {
	configDir := t.TempDir()
	writeResourceConfig(t, configDir, "jstor.json", `{
  "id": "jstor",
  "name": "JSTOR",
  "domains": [{"host": "www.jstor.org"}]
}`)

	store := openTempStore(t)
	defer store.Close()

	results, err := ImportResources(store, configDir)
	if err != nil {
		t.Fatalf("ImportResources returned error: %v", err)
	}
	if len(results) != 1 || !results[0].Imported {
		t.Fatalf("expected import to succeed, got %#v", results)
	}

	resources, err := store.ListResources()
	if err != nil {
		t.Fatalf("list resources: %v", err)
	}
	if len(resources) != 1 || resources[0].ID != "jstor" {
		t.Fatalf("expected imported jstor resource, got %#v", resources)
	}
}

func openTempStore(t *testing.T) *db.Store {
	t.Helper()

	store, err := db.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatalf("open temp store: %v", err)
	}
	if err := store.Migrate(); err != nil {
		store.Close()
		t.Fatalf("migrate temp store: %v", err)
	}
	return store
}

func writeResourceConfig(t *testing.T, configDir, name, body string) {
	t.Helper()

	resourcesDir := filepath.Join(configDir, "resources")
	if err := os.MkdirAll(resourcesDir, 0o755); err != nil {
		t.Fatalf("create resources dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(resourcesDir, name), []byte(body), 0o644); err != nil {
		t.Fatalf("write config %s: %v", name, err)
	}
}

func containsError(errors []string, want string) bool {
	for _, err := range errors {
		if strings.Contains(err, want) {
			return true
		}
	}
	return false
}
