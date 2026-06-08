package config

import (
	"os"
	"path/filepath"
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
