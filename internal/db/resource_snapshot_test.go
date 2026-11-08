package db

import (
	"encoding/json"
	"math"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"example.org/odo/internal/resources"
)

func TestResourceSnapshotTracksChangesAndReversions(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "odo.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(); err != nil {
		t.Fatal(err)
	}
	empty, err := store.ResourceSnapshot()
	if err != nil || empty.Revision != 0 || len(empty.Resources) != 0 {
		t.Fatalf("incorrect initial snapshot: %v", err)
	}
	original := resources.Resource{ID: "vendor", Name: "Vendor", Domains: []resources.DomainRule{{Host: "vendor.example"}}, CookiePolicy: resources.CookiePolicy{Enabled: true}}
	cookieless, disabled := original, original
	cookieless.CookiePolicy.Enabled = false
	disabled.Status = "disabled"
	want, err := resources.Validate(original)
	if err != nil {
		t.Fatal(err)
	}
	// Include an identical write, cookie-policy reversion, and disable/enable.
	for i, item := range []resources.Resource{original, original, cookieless, original, disabled, original} {
		if err := store.UpsertResource(item); err != nil {
			t.Fatal(err)
		}
		snapshot, err := store.ResourceSnapshot()
		if err != nil || snapshot.Revision != int64(i+1) || len(snapshot.Resources) != 1 || snapshot.Resources[0].CookiePolicy.Enabled != item.CookiePolicy.Enabled {
			t.Fatalf("resource change %d lost its revision or policy: %v", i, err)
		}
	}
	reverted, err := store.ResourceSnapshot()
	if err != nil || !reflect.DeepEqual(reverted.Resources, []resources.Resource{want}) {
		t.Fatal("reversion did not restore the original resource")
	}
	if deleted, err := store.DeleteResource(original.ID); err != nil || !deleted {
		t.Fatalf("delete failed: %v", err)
	}
	deleted, err := store.ResourceSnapshot()
	if err != nil || deleted.Revision != 7 || len(deleted.Resources) != 0 {
		t.Fatal("deletion did not advance the revision")
	}
	if deleted, err := store.DeleteResource(original.ID); err != nil || deleted {
		t.Fatal("missing deletion changed behavior")
	}
	if err := store.UpsertResource(resources.Resource{}); err == nil {
		t.Fatal("invalid resource accepted")
	}
	unchanged, err := store.ResourceSnapshot()
	if err != nil || !reflect.DeepEqual(unchanged, deleted) {
		t.Fatal("no-op or rejected write advanced the revision")
	}
	if err := store.UpsertResource(original); err != nil {
		t.Fatal(err)
	}
	recreated, err := store.ResourceSnapshot()
	if err != nil || recreated.Revision != 8 || !reflect.DeepEqual(recreated.Resources, reverted.Resources) {
		t.Fatal("delete/recreate lost the intervening changes")
	}
}

func TestResourceSnapshotMigrationAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "odo.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	// Simulate a pre-revision database containing an existing resource.
	if _, err := store.db.Exec(`CREATE TABLE resources (id TEXT PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL, config_json TEXT NOT NULL, updated_at TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	item := resources.Resource{ID: "existing", Name: "Existing", Status: "active", Domains: []resources.DomainRule{{Host: "vendor.example"}}}
	payload, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`INSERT INTO resources VALUES (?, ?, ?, ?, ?)`, item.ID, item.Name, item.Status, string(payload), "original-time"); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(); err != nil {
		t.Fatal(err)
	}
	initial, err := store.ResourceSnapshot()
	if err != nil || initial.Revision != 0 || len(initial.Resources) != 1 || initial.Resources[0].ID != item.ID {
		t.Fatal("migration lost pre-existing configuration")
	}
	if err := store.UpsertResource(item); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(); err != nil {
		t.Fatal(err)
	}
	before, err := store.ResourceSnapshot()
	if err != nil || before.Revision != 1 {
		t.Fatal("repeated migration reset the revision")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := reopened.Migrate(); err != nil {
		t.Fatal(err)
	}
	after, err := reopened.ResourceSnapshot()
	if err != nil || !reflect.DeepEqual(after, before) {
		t.Fatal("restart changed configuration or revision")
	}
}

func TestResourceRevisionFailureRollsBackWrites(t *testing.T) {
	for _, failure := range []string{"missing", "exhausted"} {
		t.Run(failure, func(t *testing.T) {
			store, err := Open(filepath.Join(t.TempDir(), "odo.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			if err := store.Migrate(); err != nil {
				t.Fatal(err)
			}
			item := resources.Resource{ID: "vendor", Name: "Vendor", Domains: []resources.DomainRule{{Host: "vendor.example"}}}
			if err := store.UpsertResource(item); err != nil {
				t.Fatal(err)
			}
			before, err := store.ListResources()
			if err != nil {
				t.Fatal(err)
			}
			events, err := store.ListAuditEvents(10)
			if err != nil {
				t.Fatal(err)
			}
			if failure == "missing" {
				_, err = store.db.Exec(`DELETE FROM resource_state`)
			} else {
				_, err = store.db.Exec(`UPDATE resource_state SET revision = ?`, int64(math.MaxInt64))
			}
			if err != nil {
				t.Fatal(err)
			}
			item.CookiePolicy.Enabled = true
			if err := store.UpsertResource(item); err == nil {
				t.Fatal("write succeeded without a new revision")
			}
			if deleted, err := store.DeleteResource(item.ID); err == nil || deleted {
				t.Fatal("delete succeeded without a new revision")
			}
			after, err := store.ListResources()
			if err != nil || !reflect.DeepEqual(after, before) {
				t.Fatal("failed revision update changed resources")
			}
			afterEvents, err := store.ListAuditEvents(10)
			if err != nil || !reflect.DeepEqual(afterEvents, events) {
				t.Fatal("failed revision update changed audits")
			}
			snapshot, err := store.ResourceSnapshot()
			if failure == "missing" {
				if err == nil || snapshot.Revision != 0 || snapshot.Resources != nil {
					t.Fatal("missing revision returned usable configuration")
				}
			} else if err != nil || snapshot.Revision != math.MaxInt64 {
				t.Fatal("counter wrapped at exhaustion")
			}
		})
	}
}

func TestResourceSnapshotReadFailureReturnsNoConfiguration(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "odo.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "z"} {
		if err := store.UpsertResource(resources.Resource{ID: id, Name: id, Domains: []resources.DomainRule{{Host: "vendor.example"}}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.db.Exec(`UPDATE resources SET config_json = 'invalid-json' WHERE id = 'z'`); err != nil {
		t.Fatal(err)
	}
	if snapshot, err := store.ResourceSnapshot(); err == nil || snapshot.Revision != 0 || snapshot.Resources != nil {
		t.Fatal("invalid configuration returned a partial snapshot")
	}
	if _, err := store.db.Exec(`ALTER TABLE resources RENAME TO unavailable_resources`); err != nil {
		t.Fatal(err)
	}
	if snapshot, err := store.ResourceSnapshot(); err == nil || snapshot.Revision != 0 || snapshot.Resources != nil {
		t.Fatal("query failure returned a revision without resources")
	}
}

func TestResourceSnapshotConcurrentWriterConsistency(t *testing.T) {
	path := filepath.Join(t.TempDir(), "odo.db")
	reader, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	if err := reader.Migrate(); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.db.Exec(`PRAGMA journal_mode = WAL`); err != nil {
		t.Fatal(err)
	}
	writer, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	for _, store := range []*Store{reader, writer} {
		store.db.SetMaxOpenConns(1)
		if _, err := store.db.Exec(`PRAGMA busy_timeout = 3000`); err != nil {
			t.Fatal(err)
		}
	}
	item := resources.Resource{ID: "vendor", Name: "1", Domains: []resources.DomainRule{{Host: "vendor.example"}}}
	if err := writer.UpsertResource(item); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		for i := 2; i <= 40; i++ {
			item.Name = strconv.Itoa(i)
			if err := writer.UpsertResource(item); err != nil {
				result <- err
				return
			}
		}
		result <- nil
	}()
	for i := 0; i < 100; i++ {
		snapshot, err := reader.ResourceSnapshot()
		if err != nil || len(snapshot.Resources) != 1 || snapshot.Resources[0].Name != strconv.FormatInt(snapshot.Revision, 10) {
			t.Fatalf("revision and resources came from different commits: %v", err)
		}
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	final, err := reader.ResourceSnapshot()
	if err != nil || final.Revision != 40 || final.Resources[0].Name != "40" {
		t.Fatal("concurrent updates were lost")
	}
}
