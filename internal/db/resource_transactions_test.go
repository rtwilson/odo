package db

import (
	"path/filepath"
	"reflect"
	"testing"

	"example.org/odo/internal/resources"
)

func TestResourceMutationRollsBackWithAuditOrWriteFailure(t *testing.T) {
	for _, operation := range []string{"create", "update", "delete"} {
		for _, failure := range []string{"audit", "write"} {
			t.Run(operation+"/"+failure, func(t *testing.T) {
				store, err := Open(filepath.Join(t.TempDir(), "odo.db"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = store.Close() })
				if err := store.Migrate(); err != nil {
					t.Fatal(err)
				}
				item := resources.Resource{ID: "vendor", Name: "Vendor", Domains: []resources.DomainRule{{Host: "vendor.example"}}, CookiePolicy: resources.CookiePolicy{Enabled: true}}
				if operation != "create" {
					if err := store.UpsertResource(item); err != nil {
						t.Fatal(err)
					}
				}
				before, existed, err := store.GetResource(item.ID)
				if err != nil {
					t.Fatal(err)
				}
				beforeSnapshot, err := store.ResourceSnapshot()
				if err != nil {
					t.Fatal(err)
				}
				events, err := store.ListAuditEvents(10)
				if err != nil {
					t.Fatal(err)
				}
				trigger := `CREATE TRIGGER fail_resource_change BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END`
				if failure == "write" {
					event := "INSERT"
					if operation == "update" {
						event = "UPDATE"
					} else if operation == "delete" {
						event = "DELETE"
					}
					trigger = `CREATE TRIGGER fail_resource_change BEFORE ` + event + ` ON resources BEGIN SELECT RAISE(ABORT, 'injected resource failure'); END`
				}
				if _, err := store.db.Exec(trigger); err != nil {
					t.Fatal(err)
				}
				if operation == "delete" {
					deleted, err := store.DeleteResource(item.ID)
					if err == nil || deleted {
						t.Fatal("failed deletion reported success")
					}
				} else {
					item.CookiePolicy.Enabled = false
					item.Status = "disabled"
					if err := store.UpsertResource(item); err == nil {
						t.Fatal("failed write reported success")
					}
				}
				after, found, err := store.GetResource(item.ID)
				if err != nil || found != existed || !reflect.DeepEqual(after, before) {
					t.Fatal("failed resource operation changed stored policy")
				}
				afterSnapshot, err := store.ResourceSnapshot()
				if err != nil || !reflect.DeepEqual(afterSnapshot, beforeSnapshot) {
					t.Fatal("failed resource operation advanced the snapshot revision")
				}
				afterEvents, err := store.ListAuditEvents(10)
				if err != nil || !reflect.DeepEqual(afterEvents, events) {
					t.Fatal("failed resource operation changed audit records")
				}
			})
		}
	}
}

func TestResourceMutationsCommitOneAuditEach(t *testing.T) {
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
	item.CookiePolicy.Enabled = true
	if err := store.UpsertResource(item); err != nil {
		t.Fatal(err)
	}
	if deleted, err := store.DeleteResource(item.ID); err != nil || !deleted {
		t.Fatalf("resource deletion failed: %v", err)
	}
	if deleted, err := store.DeleteResource(item.ID); err != nil || deleted {
		t.Fatal("missing resource deletion changed behavior")
	}
	events, err := store.ListAuditEvents(10)
	if err != nil || len(events) != 3 {
		t.Fatalf("expected one audit for each committed mutation: %v", err)
	}
	for i, want := range []string{"resource.delete", "resource.upsert", "resource.upsert"} {
		if events[i].Event != want {
			t.Fatalf("unexpected committed audit event: %s", events[i].Event)
		}
	}
}
