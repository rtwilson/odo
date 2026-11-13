package db

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"example.org/odo/internal/resources"
)

func TestWithResourceSnapshotOrdersMutations(t *testing.T) {
	for _, operation := range []string{"create", "update", "identical", "delete"} {
		t.Run(operation, func(t *testing.T) {
			store, err := Open(filepath.Join(t.TempDir(), "odo.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			// A callback read must work even with only one database connection.
			store.db.SetMaxOpenConns(1)
			if err := store.Migrate(); err != nil {
				t.Fatal(err)
			}
			item := resources.Resource{ID: "vendor", Name: "Vendor", Domains: []resources.DomainRule{{Host: "vendor.example"}}}
			if operation != "create" {
				if err := store.UpsertResource(item); err != nil {
					t.Fatal(err)
				}
			}
			before, err := store.ResourceSnapshot()
			if err != nil {
				t.Fatal(err)
			}
			started, finished := make(chan struct{}), make(chan error, 1)
			callbackErr := store.WithResourceSnapshot(func(snapshot ResourceSnapshot) error {
				if !reflect.DeepEqual(snapshot, before) {
					return errors.New("guarded snapshot differs from committed state")
				}
				go func() {
					close(started)
					if operation == "delete" {
						deleted, err := store.DeleteResource(item.ID)
						if err == nil && !deleted {
							err = errors.New("existing resource was not deleted")
						}
						finished <- err
						return
					}
					if operation == "update" {
						item.CookiePolicy.Enabled = true
					}
					finished <- store.UpsertResource(item)
				}()
				<-started
				select {
				case err := <-finished:
					finished <- err // Still drain the writer after releasing the guard.
					return errors.New("resource write completed during snapshot use")
				case <-time.After(50 * time.Millisecond):
				}
				// The callback may perform ordinary reads. The snapshot's SQL
				// transaction is closed, but participating writes remain excluded.
				current, err := store.ResourceSnapshot()
				if err != nil {
					return err
				}
				if !reflect.DeepEqual(current, snapshot) {
					return errors.New("resource revision changed during snapshot use")
				}
				return nil
			})
			select {
			case err := <-finished:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("writer did not finish after snapshot use")
			}
			if callbackErr != nil {
				t.Fatal(callbackErr)
			}
			if err := store.WithResourceSnapshot(func(snapshot ResourceSnapshot) error {
				if snapshot.Revision != before.Revision+1 {
					return errors.New("next guarded read missed the committed revision")
				}
				if operation == "delete" {
					if len(snapshot.Resources) != 0 {
						return errors.New("next guarded read retained deleted resource")
					}
				} else if len(snapshot.Resources) != 1 || snapshot.Resources[0].CookiePolicy.Enabled != item.CookiePolicy.Enabled {
					return errors.New("next guarded read missed the committed resource")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestWithResourceSnapshotErrors(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "odo.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(); err != nil {
		t.Fatal(err)
	}
	// Callback failure must propagate unchanged and release the guard.
	denied := errors.New("authorization denied")
	if err := store.WithResourceSnapshot(func(ResourceSnapshot) error { return denied }); !errors.Is(err, denied) {
		t.Fatalf("callback failure was lost: %v", err)
	}
	item := resources.Resource{ID: "vendor", Name: "Vendor", Domains: []resources.DomainRule{{Host: "vendor.example"}}}
	if err := store.UpsertResource(item); err != nil {
		t.Fatal(err)
	}
	for _, failure := range []string{"invalid resource", "unavailable database"} {
		t.Run(failure, func(t *testing.T) {
			if failure == "invalid resource" {
				if _, err := store.db.Exec(`UPDATE resources SET config_json = '{}'`); err != nil {
					t.Fatal(err)
				}
			} else if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			called := false
			for range 2 { // Read failure must release the guard too.
				err := store.WithResourceSnapshot(func(ResourceSnapshot) error {
					called = true
					return nil
				})
				if err == nil || called {
					t.Fatal("failed snapshot read invoked callback or reported success")
				}
			}
		})
	}
}
