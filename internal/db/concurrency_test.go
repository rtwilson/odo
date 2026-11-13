package db

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"example.org/odo/internal/resources"
)

func openConcurrencyStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "odo.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(); err != nil {
		t.Fatal(err)
	}
	return store
}

// Regression: pooled connections used to fail immediately with SQLITE_BUSY
// when another connection held the write lock.
func TestStoreConcurrentWritersWaitForTheLock(t *testing.T) {
	for round := range 3 {
		store := openConcurrencyStore(t)
		errs := make(chan error, 48)
		var wg sync.WaitGroup
		for i := range 16 {
			wg.Add(3)
			go func() {
				defer wg.Done()
				_, err := store.RegisterProxyHostname(fmt.Sprintf("vendor%d.example", i), "odo.example", "proxy.example")
				errs <- err
			}()
			go func() {
				defer wg.Done()
				errs <- store.TouchSession(fmt.Sprintf("session-%d", i))
			}()
			go func() {
				defer wg.Done()
				errs <- store.UpsertResource(resources.Resource{ID: fmt.Sprintf("r%d", i), Name: "R", Domains: []resources.DomainRule{{Host: fmt.Sprintf("r%d.example", i)}}})
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("round %d: concurrent write failed: %v", round, err)
			}
		}
	}
}

// Deferred transactions that read and then write deadlock-fail on lock upgrade
// without invoking the busy handler; immediate transactions wait at BEGIN.
func TestStoreReadThenWriteTransactionsDoNotFailOnUpgrade(t *testing.T) {
	store := openConcurrencyStore(t)
	errs := make(chan error, 16)
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- func() error {
				tx, err := store.db.Begin()
				if err != nil {
					return err
				}
				defer tx.Rollback()
				var count int
				if err := tx.QueryRow(`SELECT COUNT(*) FROM proxy_hostnames`).Scan(&count); err != nil {
					return err
				}
				if _, err := tx.Exec(`INSERT INTO proxy_hostnames (hostname, label) VALUES (?, ?)`, fmt.Sprintf("h%d.example", i), fmt.Sprintf("h-%d", i)); err != nil {
					return err
				}
				return tx.Commit()
			}()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("read-then-write transaction failed: %v", err)
		}
	}
}

func TestOpenAppliesConnectionParametersToEveryConnection(t *testing.T) {
	store := openConcurrencyStore(t)
	ctx := context.Background()
	var conns []interface{ Close() error }
	for range 3 {
		conn, err := store.db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, conn)
		var timeout int
		if err := conn.QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&timeout); err != nil || timeout != 5000 {
			t.Fatalf("busy_timeout=%d err=%v", timeout, err)
		}
	}
	for _, conn := range conns {
		_ = conn.Close()
	}
}

func TestOpenRejectsQueryInPath(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "odo.db?mode=memory")); err == nil {
		t.Fatal("accepted a database path the driver would silently truncate")
	}
}
