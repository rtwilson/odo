package db

import (
	"path/filepath"
	"sync"
	"testing"
)

func TestProxyHostnamePersistsAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "odo.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(); err != nil {
		t.Fatal(err)
	}
	record, err := store.RegisterProxyHostname("VENDOR.EXAMPLE.:443", "odo.example", "proxy.example")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(); err != nil {
		t.Fatal(err)
	}
	got, found, err := store.LookupProxyHostname(record.Label)
	if err != nil || !found || got != record {
		t.Fatalf("lookup after restart: %+v found=%v err=%v", got, found, err)
	}
	again, err := store.RegisterProxyHostname("vendor.example", "odo.example", "proxy.example")
	if err != nil || again != record {
		t.Fatalf("repeat registration: %+v err=%v", again, err)
	}
	if _, found, err := store.LookupProxyHostname("unknown"); err != nil || found {
		t.Fatalf("unknown label: found=%v err=%v", found, err)
	}
}

func TestProxyHostnameConflictsFailClosed(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "odo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Migrate(); err != nil {
		t.Fatal(err)
	}
	record, err := store.RegisterProxyHostname("vendor.example", "odo.example", "proxy.example")
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a label already held by another hostname.
	if _, err := store.db.Exec(`UPDATE proxy_hostnames SET hostname = ? WHERE label = ?`, "other.example", record.Label); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RegisterProxyHostname("vendor.example", "odo.example", "proxy.example"); err == nil {
		t.Fatal("accepted a label owned by another host")
	}
	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM proxy_hostnames`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("conflict changed registry: count=%d err=%v", count, err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Concurrent writers may fail with SQLite busy, but must never
			// return a successful conflicting identity.
			if _, err := store.RegisterProxyHostname("vendor.example", "odo.example", "proxy.example"); err == nil {
				t.Error("concurrent registration accepted a conflicting label")
			}
		}()
	}
	wg.Wait()
	got, found, err := store.LookupProxyHostname(record.Label)
	if err != nil || !found || got.Hostname != "other.example" {
		t.Fatalf("collision overwrote identity: %+v found=%v err=%v", got, found, err)
	}
}

func TestProxyHostnameConcurrentEnrollment(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "odo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Migrate(); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan ProxyHostname, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if record, err := store.RegisterProxyHostname("vendor.example", "odo.example", "proxy.example"); err == nil {
				results <- record
			}
		}()
	}
	wg.Wait()
	close(results)
	var first ProxyHostname
	for record := range results {
		if first.Hostname != "" && first != record {
			t.Fatal("concurrent enrollment returned different identities")
		}
		first = record
	}
	if first.Hostname != "vendor.example" {
		t.Fatal("no concurrent enrollment succeeded")
	}
	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM proxy_hostnames`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("concurrent enrollment: count=%d err=%v", count, err)
	}
	if _, err := store.RegisterProxyHostname("h-loop.proxy.example", "odo.example", "proxy.example"); err == nil {
		t.Fatal("enrolled a proxy loop")
	}
}
