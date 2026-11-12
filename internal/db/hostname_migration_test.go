package db

import (
	"crypto/sha256"
	"encoding/base32"
	"path/filepath"
	"strings"
	"testing"

	"example.org/odo/internal/resources"
)

func legacyLabelForTest(host string) string {
	sum := sha256.Sum256([]byte(host))
	return "h-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:]))
}

func hostnameMigrationStore(t *testing.T, hosts ...string) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "odo.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.Migrate(); err != nil {
		t.Fatal(err)
	}
	var domains []resources.DomainRule
	for _, host := range hosts {
		domains = append(domains, resources.DomainRule{Host: host})
		if _, err := s.db.Exec(`INSERT INTO proxy_hostnames(hostname,label) VALUES(?,?)`, host, legacyLabelForTest(host)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.UpsertResource(resources.Resource{ID: "vendor", Name: "Vendor", Domains: domains}); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestReadableMigrationPreservesUntilExplicitAndRetiresOldNames(t *testing.T) {
	s := hostnameMigrationStore(t, "www.jstor.org")
	old := legacyLabelForTest("www.jstor.org")
	record, err := s.RegisterProxyHostname("WWW.JSTOR.ORG.", "odo.example", "proxy.example")
	if err != nil || record.Label != old {
		t.Fatalf("repeat registration changed legacy mapping: %+v %v", record, err)
	}
	records, err := s.ReconcileProxyHostnames("odo.example", "proxy.example", nil)
	if err != nil || len(records) != 1 || records[0].Label != old {
		t.Fatalf("reconcile changed legacy mapping: %+v %v", records, err)
	}
	for range 2 {
		records, err = s.MigrateProxyHostnames("odo.example", "proxy.example", nil)
		if err != nil || len(records) != 1 || records[0].Label != "www-jstor-org" {
			t.Fatalf("migration: %+v %v", records, err)
		}
	}
	if _, found, err := s.LookupProxyHostname(old); err != nil || found {
		t.Fatalf("retired name admitted: %v %v", found, err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatal(err)
	}
	// A single-label upstream can otherwise generate this exact old label. The
	// tombstone must reject it even after schema migration/restart.
	if _, err := s.RegisterProxyHostname(old, "odo.example", "proxy.example"); err == nil {
		t.Fatal("retired label reused by another upstream")
	}
	if _, err := s.db.Exec(`UPDATE proxy_hostnames SET label=? WHERE hostname=?`, old, "www.jstor.org"); err == nil {
		t.Fatal("retired label restored")
	}
	got, found, err := s.LookupProxyHostnameByUpstream("www.jstor.org")
	if err != nil || !found || got.Label != "www-jstor-org" {
		t.Fatalf("current mapping lost: %+v %v", got, err)
	}
}

// Real ambiguous names must roll back the whole migration, including names
// sorted earlier in the batch, without minting fallback identities.
func TestReadableCollisionsRejectEnrollmentAndMigration(t *testing.T) {
	s := hostnameMigrationStore(t, "a.example", "a-b.example", "a.b-example")
	if _, err := s.MigrateProxyHostnames("odo.example", "proxy.example", nil); err == nil {
		t.Fatal("ambiguous names migrated")
	}
	for _, host := range []string{"a.example", "a-b.example", "a.b-example"} {
		got, found, err := s.LookupProxyHostnameByUpstream(host)
		if err != nil || !found || got.Label != legacyLabelForTest(host) {
			t.Fatalf("partial migration: %+v %v", got, err)
		}
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM proxy_hostname_retired_labels`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial tombstones: %d %v", count, err)
	}
	first, err := s.RegisterProxyHostname("x-y.example", "odo.example", "proxy.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterProxyHostname("X.Y-EXAMPLE.", "odo.example", "proxy.example"); err == nil {
		t.Fatal("colliding enrollment accepted")
	}
	if _, found, err := s.LookupProxyHostnameByUpstream("x.y-example"); err != nil || found {
		t.Fatal("collision created fallback mapping")
	}
	got, found, err := s.LookupProxyHostname(first.Label)
	if err != nil || !found || got != first {
		t.Fatalf("collision repointed name: %+v %v", got, err)
	}
}

// Any failure rolls the whole migration back: no relabel and no tombstone.
func TestReadableMigrationRollsBackWholeBatch(t *testing.T) {
	s := hostnameMigrationStore(t, "a.example", "z.example")
	if _, err := s.db.Exec(`CREATE TRIGGER fail_z_retire BEFORE INSERT ON proxy_hostname_retired_labels WHEN NEW.hostname = 'z.example' BEGIN SELECT RAISE(ABORT, 'injected'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MigrateProxyHostnames("odo.example", "proxy.example", nil); err == nil {
		t.Fatal("injected failure did not fail migration")
	}
	for _, host := range []string{"a.example", "z.example"} {
		got, found, err := s.LookupProxyHostnameByUpstream(host)
		if err != nil || !found || got.Label != legacyLabelForTest(host) {
			t.Fatalf("partial migration: %+v %v", got, err)
		}
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM proxy_hostname_retired_labels`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial tombstones: %d %v", count, err)
	}
}
