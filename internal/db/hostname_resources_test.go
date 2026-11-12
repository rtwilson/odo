package db

import (
	"path/filepath"
	"reflect"
	"testing"

	"example.org/odo/internal/proxy"
	"example.org/odo/internal/resources"
)

func TestReconcileProxyHostnamesAndLiveResourceAssociations(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "odo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Migrate(); err != nil {
		t.Fatal(err)
	}
	a := resources.Resource{ID: "a", Name: "A", Domains: []resources.DomainRule{{Host: "vendor.example"}, {Host: "second.example"}}}
	b := resources.Resource{ID: "b", Name: "B", Domains: []resources.DomainRule{{Host: "vendor.example"}}}
	wildcard := resources.Resource{ID: "wildcard", Name: "Wildcard", Domains: []resources.DomainRule{{Host: "assets.example", Match: "subdomain"}}}
	for _, item := range []resources.Resource{a, b, wildcard} {
		if err := store.UpsertResource(item); err != nil {
			t.Fatal(err)
		}
	}
	records, err := store.ReconcileProxyHostnames("odo.example", "proxy.example", nil)
	if err != nil || len(records) != 2 || records[0].Hostname != "second.example" || records[1].Hostname != "vendor.example" {
		t.Fatalf("exact hosts: %+v err=%v", records, err)
	}
	_, wildcardLabel, err := proxy.RegistryHostname("assets.example", "odo.example", "proxy.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.LookupProxyHostname(wildcardLabel); err != nil || found {
		t.Fatalf("subdomain rule auto-enrolled: found=%v err=%v", found, err)
	}
	label := records[1].Label
	ids, err := store.ProxyHostnameResourceIDs(label)
	if err != nil || !reflect.DeepEqual(ids, []string{"a", "b"}) {
		t.Fatalf("shared host associations: %v err=%v", ids, err)
	}
	a.Status = "disabled"
	if err := store.UpsertResource(a); err != nil {
		t.Fatal(err)
	}
	ids, err = store.ProxyHostnameResourceIDs(label)
	if err != nil || !reflect.DeepEqual(ids, []string{"b"}) {
		t.Fatalf("disabled resource still associated: %v err=%v", ids, err)
	}
	if _, err := store.DeleteResource("b"); err != nil {
		t.Fatal(err)
	}
	ids, err = store.ProxyHostnameResourceIDs(label)
	if err != nil || len(ids) != 0 {
		t.Fatalf("deleted resource still associated: %v err=%v", ids, err)
	}
	if _, found, err := store.LookupProxyHostname(label); err != nil || !found {
		t.Fatalf("retired identity lost: found=%v err=%v", found, err)
	}
	records, err = store.ReconcileProxyHostnames("odo.example", "proxy.example", []string{"CDN.ASSETS.EXAMPLE.:443"})
	if err != nil || len(records) != 1 || records[0].Hostname != "cdn.assets.example" {
		t.Fatalf("explicit concrete host: %+v err=%v", records, err)
	}
	ids, err = store.ProxyHostnameResourceIDs(records[0].Label)
	if err != nil || !reflect.DeepEqual(ids, []string{"wildcard"}) {
		t.Fatalf("concrete host association: %v err=%v", ids, err)
	}
}

func TestReconcileProxyHostnamesRespectsDomainPolicy(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "odo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Migrate(); err != nil {
		t.Fatal(err)
	}
	for _, item := range []resources.Resource{
		{ID: "proxy", Name: "Proxy", Domains: []resources.DomainRule{{Host: "blocked.example"}, {Host: "allowed.example"}}, AnonymousURLRules: []resources.AnonymousURLRule{{Pattern: "https://anonymous.example/*"}}},
		{ID: "block", Name: "Block", Domains: []resources.DomainRule{{Host: "blocked.example", Action: "block"}}},
		{ID: "external", Name: "External", Domains: []resources.DomainRule{{Host: "external.example", Role: "external"}}},
		{ID: "inactive", Name: "Inactive", Status: "disabled", Domains: []resources.DomainRule{{Host: "inactive.example"}}},
	} {
		if err := store.UpsertResource(item); err != nil {
			t.Fatal(err)
		}
	}
	records, err := store.ReconcileProxyHostnames("odo.example", "proxy.example", nil)
	if err != nil || len(records) != 1 || records[0].Hostname != "allowed.example" {
		t.Fatalf("policy filtering: %+v err=%v", records, err)
	}
	for _, host := range []string{"blocked.example", "external.example", "inactive.example", "unknown.example", "anonymous.example", "h-loop.proxy.example"} {
		if _, err := store.ReconcileProxyHostnames("odo.example", "proxy.example", []string{host}); err == nil {
			t.Fatalf("approved host bypassed policy: %q", host)
		}
	}
	block := resources.Resource{ID: "new-block", Name: "New block", Domains: []resources.DomainRule{{Host: "allowed.example", Action: "block"}}}
	if err := store.UpsertResource(block); err != nil {
		t.Fatal(err)
	}
	ids, err := store.ProxyHostnameResourceIDs(records[0].Label)
	if err != nil || len(ids) != 0 {
		t.Fatalf("new block did not take immediate effect: %v err=%v", ids, err)
	}
}

func TestReconcileProxyHostnamesRollsBackWholeBatch(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "odo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Migrate(); err != nil {
		t.Fatal(err)
	}
	item := resources.Resource{ID: "vendor", Name: "Vendor", Domains: []resources.DomainRule{{Host: "a.example"}, {Host: "z.example"}}}
	if err := store.UpsertResource(item); err != nil {
		t.Fatal(err)
	}
	_, collisionLabel, err := proxy.RegistryHostname("z.example", "odo.example", "proxy.example")
	if err != nil {
		t.Fatal(err)
	}
	// A taken readable label alone must fail the whole batch.
	if _, err := store.db.Exec(`INSERT INTO proxy_hostnames (hostname, label) VALUES (?, ?)`, "other.example", collisionLabel); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReconcileProxyHostnames("odo.example", "proxy.example", nil); err == nil {
		t.Fatal("accepted conflicting label")
	}
	_, firstLabel, err := proxy.RegistryHostname("a.example", "odo.example", "proxy.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.LookupProxyHostname(firstLabel); err != nil || found {
		t.Fatalf("earlier insert survived rollback: found=%v err=%v", found, err)
	}
	got, found, err := store.LookupProxyHostname(collisionLabel)
	if err != nil || !found || got.Hostname != "other.example" {
		t.Fatalf("original mapping changed: %+v found=%v err=%v", got, found, err)
	}
}
