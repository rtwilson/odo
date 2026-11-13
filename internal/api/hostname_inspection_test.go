package api

import (
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"testing"

	"example.org/odo/internal/resources"
)

func TestProxyHostnameInspectionTracksLivePolicy(t *testing.T) {
	server := newTestServer(t, "secret")
	// Inspection does not need current deployment settings or network access.
	t.Setenv("APP_PUBLIC_URL", "")
	t.Setenv("APP_PROXY_BASE_DOMAIN", "")
	record, err := server.store.RegisterProxyHostname("vendor.example", "odo.example", "proxy.example")
	if err != nil {
		t.Fatal(err)
	}
	a := resources.Resource{ID: "a", Name: "A", Domains: []resources.DomainRule{{Host: "vendor.example"}}}
	b := resources.Resource{ID: "b", Name: "B", Domains: []resources.DomainRule{{Host: "vendor.example"}}}
	for _, item := range []resources.Resource{a, b} {
		if err := server.store.UpsertResource(item); err != nil {
			t.Fatal(err)
		}
	}
	inspect := func(want []string) {
		t.Helper()
		req := httptest.NewRequest("GET", "/api/v1/proxy-hostnames/"+record.Label, nil)
		req.Header.Set("Authorization", "Bearer secret")
		rec := httptest.NewRecorder()
		server.Routes().ServeHTTP(rec, req)
		if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("inspection: %d %s", rec.Code, rec.Body.String())
		}
		var body struct {
			Hostname    string   `json:"hostname"`
			Label       string   `json:"label"`
			ResourceIDs []string `json:"resource_ids"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.Hostname != record.Hostname || body.Label != record.Label || !reflect.DeepEqual(body.ResourceIDs, want) {
			t.Fatalf("unexpected inspection: %s; want resource IDs %v", rec.Body.String(), want)
		}
	}
	inspect([]string{"a", "b"})
	a.Status = "disabled"
	if err := server.store.UpsertResource(a); err != nil {
		t.Fatal(err)
	}
	inspect([]string{"b"})
	block := resources.Resource{ID: "block", Name: "Block", Domains: []resources.DomainRule{{Host: "vendor.example", Action: "block"}}}
	if err := server.store.UpsertResource(block); err != nil {
		t.Fatal(err)
	}
	inspect([]string{})
	if _, err := server.store.DeleteResource("block"); err != nil {
		t.Fatal(err)
	}
	inspect([]string{"b"})
	if _, err := server.store.DeleteResource("b"); err != nil {
		t.Fatal(err)
	}
	inspect([]string{}) // Identity remains inspectable after its last association.
}

func TestProxyHostnameInspectionRequiresReadScope(t *testing.T) {
	server := newTestServer(t, "secret")
	record, err := server.store.RegisterProxyHostname("vendor.example", "odo.example", "proxy.example")
	if err != nil {
		t.Fatal(err)
	}
	readToken, _ := createTestAPIKey(t, server, "secret", []string{"resources:read"})
	writeToken, _ := createTestAPIKey(t, server, "secret", []string{"resources:write"})
	createLocalTestUserWithRoles(t, server, "resourceadmin", "correct horse battery", []string{"resource_admin"})
	createLocalTestUser(t, server, "patron", "correct horse battery")
	adminCookie := loginTestUser(t, server, "resourceadmin", "correct horse battery", "/admin")
	patronCookie := loginTestUser(t, server, "patron", "correct horse battery", "/resources")
	for _, tc := range []struct {
		name, token, label, session string
		want                        int
	}{
		{"anonymous known", "", record.Label, "", 401},
		{"anonymous unknown", "", "unknown", "", 401},
		{"write only", writeToken, record.Label, "", 403},
		{"patron", "", record.Label, "patron", 403},
		{"read key", readToken, record.Label, "", 200},
		{"read unknown", readToken, "unknown", "", 404},
		{"session without csrf", "", record.Label, "admin", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/proxy-hostnames/"+tc.label, nil)
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			if tc.session == "admin" {
				req.AddCookie(adminCookie)
			} else if tc.session == "patron" {
				req.AddCookie(patronCookie)
			}
			rec := httptest.NewRecorder()
			server.Routes().ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("got %d want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
	if _, found, err := server.store.LookupProxyHostname("unknown"); err != nil || found {
		t.Fatalf("inspection enrolled unknown label: found=%v err=%v", found, err)
	}
}
