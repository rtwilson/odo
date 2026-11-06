package api

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"example.org/odo/internal/proxy"
	"example.org/odo/internal/resources"
)

func TestHostnameReconciliationAPIEnrollmentAndPolicy(t *testing.T) {
	t.Setenv("APP_PUBLIC_URL", "https://odo.example")
	t.Setenv("APP_PROXY_BASE_DOMAIN", "proxy.example")
	server := newTestServer(t, "secret")
	server.ipLookup = func(context.Context, string) ([]net.IPAddr, error) {
		t.Error("reconciliation performed DNS lookup")
		return nil, errors.New("unexpected DNS")
	}
	server.httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("reconciliation fetched upstream")
		return nil, errors.New("unexpected fetch")
	})}
	if err := server.store.UpsertResource(resources.Resource{ID: "vendor", Name: "Vendor", Domains: []resources.DomainRule{
		{Host: "vendor.example"}, {Host: "assets.example", Match: "subdomain"},
	}}); err != nil {
		t.Fatal(err)
	}
	handler := server.Routes()
	for _, body := range []string{`{"approved_hosts":["cdn.assets.example"]}`, `{"approved_hosts":[]}`} {
		req := httptest.NewRequest("POST", "/api/v1/proxy-hostnames/reconcile", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer secret")
		req.Host = "vendor.example" // Must not replace the configured central host.
		req.Header.Set("X-Forwarded-Host", "vendor.example")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("reconcile: %d %s", rec.Code, rec.Body.String())
		}
		var response struct {
			Hostnames []struct {
				Hostname string `json:"hostname"`
				Label    string `json:"label"`
			} `json:"hostnames"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		wantCount := 1
		if strings.Contains(body, "cdn.assets.example") {
			wantCount = 2
		}
		if len(response.Hostnames) != wantCount {
			t.Fatalf("unexpected candidates: %s", rec.Body.String())
		}
		for _, record := range response.Hostnames {
			stored, found, err := server.store.LookupProxyHostname(record.Label)
			if err != nil || !found || stored.Hostname != record.Hostname {
				t.Fatalf("response mapping was not stored: %+v found=%v err=%v", stored, found, err)
			}
		}
	}
	req := httptest.NewRequest("POST", "/api/v1/proxy-hostnames/reconcile", strings.NewReader(`{"approved_hosts":["unknown.example"]}`))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown host accepted: %d %s", rec.Code, rec.Body.String())
	}
}

func TestHostnameReconciliationAPIRequiresScopeAndCSRF(t *testing.T) {
	t.Setenv("APP_PUBLIC_URL", "https://odo.example")
	t.Setenv("APP_PROXY_BASE_DOMAIN", "proxy.example")
	server := newTestServer(t, "secret")
	upsertTestResource(t, server, "vendor")
	readToken, _ := createTestAPIKey(t, server, "secret", []string{"resources:read"})
	writeToken, _ := createTestAPIKey(t, server, "secret", []string{"resources:write"})
	createLocalTestUserWithRoles(t, server, "resourceadmin", "correct horse battery", []string{"resource_admin"})
	cookie, csrf := loginTestUserWithCSRF(t, server, "resourceadmin", "correct horse battery", "/admin")
	for _, tc := range []struct {
		name, token, csrf string
		session           bool
		want              int
	}{
		{name: "anonymous", want: 401},
		{name: "read key", token: readToken, want: 403},
		{name: "missing csrf", session: true, want: 403},
		{name: "wrong csrf", session: true, csrf: "wrong", want: 403},
		{name: "session", session: true, csrf: csrf, want: 200},
		{name: "write key", token: writeToken, want: 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/v1/proxy-hostnames/reconcile", strings.NewReader(`{}`))
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			if tc.session {
				req.AddCookie(cookie)
				req.Header.Set("X-Odo-CSRF", tc.csrf)
			}
			rec := httptest.NewRecorder()
			server.Routes().ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("got %d want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
			if tc.want != 200 {
				_, label, err := proxy.RegistryHostname("vendor.example.org", "odo.example", "proxy.example")
				if err != nil {
					t.Fatal(err)
				}
				if _, found, err := server.store.LookupProxyHostname(label); err != nil || found {
					t.Fatalf("unauthorized mutation: found=%v err=%v", found, err)
				}
			}
		})
	}
}

func TestHostnameReconciliationAPIRejectsInvalidInputAndConfiguration(t *testing.T) {
	server := newTestServer(t, "secret")
	upsertTestResource(t, server, "vendor")
	for _, tc := range []struct {
		name, public, base, body string
		want                     int
	}{
		{"missing public", "", "proxy.example", `{}`, 503},
		{"missing base", "https://odo.example", "", `{}`, 503},
		{"http public", "http://odo.example", "proxy.example", `{}`, 503},
		{"public credentials", "https://u:p@odo.example", "proxy.example", `{}`, 503},
		{"public port", "https://odo.example:8443", "proxy.example", `{}`, 503},
		{"public path", "https://odo.example/admin", "proxy.example", `{}`, 503},
		{"public empty query", "https://odo.example?", "proxy.example", `{}`, 503},
		{"public empty fragment", "https://odo.example#", "proxy.example", `{}`, 503},
		{"public escaped root", "https://odo.example/%2F", "proxy.example", `{}`, 503},
		{"invalid base", "https://odo.example", "*.proxy.example", `{}`, 503},
		{"null", "https://odo.example", "proxy.example", `null`, 400},
		{"unknown field", "https://odo.example", "proxy.example", `{"proxy_base":"evil.example"}`, 400},
		{"trailing JSON", "https://odo.example", "proxy.example", `{} {}`, 400},
		{"wrong type", "https://odo.example", "proxy.example", `{"approved_hosts":[1]}`, 400},
		{"too large", "https://odo.example", "proxy.example", strings.Repeat(" ", 64<<10) + `{}`, 413},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("APP_PUBLIC_URL", tc.public)
			t.Setenv("APP_PROXY_BASE_DOMAIN", tc.base)
			req := httptest.NewRequest("POST", "/api/v1/proxy-hostnames/reconcile", strings.NewReader(tc.body))
			req.Header.Set("Authorization", "Bearer secret")
			rec := httptest.NewRecorder()
			server.Routes().ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("got %d want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
	_, label, _ := proxy.RegistryHostname("vendor.example.org", "odo.example", "proxy.example")
	if _, found, err := server.store.LookupProxyHostname(label); err != nil || found {
		t.Fatalf("invalid request mutated registry: found=%v err=%v", found, err)
	}
}
