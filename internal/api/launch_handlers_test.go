package api

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"example.org/odo/internal/accesslog"
	"example.org/odo/internal/proxy"
	"example.org/odo/internal/resources"
)

func TestLaunchRedirectPreservesTargetWithoutFetching(t *testing.T) {
	t.Setenv("APP_PROXY_REQUIRE_LOGIN", "true")
	var logs bytes.Buffer
	logger, err := accesslog.New(accesslog.FormatPrivacy, &logs)
	if err != nil {
		t.Fatal(err)
	}
	server := newTestServerWithConfigAndAccessLog(t, "secret", t.TempDir(), logger)
	server.httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("launch fetched vendor content")
		return nil, errors.New("unexpected fetch")
	})}
	upsertTestResource(t, server, "vendor")
	createLocalTestUser(t, server, "alice", "correct horse battery")
	cookie := loginTestUser(t, server, "alice", "correct horse battery", "/resources")
	logs.Reset()
	for _, mode := range []string{"path", "query", "dual", "virtual_host"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("APP_PROXY_URL_MODE", mode)
			for _, target := range []string{
				"https://vendor.example.org/a%2Fb?url=https%3A%2F%2Fother.example%2F&term=private-search%2Bterm",
				"https://vendor.example.org/path?",
			} {
				for _, query := range []string{"url=" + target, "url=" + url.QueryEscape(target)} {
					req := httptest.NewRequest("GET", "/launch?"+query, nil)
					req.AddCookie(cookie)
					rec := httptest.NewRecorder()
					server.Routes().ServeHTTP(rec, req)
					if rec.Code != 302 || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Referrer-Policy") != "no-referrer" {
						t.Fatalf("launch: %d %s", rec.Code, rec.Body.String())
					}
					location := rec.Header().Get("Location")
					if !strings.HasPrefix(location, "/odo") {
						t.Fatalf("launch escaped proxy origin: %q", location)
					}
					parsed, _, ok, err := proxy.ParseProxyRequest(httptest.NewRequest("GET", location, nil))
					if err != nil || !ok || parsed.String() != target {
						t.Fatalf("launch changed target: %v ok=%v err=%v", parsed, ok, err)
					}
					if len(rec.Result().Cookies()) != 0 {
						t.Fatal("launch created a cookie")
					}
				}
			}
		})
	}
	if server.sessions.Count() != 0 {
		t.Fatal("launch created a vendor session")
	}
	if strings.Contains(logs.String(), "private-search") || strings.Contains(logs.String(), "other.example") || strings.Contains(logs.String(), "a%2Fb") {
		t.Fatalf("launch leaked vendor URL data into logs: %s", logs.String())
	}
	events, err := server.store.ListAuditEvents(100)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if strings.Contains(event.Detail, "private-search") || strings.Contains(event.Detail, "other.example") {
			t.Fatalf("launch leaked vendor URL into audit: %s", event.Detail)
		}
	}
}

func TestLaunchRejectsUnsafeOrUnauthorizedTargets(t *testing.T) {
	t.Setenv("APP_PROXY_REQUIRE_LOGIN", "true")
	server := newTestServer(t, "secret")
	if err := server.store.UpsertResource(resources.Resource{
		ID: "vendor", Name: "Vendor", Domains: []resources.DomainRule{{Host: "vendor.example"}},
		AnonymousURLRules: []resources.AnonymousURLRule{{Pattern: "https://public.example/*", Behavior: "allow_public_proxy", Methods: []string{"GET", "HEAD"}}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := server.store.UpsertResource(resources.Resource{ID: "post", Name: "Post", HTTPMethods: []string{"POST"}, Domains: []resources.DomainRule{{Host: "post.example"}}}); err != nil {
		t.Fatal(err)
	}
	for _, item := range []resources.Resource{
		{ID: "block", Name: "Block", Domains: []resources.DomainRule{{Host: "blocked.example", Action: "block"}}},
		{ID: "disabled", Name: "Disabled", Status: "disabled", Domains: []resources.DomainRule{{Host: "disabled.example"}}},
	} {
		if err := server.store.UpsertResource(item); err != nil {
			t.Fatal(err)
		}
	}
	server.ipLookup = func(_ context.Context, host string) ([]net.IPAddr, error) {
		if host == "private.example" {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		}
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
	}
	for _, tc := range []struct {
		name, method, path string
		want               int
	}{
		{"missing", "GET", "/launch", 400},
		{"fragment", "GET", "/launch?url=" + url.QueryEscape("https://vendor.example/#x"), 400},
		{"duplicate", "GET", "/launch?url=https%3A%2F%2Fvendor.example&url=https%3A%2F%2Fpublic.example", 400},
		{"unknown", "GET", "/launch?url=https://unknown.example/", 403},
		{"blocked", "GET", "/launch?url=https://blocked.example/", 403},
		{"disabled", "GET", "/launch?url=https://disabled.example/", 403},
		{"unsafe DNS", "GET", "/launch?url=https://private.example/", 403},
		{"GET denied", "GET", "/launch?url=https://post.example/", 403},
		{"login required", "GET", "/launch?url=https://vendor.example/private?term=secret", 401},
		{"public exception", "GET", "/launch?url=https://public.example/asset.js", 302},
		{"POST", "POST", "/launch?url=https://public.example/", 405},
		{"HEAD", "HEAD", "/launch?url=https://public.example/", 405},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.name == "login required" {
				req.Header.Set("Accept", "application/json")
			}
			// A management key must not replace a patron session.
			req.Header.Set("Authorization", "Bearer secret")
			server.Routes().ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("got %d want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
			if tc.want == 401 && (rec.Header().Get("Location") != "" || !strings.Contains(rec.Body.String(), `"login_url":"/login"`) || strings.Contains(rec.Body.String(), "secret")) {
				t.Fatalf("unsafe login response: %s", rec.Body.String())
			}
		})
	}
	t.Setenv("APP_PROXY_REQUIRE_LOGIN", "false")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, httptest.NewRequest("GET", "/launch?url=https://vendor.example/", nil))
	if rec.Code != 302 {
		t.Fatalf("explicit login-disabled mode: %d %s", rec.Code, rec.Body.String())
	}
	if err := server.store.UpsertResource(resources.Resource{ID: "vendor", Name: "Vendor", Status: "disabled", Domains: []resources.DomainRule{{Host: "vendor.example"}}}); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, httptest.NewRequest("GET", "/launch?url=https://vendor.example/", nil))
	if rec.Code != 403 {
		t.Fatalf("resource disablement did not take effect: %d %s", rec.Code, rec.Body.String())
	}
}

func TestLaunchSubpathsCannotRecoverVendorContent(t *testing.T) {
	t.Setenv("APP_PROXY_REFERER_RECOVERY", "true")
	server := newTestServer(t, "secret")
	for _, path := range []string{"/launch/", "/launch/missing"} {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("Referer", "http://example.com/odo/https/vendor.example/page")
		rec := httptest.NewRecorder()
		server.Routes().ServeHTTP(rec, req)
		if rec.Code != 404 {
			t.Fatalf("reserved launch path recovered: %d %s", rec.Code, rec.Body.String())
		}
	}
}
