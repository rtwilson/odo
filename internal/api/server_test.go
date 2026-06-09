package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"example.org/odo/internal/accesslog"
	"example.org/odo/internal/db"
	"example.org/odo/internal/proxy"
	"example.org/odo/internal/resources"
)

func TestHealthDoesNotRequireAPIKey(t *testing.T) {
	server := newTestServer(t, "secret")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected public health endpoint to return 200, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestRootRedirectsToAdmin(t *testing.T) {
	server := newTestServer(t, "secret")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/admin" {
		t.Fatalf("expected root redirect to /admin, got %d location %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestUnknownPathReturns404(t *testing.T) {
	server := newTestServer(t, "secret")

	req := httptest.NewRequest(http.MethodGet, "/china/example", nil)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected unknown path to return 404, got %d with location %q and body %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
}

func TestOpenAPIYAML(t *testing.T) {
	server := newTestServer(t, "secret")

	req := httptest.NewRequest(http.MethodGet, "/openapi.yaml", nil)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected openapi.yaml to return 200, got %d with body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "openapi: 3.1.0") {
		t.Fatalf("expected OpenAPI 3.1 marker in response, got %q", rec.Body.String())
	}
}

func TestDocsUseOdoProxyRoute(t *testing.T) {
	for _, path := range []string{"../../README.md", "../../openapi/openapi.yaml"} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		text := string(body)
		if !strings.Contains(text, "/odo") {
			t.Fatalf("expected %s to reference /odo", path)
		}
		for _, stale := range []string{"/p?url", "`/p", " /p:", "\n  /p:"} {
			if strings.Contains(text, stale) {
				t.Fatalf("expected %s not to contain stale proxy route %q", path, stale)
			}
		}
	}
}

func TestAdminContainsResourceEditorControls(t *testing.T) {
	server := newTestServer(t, "secret")

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected admin to return 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"Load Resources", "Save Resource", "Delete Resource", "New Resource", "Admin API Key", "Proxy Test", "Test Rule", "Open Through Proxy", "Fetch Through Proxy", "Load Access Logs", "Load Proxy Diagnostics"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected admin body to contain %q", want)
		}
	}
}

func TestProxyTestFetchRequiresAPIKey(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	server := newProxyFetchTestServerWithAdmin(t, upstream.URL, "secret")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/proxy/test-fetch", strings.NewReader(`{"url":"https://www.jstor.org/"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected missing API key to return 401, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestProxyTestFetchDeniedForNonAllowlistedURL(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	server := newProxyFetchTestServer(t, upstream.URL)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/proxy/test-fetch", strings.NewReader(`{"url":"https://bad.example/"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected denied response to return 200, got %d with body %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["allowed"] != false || body["reason"] == "" || body["target_host"] != "bad.example" {
		t.Fatalf("expected denied response with safe target host, got %#v", body)
	}
}

func TestProxyTestFetchReturnsPreviewForAllowlistedUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "max-age=60")
		w.Header().Set("Set-Cookie", "vendor=secret")
		_, _ = w.Write([]byte("<!doctype html><title>JSTOR</title>"))
	}))
	defer upstream.Close()
	server := newProxyFetchTestServer(t, upstream.URL)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/proxy/test-fetch", strings.NewReader(`{"url":"https://www.jstor.org/"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected proxy test fetch to return 200, got %d with body %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["allowed"] != true || body["status"].(float64) != 200 || !strings.Contains(body["body_preview"].(string), "<!doctype html>") {
		t.Fatalf("expected allowed preview response, got %#v", body)
	}
	headers := body["headers"].(map[string]any)
	if headers["content-type"] != "text/html; charset=utf-8" || headers["cache-control"] != "max-age=60" {
		t.Fatalf("expected safe headers, got %#v", headers)
	}
	if _, ok := headers["set-cookie"]; ok {
		t.Fatalf("Set-Cookie should not be returned in header summary: %#v", headers)
	}
}

func TestProxyTestFetchTruncatesLargePreview(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("a"), 20*1024))
	}))
	defer upstream.Close()
	server := newProxyFetchTestServer(t, upstream.URL)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/proxy/test-fetch", strings.NewReader(`{"url":"https://www.jstor.org/"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["body_preview_truncated"] != true {
		t.Fatalf("expected truncated preview, got %#v", body)
	}
	if len(body["body_preview"].(string)) != 16*1024 {
		t.Fatalf("expected 16 KiB preview, got %d", len(body["body_preview"].(string)))
	}
}

func TestRecentAccessLogsRequiresAPIKey(t *testing.T) {
	server := newTestServer(t, "secret")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/logs/access/recent", nil)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected recent access logs without API key to return 401, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestRecentAccessLogsReturnsSafeEntries(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	accessLogger, err := accesslog.New(accesslog.FormatPrivacy, io.Discard)
	if err != nil {
		t.Fatalf("create access logger: %v", err)
	}
	server := newProxyFetchTestServerWithAccessLog(t, upstream.URL, accessLogger)

	proxyReq := httptest.NewRequest(http.MethodGet, "/odo?url=https://www.jstor.org/stable/example?token=secret", nil)
	proxyReq.Header.Set("Authorization", "Bearer should-not-appear")
	proxyReq.Header.Set("Cookie", "session=should-not-appear")
	proxyRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(proxyRec, proxyReq)
	if proxyRec.Code != http.StatusOK {
		t.Fatalf("expected proxy request to return 200, got %d with body %s", proxyRec.Code, proxyRec.Body.String())
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/logs/access/recent", nil)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected recent logs to return 200, got %d with body %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, leaked := range []string{"https://www.jstor.org/stable/example", "?url=", "token=secret", "should-not-appear"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("recent access logs leaked %q: %s", leaked, body)
		}
	}
	for _, want := range []string{`"route":"/odo"`, `"target_host":"www.jstor.org"`, `"resource_id":"jstor"`, `"decision":"allowed"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected recent access logs to contain %q, got %s", want, body)
		}
	}
}

func TestPrivacyAccessLogForProxyStubUsesSafeMetadata(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	var logs bytes.Buffer
	accessLogger, err := accesslog.New(accesslog.FormatPrivacy, &logs)
	if err != nil {
		t.Fatalf("create access logger: %v", err)
	}
	server := newProxyFetchTestServerWithAccessLog(t, upstream.URL, accessLogger)

	req := httptest.NewRequest(http.MethodGet, "/odo?url=https://www.jstor.org/stable/example", nil)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected proxy stub to return 200, got %d with body %s", rec.Code, rec.Body.String())
	}
	line := logs.String()
	if strings.Contains(line, "https://www.jstor.org/stable/example") || strings.Contains(line, "?url=") {
		t.Fatalf("privacy proxy log leaked full target URL: %q", line)
	}
	for _, want := range []string{"route=/odo", "target_host=www.jstor.org", "resource_id=jstor", "decision=allowed"} {
		if !strings.Contains(line, want) {
			t.Fatalf("expected proxy access log to contain %q, got %q", want, line)
		}
	}
}

func TestProxyStubAllowsSafeMatchedURLWithPublicDNS(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	server := newProxyFetchTestServer(t, upstream.URL)
	req := httptest.NewRequest(http.MethodGet, "/odo?url=https://www.jstor.org/stable/example", nil)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected safe matched proxy URL to return 200, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestProxyPathModeRouteAllowsSafeMatchedURL(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	server := newProxyFetchTestServer(t, upstream.URL)
	req := httptest.NewRequest(http.MethodGet, "/odo/https/www.jstor.org/stable/example", nil)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected path-mode proxy URL to return 200, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestProxyFetchesAllowlistedUpstreamContent(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET upstream, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "max-age=60")
		w.Header().Set("Set-Cookie", "secret=value")
		_, _ = w.Write([]byte("upstream body"))
	}))
	defer upstream.Close()

	server := newProxyFetchTestServer(t, upstream.URL)
	req := httptest.NewRequest(http.MethodGet, "/odo?url=https://www.jstor.org/stable/example", nil)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d with body %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "upstream body" {
		t.Fatalf("expected upstream body, got %q", rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != "text/plain" {
		t.Fatalf("expected Content-Type copied, got %q", rec.Header().Get("Content-Type"))
	}
	if rec.Header().Get("Cache-Control") != "max-age=60" {
		t.Fatalf("expected Cache-Control copied, got %q", rec.Header().Get("Cache-Control"))
	}
	if strings.Contains(rec.Header().Get("Set-Cookie"), "secret=value") {
		t.Fatalf("expected upstream Set-Cookie not copied, got %q", rec.Header().Get("Set-Cookie"))
	}
}

func TestProxyHEADWorks(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Fatalf("expected HEAD upstream, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "text/plain")
	}))
	defer upstream.Close()

	server := newProxyFetchTestServer(t, upstream.URL)
	req := httptest.NewRequest(http.MethodHead, "/odo?url=https://www.jstor.org/stable/example", nil)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d with body %s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("expected empty HEAD body, got %q", rec.Body.String())
	}
}

func TestProxyPUTReturns405(t *testing.T) {
	server := newProxyFetchTestServer(t, "http://127.0.0.1")
	req := httptest.NewRequest(http.MethodPut, "/odo?url=https://www.jstor.org/stable/example", nil)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestProxyRefusesNonAllowlistedURL(t *testing.T) {
	server := newProxyFetchTestServer(t, "http://127.0.0.1")
	req := httptest.NewRequest(http.MethodGet, "/odo?url=https://example.org/", nil)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestProxyBlockActionDeniesFetch(t *testing.T) {
	server := newProxyFetchTestServer(t, "http://127.0.0.1")
	if err := server.store.UpsertResource(resources.Resource{
		ID:     "blocked",
		Name:   "Blocked",
		Status: "active",
		Domains: []resources.DomainRule{
			{Host: "blocked.example.org", Match: "exact", Role: "blocked", Action: "block"},
		},
	}); err != nil {
		t.Fatalf("upsert blocked resource: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/odo?url=https://blocked.example.org/pixel", nil)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d with body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "explicitly_blocked") {
		t.Fatalf("expected explicit block reason, got %s", rec.Body.String())
	}
}

func TestProxyAllowActionDoesNotFetch(t *testing.T) {
	server := newProxyFetchTestServer(t, "http://127.0.0.1")
	if err := server.store.UpsertResource(resources.Resource{
		ID:     "external",
		Name:   "External",
		Status: "active",
		Domains: []resources.DomainRule{
			{Host: "external.example.org", Match: "exact", Role: "external", Action: "allow"},
		},
	}); err != nil {
		t.Fatalf("upsert external resource: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/odo?url=https://external.example.org/page", nil)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d with body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not_proxyable") {
		t.Fatalf("expected non-proxyable reason, got %s", rec.Body.String())
	}
}

func TestProxyRefusesUnsafeURL(t *testing.T) {
	server := newProxyFetchTestServer(t, "http://127.0.0.1")
	req := httptest.NewRequest(http.MethodGet, "/odo?url=http://www.jstor.org/stable/example", nil)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestProxyRedirectToAllowlistedTargetIsRewritten(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://www.jstor.org/stable/next", http.StatusFound)
	}))
	defer upstream.Close()

	server := newProxyFetchTestServer(t, upstream.URL)
	req := httptest.NewRequest(http.MethodGet, "/odo?url=https://www.jstor.org/stable/example", nil)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d with body %s", rec.Code, rec.Body.String())
	}
	location := rec.Header().Get("Location")
	if location != "/odo/https/www.jstor.org/stable/next" {
		t.Fatalf("expected local proxied redirect, got %q", location)
	}
}

func TestProxyRedirectToUnsafeTargetIsRejected(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://www.jstor.org/unsafe", http.StatusFound)
	}))
	defer upstream.Close()

	server := newProxyFetchTestServer(t, upstream.URL)
	req := httptest.NewRequest(http.MethodGet, "/odo?url=https://www.jstor.org/stable/example", nil)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestProxyDoesNotForwardUnsafeRequestHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, name := range []string{"Cookie", "Authorization", "Proxy-Authorization", "X-Forwarded-For", "X-Real-IP", "Forwarded", "Connection", "Upgrade", "Host", "Referer"} {
			if name == "Host" {
				continue
			}
			if r.Header.Get(name) != "" {
				t.Fatalf("unsafe header %s was forwarded as %q", name, r.Header.Get(name))
			}
		}
		if r.Header.Get("Accept") != "text/html" || r.Header.Get("Accept-Language") != "en-US" || r.Header.Get("User-Agent") != "odo-test" {
			t.Fatalf("safe headers were not forwarded as expected: %#v", r.Header)
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	server := newProxyFetchTestServer(t, upstream.URL)
	req := httptest.NewRequest(http.MethodGet, "/odo?url=https://www.jstor.org/stable/example", nil)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("User-Agent", "odo-test")
	req.Header.Set("Cookie", "secret=value")
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Referer", "https://private.example/search?q=secret")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestProxyStubRejectsPrivateResolvedIP(t *testing.T) {
	server := newTestServerWithResolver(t, "", t.TempDir(), func(ctx context.Context, host string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	})

	req := httptest.NewRequest(http.MethodGet, "/odo?url=https://www.jstor.org/stable/example", nil)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected private resolved proxy URL to return 403, got %d with body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "target URL is not allowed") || !strings.Contains(rec.Body.String(), "hostname resolves to private IP") {
		t.Fatalf("expected safe denial response, got %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "https://www.jstor.org/stable/example") {
		t.Fatalf("denial response leaked full target URL: %s", rec.Body.String())
	}
}

func TestManagementEndpointWorksWithoutConfiguredAPIKey(t *testing.T) {
	server := newTestServer(t, "")
	body := bytes.NewBufferString(`{
  "id": "jstor",
  "name": "JSTOR",
  "domains": [{"host": "www.jstor.org"}]
}`)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/resources", body)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected unset API key to allow dev management request, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestManagementEndpointAllowsValidAPIKey(t *testing.T) {
	server := newTestServer(t, "secret")
	body := bytes.NewBufferString(`{
  "id": "jstor",
  "name": "JSTOR",
  "domains": [{"host": "www.jstor.org"}]
}`)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/resources", body)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected valid API key to return 200, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestGetResourceReturnsExistingResource(t *testing.T) {
	server := newTestServer(t, "secret")
	upsertTestResource(t, server, "jstor")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/resources/jstor", nil)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d with body %s", rec.Code, rec.Body.String())
	}
	var resource resources.Resource
	if err := json.Unmarshal(rec.Body.Bytes(), &resource); err != nil {
		t.Fatalf("decode resource: %v", err)
	}
	if resource.ID != "jstor" {
		t.Fatalf("expected jstor resource, got %#v", resource)
	}
}

func TestGetResourceReturns404ForMissingResource(t *testing.T) {
	server := newTestServer(t, "secret")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/resources/missing", nil)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestDeleteResourceDeletesExistingResourceAndAudits(t *testing.T) {
	server := newTestServer(t, "secret")
	upsertTestResource(t, server, "jstor")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/resources/jstor", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d with body %s", rec.Code, rec.Body.String())
	}
	if _, found, err := server.store.GetResource("jstor"); err != nil || found {
		t.Fatalf("expected resource deleted, found=%v err=%v", found, err)
	}
	events, err := server.store.ListAuditEvents(10)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	var sawDelete bool
	for _, event := range events {
		if event.Event == "resource.delete" && strings.Contains(event.Detail, "jstor") {
			sawDelete = true
		}
	}
	if !sawDelete {
		t.Fatalf("expected resource.delete audit event, got %#v", events)
	}
}

func TestDeleteResourceReturns404ForMissingResource(t *testing.T) {
	server := newTestServer(t, "secret")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/resources/missing", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestDeleteResourceRequiresAPIKey(t *testing.T) {
	server := newTestServer(t, "secret")
	upsertTestResource(t, server, "jstor")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/resources/jstor", nil)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestManagementEndpointRejectsMissingAPIKey(t *testing.T) {
	server := newTestServer(t, "secret")
	body := bytes.NewBufferString(`{"id":"jstor","name":"JSTOR"}`)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/resources", body)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected missing API key to return 401, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestManagementEndpointRejectsInvalidAPIKey(t *testing.T) {
	server := newTestServer(t, "secret")
	body := bytes.NewBufferString(`{"id":"jstor","name":"JSTOR"}`)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/resources", body)
	req.Header.Set("Authorization", "Bearer wrong")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected invalid API key to return 403, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigImportRequiresAPIKey(t *testing.T) {
	server := newTestServer(t, "secret")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/import", nil)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected config import without API key to return 401, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestValidateConfigEndpointSucceedsWithValidConfig(t *testing.T) {
	configDir := t.TempDir()
	writeAPIResourceConfig(t, configDir, "jstor.json", `{
  "id": "jstor",
  "name": "JSTOR",
  "domains": [{"host": "www.jstor.org"}]
}`)
	server := newTestServerWithConfig(t, "secret", configDir)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/validate", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected validation endpoint to return 200, got %d with body %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Valid   bool `json:"valid"`
		Results []struct {
			Valid      bool   `json:"valid"`
			ResourceID string `json:"resource_id"`
		} `json:"results"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode validation response: %v", err)
	}
	if !body.Valid || len(body.Results) != 1 || !body.Results[0].Valid || body.Results[0].ResourceID != "jstor" {
		t.Fatalf("unexpected validation response: %#v", body)
	}

	revisions, err := server.store.ListConfigRevisions(10)
	if err != nil {
		t.Fatalf("list revisions after validation: %v", err)
	}
	if len(revisions) != 0 {
		t.Fatalf("validation endpoint should not create revisions, got %#v", revisions)
	}
}

func TestValidateConfigEndpointReturnsInvalidConfig(t *testing.T) {
	configDir := t.TempDir()
	writeAPIResourceConfig(t, configDir, "bad.json", `{
  "id": "",
  "name": "Bad",
  "domains": []
}`)
	server := newTestServerWithConfig(t, "secret", configDir)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/validate", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected validation endpoint to return 200, got %d with body %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Valid   bool `json:"valid"`
		Results []struct {
			Valid  bool     `json:"valid"`
			Errors []string `json:"errors"`
		} `json:"results"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode validation response: %v", err)
	}
	if body.Valid || len(body.Results) != 1 || body.Results[0].Valid || len(body.Results[0].Errors) == 0 {
		t.Fatalf("unexpected validation response: %#v", body)
	}
}

func TestValidateConfigEndpointRequiresAPIKey(t *testing.T) {
	server := newTestServer(t, "secret")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/validate", nil)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected validate config without API key to return 401, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestConfigRevisionEndpointsReturnListAndDetail(t *testing.T) {
	configDir := t.TempDir()
	writeAPIResourceConfig(t, configDir, "jstor.json", `{
  "id": "jstor",
  "name": "JSTOR",
  "domains": [{"host": "www.jstor.org"}]
}`)
	server := newTestServerWithConfig(t, "secret", configDir)

	importReq := httptest.NewRequest(http.MethodPost, "/api/v1/config/import", nil)
	importReq.Header.Set("Authorization", "Bearer secret")
	importRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(importRec, importReq)
	if importRec.Code != http.StatusOK {
		t.Fatalf("expected import to return 200, got %d with body %s", importRec.Code, importRec.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/config/revisions", nil)
	listReq.Header.Set("Authorization", "Bearer secret")
	listRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("expected revision list to return 200, got %d with body %s", listRec.Code, listRec.Body.String())
	}

	var listBody struct {
		Revisions []map[string]any `json:"revisions"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &listBody); err != nil {
		t.Fatalf("decode revision list: %v", err)
	}
	if len(listBody.Revisions) != 1 {
		t.Fatalf("expected one revision in list, got %#v", listBody)
	}
	if _, exists := listBody.Revisions[0]["config_json"]; exists {
		t.Fatalf("revision list should not include config_json: %#v", listBody.Revisions[0])
	}
	id, ok := listBody.Revisions[0]["id"].(float64)
	if !ok || id <= 0 {
		t.Fatalf("expected numeric revision id, got %#v", listBody.Revisions[0]["id"])
	}

	detailReq := httptest.NewRequest(http.MethodGet, "/api/v1/config/revisions/"+strconv.FormatInt(int64(id), 10), nil)
	detailReq.Header.Set("Authorization", "Bearer secret")
	detailRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(detailRec, detailReq)
	if detailRec.Code != http.StatusOK {
		t.Fatalf("expected revision detail to return 200, got %d with body %s", detailRec.Code, detailRec.Body.String())
	}

	var detailBody map[string]any
	if err := json.Unmarshal(detailRec.Body.Bytes(), &detailBody); err != nil {
		t.Fatalf("decode revision detail: %v", err)
	}
	if detailBody["config_json"] == "" {
		t.Fatalf("revision detail should include config_json: %#v", detailBody)
	}
}

func TestConfigRevisionEndpointsRequireAPIKey(t *testing.T) {
	server := newTestServer(t, "secret")

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/config/revisions", nil)
	listRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected revision list without API key to return 401, got %d with body %s", listRec.Code, listRec.Body.String())
	}

	detailReq := httptest.NewRequest(http.MethodGet, "/api/v1/config/revisions/1", nil)
	detailRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(detailRec, detailReq)
	if detailRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected revision detail without API key to return 401, got %d with body %s", detailRec.Code, detailRec.Body.String())
	}
}

func newTestServer(t *testing.T, adminKey string) *Server {
	return newTestServerWithConfig(t, adminKey, t.TempDir())
}

func newTestServerWithConfig(t *testing.T, adminKey, configDir string) *Server {
	accessLogger, err := accesslog.New(accesslog.FormatPrivacy, io.Discard)
	if err != nil {
		t.Fatalf("create access logger: %v", err)
	}
	return newTestServerWithConfigAndAccessLog(t, adminKey, configDir, accessLogger)
}

func newTestServerWithConfigAndAccessLog(t *testing.T, adminKey, configDir string, accessLogger *accesslog.Logger) *Server {
	return newTestServerWithConfigAccessLogAndResolver(t, adminKey, configDir, accessLogger, publicTestResolver)
}

func newTestServerWithResolver(t *testing.T, adminKey, configDir string, lookup proxy.IPLookupFunc) *Server {
	accessLogger, err := accesslog.New(accesslog.FormatPrivacy, io.Discard)
	if err != nil {
		t.Fatalf("create access logger: %v", err)
	}
	return newTestServerWithConfigAccessLogAndResolver(t, adminKey, configDir, accessLogger, lookup)
}

func newTestServerWithConfigAccessLogAndResolver(t *testing.T, adminKey, configDir string, accessLogger *accesslog.Logger, lookup proxy.IPLookupFunc) *Server {
	return newTestServerWithConfigAccessLogResolverAndClient(t, adminKey, configDir, accessLogger, lookup, proxy.DefaultHTTPClient())
}

func newTestServerWithConfigAccessLogResolverAndClient(t *testing.T, adminKey, configDir string, accessLogger *accesslog.Logger, lookup proxy.IPLookupFunc, client *http.Client) *Server {
	t.Helper()

	store, err := db.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatalf("open temp store: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close temp store: %v", err)
		}
	})
	if err := store.Migrate(); err != nil {
		t.Fatalf("migrate temp store: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewServerWithAccessLoggerResolverAndHTTPClient(store, configDir, adminKey, logger, accessLogger, lookup, client)
}

func publicTestResolver(ctx context.Context, host string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
}

func newProxyFetchTestServer(t *testing.T, upstreamURL string) *Server {
	t.Helper()
	accessLogger, err := accesslog.New(accesslog.FormatPrivacy, io.Discard)
	if err != nil {
		t.Fatalf("create access logger: %v", err)
	}
	return newProxyFetchTestServerWithAccessLogAndAdmin(t, upstreamURL, accessLogger, "")
}

func newProxyFetchTestServerWithAdmin(t *testing.T, upstreamURL, adminKey string) *Server {
	t.Helper()
	accessLogger, err := accesslog.New(accesslog.FormatPrivacy, io.Discard)
	if err != nil {
		t.Fatalf("create access logger: %v", err)
	}
	return newProxyFetchTestServerWithAccessLogAndAdmin(t, upstreamURL, accessLogger, adminKey)
}

func newProxyFetchTestServerWithAccessLog(t *testing.T, upstreamURL string, accessLogger *accesslog.Logger) *Server {
	t.Helper()
	return newProxyFetchTestServerWithAccessLogAndAdmin(t, upstreamURL, accessLogger, "")
}

func newProxyFetchTestServerWithAccessLogAndAdmin(t *testing.T, upstreamURL string, accessLogger *accesslog.Logger, adminKey string) *Server {
	t.Helper()
	client := &http.Client{
		Transport: rewriteTransport(t, upstreamURL),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	server := newTestServerWithConfigAccessLogResolverAndClient(t, adminKey, t.TempDir(), accessLogger, publicTestResolver, client)
	if err := server.store.UpsertResource(resources.Resource{
		ID:      "jstor",
		Name:    "JSTOR",
		Status:  "active",
		Domains: []resources.DomainRule{{Host: "www.jstor.org", Match: "exact"}},
	}); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}
	return server
}

func rewriteTransport(t *testing.T, upstreamURL string) http.RoundTripper {
	t.Helper()
	upstream, err := url.Parse(upstreamURL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}
	return roundTripFunc(func(req *http.Request) (*http.Response, error) {
		req.URL.Scheme = upstream.Scheme
		req.URL.Host = upstream.Host
		req.Host = upstream.Host
		return http.DefaultTransport.RoundTrip(req)
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func writeAPIResourceConfig(t *testing.T, configDir, name, body string) {
	t.Helper()

	resourcesDir := filepath.Join(configDir, "resources")
	if err := os.MkdirAll(resourcesDir, 0o755); err != nil {
		t.Fatalf("create resources dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(resourcesDir, name), []byte(body), 0o644); err != nil {
		t.Fatalf("write config %s: %v", name, err)
	}
}

func upsertTestResource(t *testing.T, server *Server, id string) {
	t.Helper()

	if err := server.store.UpsertResource(resources.Resource{
		ID:     id,
		Name:   strings.ToUpper(id),
		Status: "active",
		Domains: []resources.DomainRule{
			{Host: id + ".example.org", Match: "exact", Role: "content", Action: "proxy"},
		},
	}); err != nil {
		t.Fatalf("upsert test resource: %v", err)
	}
}
