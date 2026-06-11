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
	"time"

	"example.org/odo/internal/accesslog"
	"example.org/odo/internal/auth/local"
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
	for _, want := range []string{"Dashboard", "Resources", "Config", "Proxy Test", "Diagnostics", "API Keys", "Users", "Auth", "Settings", "Load Resources", "Save Resource", "Delete Resource", "New Resource", "Admin API Key", "Test Rule", "Open Through Proxy", "Fetch Through Proxy", "Load Access Logs", "Load Proxy Diagnostics", "Load Missed Rewrites", "Load API Keys", "New API Key", "Create API Key", "Rotate Selected Key", "Revoke Selected Key", "Delete Selected Key", "Load Users", "New User", "Create User", "Update User", "Set Password", "Revoke Sessions", "Load SAML Providers", "New SAML Provider", "Save SAML Provider", "Delete SAML Provider", "Open SP Metadata", "Resource Config Builder", "Start with a title, entry URL, and main domain. Generate and validate JSON before saving. Add additional domains only when testing or diagnostics show they are needed.", "docs/resource-how-to.md", "Add Domain", "Anonymous URL Rules", "Add Anonymous Rule", "Content Rewrite Rules", "Add Rewrite Rule", "rewrite_javascript", "Generate JSON", "Validate JSON", "Save as Resource", "Export JSON"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected admin body to contain %q", want)
		}
	}
	if !strings.Contains(body, "/api/v1/api-keys") {
		t.Fatalf("expected admin JS to reference /api/v1/api-keys")
	}
	if strings.Contains(body, `data-odo-js-shim="true"`) {
		t.Fatalf("admin UI should not include proxy JS shim")
	}
}

func TestResourceDocumentationExistsAndReadmeLinksIt(t *testing.T) {
	root := filepath.Join("..", "..")
	docPath := filepath.Join(root, "docs", "resource-how-to.md")
	doc, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("expected docs/resource-how-to.md to exist: %v", err)
	}
	for _, want := range []string{"# Adding Resources in Odo", "What is an Odo resource?", "JSTOR-style example", "Economist-style example"} {
		if !strings.Contains(string(doc), want) {
			t.Fatalf("expected resource how-to to contain %q", want)
		}
	}

	readme, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	for _, want := range []string{"## Adding resources", "docs/resource-how-to.md", "Resource Config Builder", "Proxy Test and Diagnostics"} {
		if !strings.Contains(string(readme), want) {
			t.Fatalf("expected README to contain %q", want)
		}
	}
	if strings.Contains(strings.ToLower(string(readme)), "ezproxy") || strings.Contains(strings.ToLower(string(doc)), "ezproxy") {
		t.Fatalf("documentation should not reference EZproxy")
	}
}

func TestUserAPICreatesUserWithHashedPasswordAndNoHashInJSON(t *testing.T) {
	server := newTestServer(t, "secret")
	body := `{"username":"alice","email":"alice@example.edu","display_name":"Alice","password":"correct horse battery","roles":["user"],"status":"active"}`

	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected user create 201, got %d with body %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "password_hash") || strings.Contains(rec.Body.String(), "correct horse") {
		t.Fatalf("user JSON should not expose password material: %s", rec.Body.String())
	}
	user, found, err := server.store.GetUserByUsername("alice")
	if err != nil || !found {
		t.Fatalf("expected stored user, found=%v err=%v", found, err)
	}
	if user.PasswordHash == "" || user.PasswordHash == "correct horse battery" || !local.CheckPassword(user.PasswordHash, "correct horse battery") {
		t.Fatalf("expected bcrypt password hash, got %q", user.PasswordHash)
	}

	dupReq := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(body))
	dupReq.Header.Set("Content-Type", "application/json")
	dupReq.Header.Set("Authorization", "Bearer secret")
	dupRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(dupRec, dupReq)
	if dupRec.Code != http.StatusConflict {
		t.Fatalf("expected duplicate username 409, got %d with body %s", dupRec.Code, dupRec.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	listReq.Header.Set("Authorization", "Bearer secret")
	listRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("expected user list 200, got %d with body %s", listRec.Code, listRec.Body.String())
	}
	if strings.Contains(listRec.Body.String(), "password_hash") || strings.Contains(listRec.Body.String(), user.PasswordHash) {
		t.Fatalf("user list should not expose password hashes: %s", listRec.Body.String())
	}
}

func TestUserAPIRequiresAdminAPIKey(t *testing.T) {
	server := newTestServer(t, "secret")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected missing API key 401, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestLoginResourcesAndProxyRequireLocalSession(t *testing.T) {
	t.Setenv("APP_PROXY_REQUIRE_LOGIN", "")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("proxied ok"))
	}))
	defer upstream.Close()
	server := newProxyFetchTestServer(t, upstream.URL)
	createLocalTestUser(t, server, "alice", "correct horse battery")
	if err := server.store.UpsertResource(resources.Resource{
		ID:        "portal",
		Name:      "Portal",
		Title:     "Portal Resource",
		Status:    "active",
		EntryURLs: []string{"https://www.jstor.org/"},
		Domains:   []resources.DomainRule{{Host: "www.jstor.org", Match: "exact", Action: "proxy"}},
	}); err != nil {
		t.Fatalf("upsert portal resource: %v", err)
	}

	anon := httptest.NewRequest(http.MethodGet, "/odo?url=https://www.jstor.org/", nil)
	anon.Header.Set("Accept", "text/html")
	anonRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(anonRec, anon)
	if anonRec.Code != http.StatusFound || !strings.HasPrefix(anonRec.Header().Get("Location"), "/login?next=") {
		t.Fatalf("expected proxy document to redirect to login, got %d location %q", anonRec.Code, anonRec.Header().Get("Location"))
	}

	cookie := loginTestUser(t, server, "alice", "correct horse battery", "/resources")
	resourcesReq := httptest.NewRequest(http.MethodGet, "/resources", nil)
	resourcesReq.AddCookie(cookie)
	resourcesRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(resourcesRec, resourcesReq)
	if resourcesRec.Code != http.StatusOK || !strings.Contains(resourcesRec.Body.String(), "Portal Resource") || !strings.Contains(resourcesRec.Body.String(), "/odo/https/www.jstor.org/") {
		t.Fatalf("expected signed-in resource portal, got %d body %s", resourcesRec.Code, resourcesRec.Body.String())
	}

	proxyReq := httptest.NewRequest(http.MethodGet, "/odo?url=https://www.jstor.org/", nil)
	proxyReq.AddCookie(cookie)
	proxyRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(proxyRec, proxyReq)
	if proxyRec.Code != http.StatusOK || !strings.Contains(proxyRec.Body.String(), "proxied ok") {
		t.Fatalf("expected signed-in proxy fetch 200, got %d body %s", proxyRec.Code, proxyRec.Body.String())
	}
	if got := proxyRec.Header().Values("Set-Cookie"); strings.Contains(strings.Join(got, "\n"), "vendor") {
		t.Fatalf("proxy response should not expose upstream cookies: %v", got)
	}
}

func TestDisabledUserCannotReuseSession(t *testing.T) {
	t.Setenv("APP_PROXY_REQUIRE_LOGIN", "")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("proxied ok"))
	}))
	defer upstream.Close()
	server := newProxyFetchTestServer(t, upstream.URL)
	user := createLocalTestUser(t, server, "bob", "correct horse battery")
	cookie := loginTestUser(t, server, "bob", "correct horse battery", "/resources")

	if _, found, err := server.store.SetUserStatus(user.ID, "disabled"); err != nil || !found {
		t.Fatalf("disable user found=%v err=%v", found, err)
	}
	proxyReq := httptest.NewRequest(http.MethodGet, "/odo?url=https://www.jstor.org/", nil)
	proxyReq.Header.Set("Accept", "text/html")
	proxyReq.AddCookie(cookie)
	proxyRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(proxyRec, proxyReq)
	if proxyRec.Code != http.StatusFound || !strings.HasPrefix(proxyRec.Header().Get("Location"), "/login?next=") {
		t.Fatalf("expected disabled user's session to be rejected, got %d location %q", proxyRec.Code, proxyRec.Header().Get("Location"))
	}

	loginReq := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=bob&password=correct+horse+battery"))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected disabled user login to fail, got %d body %s", loginRec.Code, loginRec.Body.String())
	}
}

func TestAccessLogIncludesSafeUserSessionMetadata(t *testing.T) {
	t.Setenv("APP_PROXY_REQUIRE_LOGIN", "")
	var buf bytes.Buffer
	accessLogger, err := accesslog.New(accesslog.FormatPrivacy, &buf)
	if err != nil {
		t.Fatalf("create access logger: %v", err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("proxied ok"))
	}))
	defer upstream.Close()
	server := newProxyFetchTestServerWithAccessLog(t, upstream.URL, accessLogger)
	user := createLocalTestUser(t, server, "carol", "correct horse battery")
	cookie := loginTestUser(t, server, "carol", "correct horse battery", "/resources")

	req := httptest.NewRequest(http.MethodGet, "/odo?url=https://www.jstor.org/stable/example?token=secret", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected proxy fetch 200, got %d body %s", rec.Code, rec.Body.String())
	}
	logs := buf.String()
	if !strings.Contains(logs, "user_id="+user.ID) || !strings.Contains(logs, "session_id=sess_") || !strings.Contains(logs, "resource_id=jstor") || !strings.Contains(logs, "target_host=www.jstor.org") {
		t.Fatalf("expected safe user/session/resource metadata in access log, got:\n%s", logs)
	}
	if strings.Contains(logs, "token=secret") || strings.Contains(logs, "stable/example?") {
		t.Fatalf("privacy access log should not include target query/full URL, got:\n%s", logs)
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

func TestUnknownLocalPathWithProxiedRefererIsRecovered(t *testing.T) {
	var upstreamPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamPath = r.URL.Path
		_, _ = w.Write([]byte("remote entry"))
	}))
	defer upstream.Close()

	server := newProxyFetchTestServer(t, upstream.URL)
	req := httptest.NewRequest(http.MethodGet, "/mfe-copper-roof/status-banner/5e83f48a/remoteEntry.js", nil)
	req.Header.Set("Referer", "http://127.0.0.1:8080/odo/https/www.jstor.org/")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected recovered request to return 200, got %d with body %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "remote entry" {
		t.Fatalf("expected upstream body, got %q", rec.Body.String())
	}
	if upstreamPath != "/mfe-copper-roof/status-banner/5e83f48a/remoteEntry.js" {
		t.Fatalf("expected recovered upstream path, got %q", upstreamPath)
	}
	events := server.missedDiag.Recent()
	if len(events) == 0 || events[0].RequestKind != proxy.RequestKindAsset || events[0].RecoveryAction != proxy.RecoveryActionSilentlyProxied {
		t.Fatalf("expected asset silent-proxy diagnostics, got %#v", events)
	}
}

func TestUnknownDocumentPathWithProxiedRefererRedirectsToCanonical(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("document recovery should redirect before fetching upstream")
	}))
	defer upstream.Close()

	server := newProxyFetchTestServer(t, upstream.URL)
	req := httptest.NewRequest(http.MethodGet, "/action/doAdvancedSearch", nil)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Referer", "http://127.0.0.1:8080/odo/https/www.jstor.org/")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected document recovery redirect, got %d with body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "/odo/https/www.jstor.org/action/doAdvancedSearch" {
		t.Fatalf("expected canonical proxy redirect, got %q", got)
	}
	events := server.missedDiag.Recent()
	if len(events) == 0 {
		t.Fatal("expected missed rewrite diagnostics event")
	}
	event := events[0]
	if event.RequestKind != proxy.RequestKindDocument || event.RecoveryAction != proxy.RecoveryActionRedirectedToCanonical || !event.Recovered {
		t.Fatalf("expected document redirect diagnostics, got %#v", event)
	}
	if event.CanonicalProxyPath != "/odo/https/www.jstor.org/action/doAdvancedSearch" {
		t.Fatalf("expected canonical path without query, got %q", event.CanonicalProxyPath)
	}
}

func TestUnknownDocumentPathRedirectPreservesQuery(t *testing.T) {
	server := newProxyFetchTestServer(t, "http://127.0.0.1")
	req := httptest.NewRequest(http.MethodGet, "/action/doBasicSearch?Query=science", nil)
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Referer", "http://127.0.0.1:8080/odo/https/www.jstor.org/")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected document recovery redirect, got %d with body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "/odo/https/www.jstor.org/action/doBasicSearch?Query=science" {
		t.Fatalf("expected query-preserving canonical redirect, got %q", got)
	}
	events := server.missedDiag.Recent()
	if len(events) == 0 || strings.Contains(events[0].CanonicalProxyPath, "Query=science") {
		t.Fatalf("expected diagnostics canonical path to omit query, got %#v", events)
	}
}

func TestUnknownCSSPathWithProxiedRefererIsSilentlyRecovered(t *testing.T) {
	var upstreamPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamPath = r.URL.Path
		w.Header().Set("Content-Type", "text/css")
		_, _ = w.Write([]byte("body { color: black; }"))
	}))
	defer upstream.Close()

	server := newProxyFetchTestServer(t, upstream.URL)
	req := httptest.NewRequest(http.MethodGet, "/assets/site.css", nil)
	req.Header.Set("Accept", "text/css,*/*")
	req.Header.Set("Referer", "http://127.0.0.1:8080/odo/https/www.jstor.org/")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected silent CSS recovery, got %d with body %s", rec.Code, rec.Body.String())
	}
	if upstreamPath != "/assets/site.css" {
		t.Fatalf("expected recovered upstream CSS path, got %q", upstreamPath)
	}
	events := server.missedDiag.Recent()
	if len(events) == 0 || events[0].RequestKind != proxy.RequestKindAsset || events[0].RecoveryAction != proxy.RecoveryActionSilentlyProxied {
		t.Fatalf("expected asset silent-proxy diagnostics, got %#v", events)
	}
}

func TestUnknownNextDataJSONWithProxiedRefererIsSilentlyRecovered(t *testing.T) {
	var upstreamPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"pageProps":{"title":"China"}}`))
	}))
	defer upstream.Close()

	server := newProxyFetchTestServer(t, upstream.URL)
	req := httptest.NewRequest(http.MethodGet, "/_next/data/build-id/sections/china.json", nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Referer", "http://127.0.0.1:8080/odo/https/www.jstor.org/china/")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected app data recovery, got %d with body %s", rec.Code, rec.Body.String())
	}
	if upstreamPath != "/_next/data/build-id/sections/china.json" {
		t.Fatalf("expected recovered upstream data path, got %q", upstreamPath)
	}
	if rec.Header().Get("Location") != "" {
		t.Fatalf("app data recovery must not redirect, got %q", rec.Header().Get("Location"))
	}
	events := server.missedDiag.Recent()
	if len(events) == 0 {
		t.Fatal("expected diagnostics event")
	}
	event := events[0]
	if event.RequestKind != proxy.RequestKindAppData || event.RecoveryAction != proxy.RecoveryActionSilentlyProxied {
		t.Fatalf("expected JSON data request to be recovered as app data, got %#v", event)
	}
	if event.SecFetchDest != "empty" || event.SecFetchMode != "cors" || event.AcceptHeaderSummary != "application/json" {
		t.Fatalf("expected safe request header summaries, got %#v", event)
	}
	if event.UpstreamStatus != http.StatusOK || !strings.Contains(event.ContentType, "application/json") {
		t.Fatalf("expected upstream response diagnostics, got %#v", event)
	}
}

func TestUnknownVendorAPIWithProxiedRefererIsRecovered(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	server := newProxyFetchTestServer(t, upstream.URL)
	req := httptest.NewRequest(http.MethodGet, "/api/foo", nil)
	req.Header.Set("Referer", "http://127.0.0.1:8080/odo/https/www.jstor.org/")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected vendor API recovery, got %d with body %s", rec.Code, rec.Body.String())
	}
	events := server.missedDiag.Recent()
	if len(events) == 0 || events[0].RequestKind != proxy.RequestKindAPI || events[0].RecoveryAction != proxy.RecoveryActionSilentlyProxied {
		t.Fatalf("expected API silent recovery diagnostics, got %#v", events)
	}
}

func TestUnknownGraphQLWithProxiedRefererIsClassifiedAPI(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	defer upstream.Close()

	server := newProxyFetchTestServer(t, upstream.URL)
	req := httptest.NewRequest(http.MethodGet, "/graphql", nil)
	req.Header.Set("Referer", "http://127.0.0.1:8080/odo/https/www.jstor.org/")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected GraphQL recovery, got %d with body %s", rec.Code, rec.Body.String())
	}
	events := server.missedDiag.Recent()
	if len(events) == 0 || events[0].RequestKind != proxy.RequestKindAPI {
		t.Fatalf("expected GraphQL to be classified as API, got %#v", events)
	}
}

func TestUnknownManifestJSONGetsJSONFallbackContentType(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header()["Content-Type"] = []string{""}
		_, _ = w.Write([]byte(`{"name":"app"}`))
	}))
	defer upstream.Close()

	server := newProxyFetchTestServer(t, upstream.URL)
	req := httptest.NewRequest(http.MethodGet, "/manifest.json", nil)
	req.Header.Set("Referer", "http://127.0.0.1:8080/odo/https/www.jstor.org/")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected manifest recovery, got %d with body %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf("expected JSON fallback content type, got %q", rec.Header().Get("Content-Type"))
	}
	events := server.missedDiag.Recent()
	if len(events) == 0 || events[0].RequestKind != proxy.RequestKindAppData {
		t.Fatalf("expected manifest to be app_data, got %#v", events)
	}
}

func TestUnknownMFERemoteEntryIsSilentlyRecovered(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("window.remote = {};"))
	}))
	defer upstream.Close()

	server := newProxyFetchTestServer(t, upstream.URL)
	req := httptest.NewRequest(http.MethodGet, "/mfe-header/remoteEntry.js", nil)
	req.Header.Set("Sec-Fetch-Dest", "script")
	req.Header.Set("Referer", "http://127.0.0.1:8080/odo/https/www.jstor.org/")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected MFE recovery, got %d with body %s", rec.Code, rec.Body.String())
	}
	events := server.missedDiag.Recent()
	if len(events) == 0 || (events[0].RequestKind != proxy.RequestKindAsset && events[0].RequestKind != proxy.RequestKindAppData) {
		t.Fatalf("expected MFE remote entry to be asset/app_data, got %#v", events)
	}
}

func TestJSONAppDataIsNotTransformedAsHTML(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"html":"<a href=\"/article\">article</a>"}`))
	}))
	defer upstream.Close()

	server := newProxyFetchTestServer(t, upstream.URL)
	req := httptest.NewRequest(http.MethodGet, "/_next/data/build-id/page.json", nil)
	req.Header.Set("Referer", "http://127.0.0.1:8080/odo/https/www.jstor.org/")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected app data recovery, got %d with body %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "/odo/https/") {
		t.Fatalf("JSON app data should not be transformed, got %s", rec.Body.String())
	}
}

func TestUnknownPostWithProxiedRefererIsNotRedirectedToGet(t *testing.T) {
	var upstreamMethod string
	var upstreamBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamMethod = r.Method
		data, _ := io.ReadAll(r.Body)
		upstreamBody = string(data)
		_, _ = w.Write([]byte("posted"))
	}))
	defer upstream.Close()

	server := newProxyFetchTestServer(t, upstream.URL)
	req := httptest.NewRequest(http.MethodPost, "/action/doBasicSearch", strings.NewReader("Query=science"))
	req.Header.Set("Referer", "http://127.0.0.1:8080/odo/https/www.jstor.org/")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected POST recovery to proxy, got %d with body %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Location") != "" {
		t.Fatalf("POST recovery must not redirect to GET, got Location %q", rec.Header().Get("Location"))
	}
	if upstreamMethod != http.MethodPost || upstreamBody != "Query=science" {
		t.Fatalf("expected upstream POST body to be preserved, got method=%q body=%q", upstreamMethod, upstreamBody)
	}
}

func TestRecoveredRequestUsesSameResourcePolicy(t *testing.T) {
	server := newProxyFetchTestServer(t, "http://127.0.0.1")
	req := httptest.NewRequest(http.MethodGet, "/assets/app.js", nil)
	req.Header.Set("Referer", "http://127.0.0.1:8080/odo/https/bad.example/")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected non-allowlisted recovered request to be denied, got %d with body %s", rec.Code, rec.Body.String())
	}
	events := server.missedDiag.Recent()
	if len(events) == 0 || events[0].Recovered {
		t.Fatalf("expected unrecovered diagnostics event, got %#v", events)
	}
}

func TestExplicitBlockPreventsRefererRecovery(t *testing.T) {
	server := newProxyFetchTestServer(t, "http://127.0.0.1")
	if err := server.store.UpsertResource(resources.Resource{
		ID:     "jstor",
		Name:   "JSTOR",
		Status: "active",
		Domains: []resources.DomainRule{
			{Host: "www.jstor.org", Match: "exact", Role: "blocked", Action: "block"},
		},
	}); err != nil {
		t.Fatalf("upsert blocked resource: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/assets/app.js", nil)
	req.Header.Set("Referer", "http://127.0.0.1:8080/odo/https/www.jstor.org/")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected blocked recovered request to be denied, got %d with body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "explicitly_blocked") {
		t.Fatalf("expected explicit block reason, got %s", rec.Body.String())
	}
	events := server.missedDiag.Recent()
	if len(events) == 0 || events[0].RecoveryAction != proxy.RecoveryActionDenied {
		t.Fatalf("expected denied recovery diagnostics, got %#v", events)
	}
}

func TestUnsafeRefererHostPreventsRecovery(t *testing.T) {
	server := newProxyFetchTestServer(t, "http://127.0.0.1")
	req := httptest.NewRequest(http.MethodGet, "/_next/data/build-id/page.json", nil)
	req.Header.Set("Referer", "http://127.0.0.1:8080/odo/https/localhost/")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected unsafe recovered host to be denied, got %d with body %s", rec.Code, rec.Body.String())
	}
	events := server.missedDiag.Recent()
	if len(events) == 0 || events[0].RecoveryAction != proxy.RecoveryActionDenied || events[0].Recovered {
		t.Fatalf("expected unsafe recovery denied diagnostics, got %#v", events)
	}
}

func TestUnknownLocalPathRecoveryRequiresProxiedReferer(t *testing.T) {
	server := newProxyFetchTestServer(t, "http://127.0.0.1")

	noReferer := httptest.NewRecorder()
	server.Routes().ServeHTTP(noReferer, httptest.NewRequest(http.MethodGet, "/assets/app.js", nil))
	if noReferer.Code != http.StatusNotFound {
		t.Fatalf("expected missing referer to return 404, got %d", noReferer.Code)
	}

	badRefererReq := httptest.NewRequest(http.MethodGet, "/assets/app.js", nil)
	badRefererReq.Header.Set("Referer", "http://127.0.0.1:8080/admin")
	badReferer := httptest.NewRecorder()
	server.Routes().ServeHTTP(badReferer, badRefererReq)
	if badReferer.Code != http.StatusNotFound {
		t.Fatalf("expected non-proxied referer to return 404, got %d", badReferer.Code)
	}
}

func TestProtectedAppPathsAreNotRecovered(t *testing.T) {
	server := newProxyFetchTestServer(t, "http://127.0.0.1")
	for _, path := range []string{"/api/v1/search", "/admin/assets/app.js"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Referer", "http://127.0.0.1:8080/odo/https/www.jstor.org/")
		rec := httptest.NewRecorder()
		server.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected protected path %s to return 404, got %d", path, rec.Code)
		}
	}
}

func TestRefererRecoveryCanBeDisabled(t *testing.T) {
	t.Setenv("APP_PROXY_REFERER_RECOVERY", "false")
	server := newProxyFetchTestServer(t, "http://127.0.0.1")

	req := httptest.NewRequest(http.MethodGet, "/assets/app.js", nil)
	req.Header.Set("Referer", "http://127.0.0.1:8080/odo/https/www.jstor.org/")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected disabled recovery to return 404, got %d", rec.Code)
	}
}

func TestMissedRewriteDiagnosticsEndpointRequiresAPIKey(t *testing.T) {
	server := newTestServer(t, "secret")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/diagnostics/missed-rewrites/recent", nil)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected missed rewrite diagnostics without API key to return 401, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestMissedRewriteDiagnosticsRecordsRecoveredAndUnrecovered(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	server := newProxyFetchTestServer(t, upstream.URL)

	unrecovered := httptest.NewRecorder()
	server.Routes().ServeHTTP(unrecovered, httptest.NewRequest(http.MethodGet, "/missing.js", nil))

	recoveredReq := httptest.NewRequest(http.MethodGet, "/assets/app.js", nil)
	recoveredReq.Header.Set("Referer", "http://127.0.0.1:8080/odo/https/www.jstor.org/")
	recovered := httptest.NewRecorder()
	server.Routes().ServeHTTP(recovered, recoveredReq)

	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/diagnostics/missed-rewrites/recent", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected diagnostics endpoint to return 200, got %d with body %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{`"recovered":true`, `"recovered":false`, `"path":"/assets/app.js"`, `"referer_route":"/odo"`, `"request_kind":"asset"`, `"recovery_action":"silently_proxied"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected diagnostics body to contain %q, got %s", want, body)
		}
	}
	if strings.Contains(body, "https://www.jstor.org/assets/app.js") || strings.Contains(body, "?secret=") {
		t.Fatalf("diagnostics leaked full target URL or query: %s", body)
	}
}

func TestRefererRecoveryDebugHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	server := newProxyFetchTestServerWithDebug(t, upstream.URL)

	req := httptest.NewRequest(http.MethodGet, "/assets/app.js", nil)
	req.Header.Set("Referer", "http://127.0.0.1:8080/odo/https/www.jstor.org/")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Header().Get("X-Odo-Recovered-From-Referer") != "true" ||
		rec.Header().Get("X-Odo-Recovery-Action") != "silently-proxied" ||
		rec.Header().Get("X-Odo-Target-Host") != "www.jstor.org" {
		t.Fatalf("expected safe recovery debug headers, got %#v", rec.Header())
	}
}

func TestDocumentRecoveryDebugHeaders(t *testing.T) {
	server := newProxyFetchTestServerWithDebug(t, "http://127.0.0.1")
	req := httptest.NewRequest(http.MethodGet, "/action/doAdvancedSearch", nil)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Referer", "http://127.0.0.1:8080/odo/https/www.jstor.org/")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected document recovery redirect, got %d with body %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-Odo-Recovered-From-Referer") != "true" ||
		rec.Header().Get("X-Odo-Recovery-Action") != "redirected-to-canonical" ||
		rec.Header().Get("X-Odo-Target-Host") != "www.jstor.org" {
		t.Fatalf("expected safe document recovery debug headers, got %#v", rec.Header())
	}
}

func TestRecoveredAccessLogUsesSafeMetadata(t *testing.T) {
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

	req := httptest.NewRequest(http.MethodGet, "/assets/app.js?secret=query", nil)
	req.Header.Set("Referer", "http://127.0.0.1:8080/odo/https/www.jstor.org/")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	line := logs.String()
	for _, want := range []string{"route=/odo-recovered", "target_host=www.jstor.org", "decision=allowed", "recovered_from_referer=true"} {
		if !strings.Contains(line, want) {
			t.Fatalf("expected recovered access log to contain %q, got %q", want, line)
		}
	}
	if strings.Contains(line, "secret=query") || strings.Contains(line, "assets/app.js") {
		t.Fatalf("recovered access log leaked full local path/query: %q", line)
	}
}

func TestRecoveredResponseDoesNotCopyUnsafeEncodingHeadersAndDefaultsJSType(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header()["Content-Type"] = []string{""}
		w.Header().Set("Content-Encoding", "br")
		w.Header().Set("Content-Length", "9999")
		_, _ = w.Write([]byte("console.log('ok');"))
	}))
	defer upstream.Close()
	server := newProxyFetchTestServer(t, upstream.URL)

	req := httptest.NewRequest(http.MethodGet, "/assets/app.js", nil)
	req.Header.Set("Referer", "http://127.0.0.1:8080/odo/https/www.jstor.org/")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Header().Get("Content-Encoding") != "" || rec.Header().Get("Content-Length") != "" {
		t.Fatalf("unsafe encoding headers copied: %#v", rec.Header())
	}
	if rec.Header().Get("Content-Type") != "application/javascript; charset=utf-8" {
		t.Fatalf("expected JS content type fallback, got %q", rec.Header().Get("Content-Type"))
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

func TestProxyPUTReturns405WhenResourceDoesNotAllowMethod(t *testing.T) {
	server := newProxyFetchTestServer(t, "http://127.0.0.1")
	req := httptest.NewRequest(http.MethodPut, "/odo?url=https://www.jstor.org/stable/example", nil)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestProxyPUTAllowedByExpandedResourceAndHeaderRuleApplied(t *testing.T) {
	var upstreamMethod string
	var xRequestedWith string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamMethod = r.Method
		xRequestedWith = r.Header.Get("X-Requested-With")
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	server := newProxyFetchTestServer(t, upstream.URL)
	if err := server.store.UpsertResource(resources.Resource{
		ID:          "jstor",
		Title:       "JSTOR",
		Status:      "active",
		EntryURLs:   []string{"https://www.jstor.org/"},
		HTTPMethods: []string{"GET", "HEAD", "POST", "PUT"},
		RequestHeaderRules: []resources.RequestHeaderRule{
			{Name: "X-Requested-With", Action: "remove", Phase: "request"},
		},
		Domains: []resources.DomainRule{{Host: "www.jstor.org", Behavior: "proxy", Role: "content"}},
	}); err != nil {
		t.Fatalf("upsert expanded resource: %v", err)
	}
	req := httptest.NewRequest(http.MethodPut, "/odo?url=https://www.jstor.org/stable/example", strings.NewReader("body"))
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected PUT to be allowed, got %d with body %s", rec.Code, rec.Body.String())
	}
	if upstreamMethod != http.MethodPut {
		t.Fatalf("expected upstream PUT, got %q", upstreamMethod)
	}
	if xRequestedWith != "" {
		t.Fatalf("expected X-Requested-With removed, got %q", xRequestedWith)
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

func TestValidateResourceEndpointReturnsNormalizedResource(t *testing.T) {
	server := newTestServer(t, "secret")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/resources/validate", bytes.NewBufferString(`{
  "id": "jstor",
  "title": "JSTOR",
  "entry_urls": ["https://www.jstor.org/"],
  "domains": [{"host":"jstor.org","behavior":"proxy","include_subdomains":true,"role":"content"}]
}`))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected validate resource 200, got %d with body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"valid":true`) || !strings.Contains(rec.Body.String(), `"normalized"`) || !strings.Contains(rec.Body.String(), `"match":"subdomain"`) {
		t.Fatalf("expected normalized validation response, got %s", rec.Body.String())
	}
}

func TestCreateAPIKeyReturnsTokenOnceAndStoresHash(t *testing.T) {
	server := newTestServer(t, "secret")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", bytes.NewBufferString(`{"name":"Local admin","scopes":["admin"]}`))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected create API key to return 201, got %d with body %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID        string   `json:"id"`
		KeyPrefix string   `json:"key_prefix"`
		Token     string   `json:"token"`
		Scopes    []string `json:"scopes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created key: %v", err)
	}
	if created.ID == "" || !strings.HasPrefix(created.Token, "odo_live_") || created.KeyPrefix == "" {
		t.Fatalf("expected created key id/prefix/token, got %#v", created)
	}
	stored, found, err := server.store.GetAPIKey(created.ID)
	if err != nil || !found {
		t.Fatalf("get stored API key found=%v err=%v", found, err)
	}
	if stored.KeyHash == "" || strings.Contains(stored.KeyHash, created.Token) {
		t.Fatalf("expected non-plaintext key hash, got %#v", stored)
	}
	if stored.KeyPrefix != created.KeyPrefix {
		t.Fatalf("expected stored prefix %q, got %q", created.KeyPrefix, stored.KeyPrefix)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/api-keys", nil)
	listReq.Header.Set("Authorization", "Bearer secret")
	listRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("expected list API keys to return 200, got %d with body %s", listRec.Code, listRec.Body.String())
	}
	if strings.Contains(listRec.Body.String(), created.Token) || strings.Contains(listRec.Body.String(), "key_hash") {
		t.Fatalf("list leaked token or key_hash: %s", listRec.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/api-keys/"+created.ID, nil)
	getReq.Header.Set("Authorization", "Bearer secret")
	getRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("expected get API key to return 200, got %d with body %s", getRec.Code, getRec.Body.String())
	}
	if strings.Contains(getRec.Body.String(), created.Token) || strings.Contains(getRec.Body.String(), "key_hash") {
		t.Fatalf("get leaked token or key_hash: %s", getRec.Body.String())
	}
}

func TestStoredAPIKeyAuthenticatesAndUpdatesLastUsed(t *testing.T) {
	server := newTestServer(t, "secret")
	token, id := createTestAPIKey(t, server, "secret", []string{"config:read"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/config/revisions", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected stored API key to authenticate, got %d with body %s", rec.Code, rec.Body.String())
	}
	key, found, err := server.store.GetAPIKey(id)
	if err != nil || !found {
		t.Fatalf("get API key found=%v err=%v", found, err)
	}
	if key.LastUsedAt == "" {
		t.Fatalf("expected last_used_at to be updated, got %#v", key)
	}
}

func TestStoredAPIKeyRejectsInsufficientScope(t *testing.T) {
	server := newTestServer(t, "secret")
	token, _ := createTestAPIKey(t, server, "secret", []string{"config:read"})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/import", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "insufficient scope") {
		t.Fatalf("expected insufficient scope 403, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestStoredAPIKeyRevokedAndExpiredRejected(t *testing.T) {
	server := newTestServer(t, "secret")
	revokedToken, revokedID := createTestAPIKey(t, server, "secret", []string{"admin"})
	if _, found, err := server.store.RevokeAPIKey(revokedID); err != nil || !found {
		t.Fatalf("revoke API key found=%v err=%v", found, err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/config/revisions", nil)
	req.Header.Set("Authorization", "Bearer "+revokedToken)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected revoked key to be rejected, got %d with body %s", rec.Code, rec.Body.String())
	}

	expiredKey, expiredToken, err := server.newStoredAPIKey(apiKeyCreateRequest{
		Name:      "Expired",
		Scopes:    []string{"admin"},
		ExpiresAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("create expired key: %v", err)
	}
	if err := server.store.CreateAPIKey(expiredKey); err != nil {
		t.Fatalf("store expired key: %v", err)
	}
	expiredReq := httptest.NewRequest(http.MethodGet, "/api/v1/config/revisions", nil)
	expiredReq.Header.Set("Authorization", "Bearer "+expiredToken)
	expiredRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(expiredRec, expiredReq)
	if expiredRec.Code != http.StatusForbidden {
		t.Fatalf("expected expired key to be rejected, got %d with body %s", expiredRec.Code, expiredRec.Body.String())
	}
}

func TestAPIKeyRotateInvalidatesOldTokenAndRevokeDisablesNewToken(t *testing.T) {
	server := newTestServer(t, "secret")
	oldToken, id := createTestAPIKey(t, server, "secret", []string{"admin"})

	rotateReq := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys/"+id+"/rotate", nil)
	rotateReq.Header.Set("Authorization", "Bearer "+oldToken)
	rotateRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rotateRec, rotateReq)
	if rotateRec.Code != http.StatusOK {
		t.Fatalf("expected rotate to return 200, got %d with body %s", rotateRec.Code, rotateRec.Body.String())
	}
	var rotated struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rotateRec.Body.Bytes(), &rotated); err != nil {
		t.Fatalf("decode rotate response: %v", err)
	}
	if rotated.Token == "" || rotated.Token == oldToken {
		t.Fatalf("expected new one-time token, got %#v", rotated)
	}

	oldReq := httptest.NewRequest(http.MethodGet, "/api/v1/api-keys", nil)
	oldReq.Header.Set("Authorization", "Bearer "+oldToken)
	oldRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(oldRec, oldReq)
	if oldRec.Code != http.StatusForbidden {
		t.Fatalf("expected old rotated token to fail, got %d with body %s", oldRec.Code, oldRec.Body.String())
	}

	newReq := httptest.NewRequest(http.MethodGet, "/api/v1/api-keys", nil)
	newReq.Header.Set("Authorization", "Bearer "+rotated.Token)
	newRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(newRec, newReq)
	if newRec.Code != http.StatusOK {
		t.Fatalf("expected rotated token to work, got %d with body %s", newRec.Code, newRec.Body.String())
	}

	revokeReq := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys/"+id+"/revoke", nil)
	revokeReq.Header.Set("Authorization", "Bearer "+rotated.Token)
	revokeRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(revokeRec, revokeReq)
	if revokeRec.Code != http.StatusOK {
		t.Fatalf("expected revoke to return 200, got %d with body %s", revokeRec.Code, revokeRec.Body.String())
	}
	revokedReq := httptest.NewRequest(http.MethodGet, "/api/v1/api-keys", nil)
	revokedReq.Header.Set("Authorization", "Bearer "+rotated.Token)
	revokedRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(revokedRec, revokedReq)
	if revokedRec.Code != http.StatusForbidden {
		t.Fatalf("expected revoked rotated token to fail, got %d with body %s", revokedRec.Code, revokedRec.Body.String())
	}
}

func TestSAMLProviderCreateListGetDelete(t *testing.T) {
	server := newTestServer(t, "secret")
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/saml/providers", bytes.NewBufferString(testSAMLProviderJSON()))
	createReq.Header.Set("Authorization", "Bearer secret")
	createRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusOK {
		t.Fatalf("expected create SAML provider 200, got %d with body %s", createRec.Code, createRec.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/saml/providers", nil)
	listReq.Header.Set("Authorization", "Bearer secret")
	listRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK || !strings.Contains(listRec.Body.String(), "campus-shibboleth") {
		t.Fatalf("expected list SAML providers, got %d with body %s", listRec.Code, listRec.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/saml/providers/campus-shibboleth", nil)
	getReq.Header.Set("Authorization", "Bearer secret")
	getRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK || !strings.Contains(getRec.Body.String(), "Campus Shibboleth") {
		t.Fatalf("expected get SAML provider, got %d with body %s", getRec.Code, getRec.Body.String())
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/saml/providers/campus-shibboleth", nil)
	deleteReq.Header.Set("Authorization", "Bearer secret")
	deleteRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusOK {
		t.Fatalf("expected delete SAML provider, got %d with body %s", deleteRec.Code, deleteRec.Body.String())
	}
}

func TestSAMLProviderAPIKeyAndScopeBehavior(t *testing.T) {
	server := newTestServer(t, "secret")
	missingReq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/saml/providers", nil)
	missingRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(missingRec, missingReq)
	if missingRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected missing key 401, got %d with body %s", missingRec.Code, missingRec.Body.String())
	}

	readToken, _ := createTestAPIKey(t, server, "secret", []string{"auth:read"})
	readReq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/saml/providers", nil)
	readReq.Header.Set("Authorization", "Bearer "+readToken)
	readRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(readRec, readReq)
	if readRec.Code != http.StatusOK {
		t.Fatalf("expected auth:read to list providers, got %d with body %s", readRec.Code, readRec.Body.String())
	}

	writeReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/saml/providers", bytes.NewBufferString(testSAMLProviderJSON()))
	writeReq.Header.Set("Authorization", "Bearer "+readToken)
	writeRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(writeRec, writeReq)
	if writeRec.Code != http.StatusForbidden || !strings.Contains(writeRec.Body.String(), "insufficient scope") {
		t.Fatalf("expected insufficient scope for write, got %d with body %s", writeRec.Code, writeRec.Body.String())
	}
}

func TestInvalidSAMLProviderRejected(t *testing.T) {
	server := newTestServer(t, "secret")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/saml/providers", bytes.NewBufferString(`{"id":"","name":"","status":"weird"}`))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid SAML provider 400, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestSAMLMetadataEndpoint(t *testing.T) {
	server := newTestServer(t, "secret")
	emptyRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(emptyRec, httptest.NewRequest(http.MethodGet, "/auth/saml/metadata", nil))
	if emptyRec.Code != http.StatusNotFound {
		t.Fatalf("expected metadata without provider 404, got %d with body %s", emptyRec.Code, emptyRec.Body.String())
	}

	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/saml/providers", bytes.NewBufferString(testSAMLProviderJSON()))
	createReq.Header.Set("Authorization", "Bearer secret")
	createRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusOK {
		t.Fatalf("create SAML provider: %d %s", createRec.Code, createRec.Body.String())
	}

	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/saml/metadata", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected metadata 200, got %d with body %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"EntityDescriptor", "SPSSODescriptor", "AssertionConsumerService", `entityID="https://access.example.edu/auth/saml/metadata"`, `Location="https://access.example.edu/auth/saml/acs"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected metadata to contain %q, got %s", want, body)
		}
	}
}

func TestSAMLPlaceholdersReturn501(t *testing.T) {
	server := newTestServer(t, "")
	loginRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(loginRec, httptest.NewRequest(http.MethodGet, "/auth/saml/login", nil))
	if loginRec.Code != http.StatusNotImplemented {
		t.Fatalf("expected SAML login 501, got %d", loginRec.Code)
	}
	acsRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(acsRec, httptest.NewRequest(http.MethodPost, "/auth/saml/acs", nil))
	if acsRec.Code != http.StatusNotImplemented {
		t.Fatalf("expected SAML ACS 501, got %d", acsRec.Code)
	}
}

func TestSampleResourceConfigsParseAndValidate(t *testing.T) {
	for _, path := range []string{"../../config/resources/jstor.json", "../../config/resources/jstor-aluka.json", "../../config/resources/economist.json"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		resource, err := resources.Decode(data)
		if err != nil {
			t.Fatalf("expected %s to parse and validate: %v", path, err)
		}
		if strings.Contains(path, "economist") {
			if len(resource.AnonymousURLRules) == 0 || len(resource.ContentRewriteRules) == 0 {
				t.Fatalf("expected economist sample to include anonymous and content rewrite rules: %#v", resource)
			}
			if len(resource.RequestHeaderRules) == 0 || resource.RequestHeaderRules[0].Name != "X-Requested-With" {
				t.Fatalf("expected economist sample to remove X-Requested-With: %#v", resource.RequestHeaderRules)
			}
		}
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

func createLocalTestUser(t *testing.T, server *Server, username, password string) db.User {
	t.Helper()
	hash, err := local.HashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	id, err := randomID("user_", 12)
	if err != nil {
		t.Fatalf("random user id: %v", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	user := db.User{
		ID:           id,
		Username:     username,
		PasswordHash: hash,
		Status:       "active",
		Roles:        []string{"user"},
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := server.store.CreateUser(user); err != nil {
		t.Fatalf("create local test user: %v", err)
	}
	return user
}

func loginTestUser(t *testing.T, server *Server, username, password, next string) *http.Cookie {
	t.Helper()
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", password)
	req := httptest.NewRequest(http.MethodPost, "/login?next="+url.QueryEscape(next), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("expected login redirect, got %d body %s", rec.Code, rec.Body.String())
	}
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == browserSessionCookieName {
			if !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
				t.Fatalf("login session cookie missing security attributes: %#v", cookie)
			}
			return cookie
		}
	}
	t.Fatalf("login did not set %s cookie; headers=%v", browserSessionCookieName, rec.Header())
	return nil
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

func createTestAPIKey(t *testing.T, server *Server, bootstrapToken string, scopes []string) (string, string) {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"name":   "Test key",
		"scopes": scopes,
	})
	if err != nil {
		t.Fatalf("marshal API key payload: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+bootstrapToken)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create API key got %d with body %s", rec.Code, rec.Body.String())
	}
	var body struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode API key response: %v", err)
	}
	if body.ID == "" || body.Token == "" {
		t.Fatalf("expected API key id/token, got %#v", body)
	}
	return body.Token, body.ID
}

func newProxyFetchTestServerWithDebug(t *testing.T, upstreamURL string) *Server {
	t.Helper()
	accessLogger, err := accesslog.New(accesslog.FormatPrivacy, io.Discard)
	if err != nil {
		t.Fatalf("create access logger: %v", err)
	}
	client := &http.Client{
		Transport: rewriteTransport(t, upstreamURL),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	server := newTestServerWithConfigAccessLogResolverAndClient(t, "", t.TempDir(), accessLogger, publicTestResolver, client)
	server.proxyDebug = true
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

func testSAMLProviderJSON() string {
	return `{
  "id": "campus-shibboleth",
  "name": "Campus Shibboleth",
  "status": "active",
  "entity_id": "https://access.example.edu/auth/saml/metadata",
  "acs_url": "https://access.example.edu/auth/saml/acs",
  "sign_authn_requests": true,
  "require_signed_assertions": true,
  "require_signed_responses": true,
  "attribute_mappings": {
    "subject": "urn:oid:0.9.2342.19200300.100.1.1",
    "email": "urn:oid:0.9.2342.19200300.100.1.3"
  },
  "session_ttl_minutes": 480,
  "idle_timeout_minutes": 60
}`
}
