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

func TestAPIIndexIsPublicAndListsOnlyKnownRoutes(t *testing.T) {
	t.Setenv("APP_ADMIN_API_KEY", "do-not-leak")
	t.Setenv("APP_KEY_HASH_SECRET", "also-do-not-leak")
	server := newTestServerWithConfig(t, "secret", "/private/config")

	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected public API index to return 200, got %d with body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("expected application/json content type, got %q", got)
	}
	var body struct {
		Name    string            `json:"name"`
		Version string            `json:"version"`
		Status  string            `json:"status"`
		Links   map[string]string `json:"links"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode API index: %v", err)
	}
	wantLinks := map[string]string{
		"api_keys": "/api/v1/api-keys", "diagnostics": "/api/v1/diagnostics/proxy/recent",
		"health": "/api/v1/health", "logs": "/api/v1/logs/access/recent",
		"openapi": "/openapi.yaml", "resources": "/api/v1/resources",
		"session": "/api/v1/session/me", "system": "/api/v1/system", "users": "/api/v1/users",
	}
	if body.Name != "Odo API" || body.Version != "v1" || body.Status != "ok" {
		t.Fatalf("unexpected API index metadata: %#v", body)
	}
	if len(body.Links) != len(wantLinks) {
		t.Fatalf("unexpected API index links: %#v", body.Links)
	}
	for name, path := range wantLinks {
		if body.Links[name] != path {
			t.Fatalf("expected link %q to be %q, got %q", name, path, body.Links[name])
		}
	}
	for _, sensitive := range []string{"secret", "do-not-leak", "also-do-not-leak", "/private/config", "password", "username"} {
		if strings.Contains(rec.Body.String(), sensitive) {
			t.Fatalf("API index exposed sensitive value %q: %s", sensitive, rec.Body.String())
		}
	}
}

func TestAPIIndexDoesNotWeakenProtectedRoutes(t *testing.T) {
	server := newTestServer(t, "secret")
	for _, path := range []string{
		"/api/v1/resources", "/api/v1/api-keys", "/api/v1/users",
		"/api/v1/config/revisions", "/api/v1/diagnostics/proxy/recent",
		"/api/v1/logs/access/recent", "/api/v1/system",
	} {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			server.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("expected %s to remain protected, got %d with body %s", path, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestUnknownAPIV1RouteReturns404(t *testing.T) {
	server := newTestServer(t, "secret")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/does-not-exist", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected unknown API v1 route to return 404, got %d with body %s", rec.Code, rec.Body.String())
	}
}

func TestSystemEndpointReturnsNonSecretRuntimeInfo(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("APP_PUBLIC_URL", "https://access.example.edu/")
	t.Setenv("APP_DATA_DIR", "/var/lib/odo")
	t.Setenv("APP_PROXY_REQUIRE_LOGIN", "true")
	t.Setenv("APP_TRUST_PROXY_HEADERS", "true")
	t.Setenv("APP_ADMIN_API_KEY", "do-not-leak")
	t.Setenv("APP_KEY_HASH_SECRET", "also-do-not-leak")
	server := newTestServerWithConfig(t, "secret", "/etc/odo")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected system endpoint to return 200, got %d with body %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode system response: %v", err)
	}
	if body["app_env"] != "production" || body["public_url"] != "https://access.example.edu" || body["public_url_set"] != true || body["data_dir"] != "/var/lib/odo" || body["config_dir"] != "/etc/odo" || body["proxy_require_login"] != true || body["trust_proxy_headers"] != true {
		t.Fatalf("unexpected system response: %#v", body)
	}
	if strings.Contains(rec.Body.String(), "do-not-leak") || strings.Contains(rec.Body.String(), "also-do-not-leak") {
		t.Fatalf("system endpoint exposed a secret: %s", rec.Body.String())
	}
}

func TestSystemRuntimeEndpointRequiresSystemScopeAndReturnsSafeMetrics(t *testing.T) {
	server := newTestServer(t, "secret")

	anonReq := httptest.NewRequest(http.MethodGet, "/api/v1/system/runtime", nil)
	anonRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(anonRec, anonReq)
	if anonRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected runtime endpoint to require auth, got %d", anonRec.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/runtime", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected runtime endpoint to return 200, got %d body %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"goroutines", "memory_alloc_bytes", "memory_sys_bytes", "open_sessions", "active_sessions_recent", "resource_count", "uptime_seconds"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected runtime response to contain %q, got %s", want, body)
		}
	}
	if strings.Contains(body, "secret") || strings.Contains(body, "session_hash") || strings.Contains(body, "password_hash") {
		t.Fatalf("runtime endpoint exposed sensitive data: %s", body)
	}
}

func TestPublicBaseURLIgnoresForwardedHeadersByDefault(t *testing.T) {
	t.Setenv("APP_PUBLIC_URL", "")
	t.Setenv("APP_TRUST_PROXY_HEADERS", "")
	req := httptest.NewRequest(http.MethodGet, "http://internal.local/auth/saml/metadata", nil)
	req.Host = "internal.local"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "access.example.edu")

	if got := publicBaseURL(req); got != "http://internal.local" {
		t.Fatalf("expected forwarded headers to be ignored by default, got %q", got)
	}
}

func TestPublicBaseURLUsesTrustedForwardedHeadersWhenEnabled(t *testing.T) {
	t.Setenv("APP_PUBLIC_URL", "")
	t.Setenv("APP_TRUST_PROXY_HEADERS", "true")
	req := httptest.NewRequest(http.MethodGet, "http://internal.local/auth/saml/metadata", nil)
	req.Host = "internal.local"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "access.example.edu")

	if got := publicBaseURL(req); got != "https://access.example.edu" {
		t.Fatalf("expected trusted forwarded headers to set public base URL, got %q", got)
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
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected admin to return 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"Dashboard", "Resources", "Config", "Proxy Test", "Diagnostics", "API Keys", "Users", "Auth", "Settings", "Load Resources", "Save Resource", "Delete Resource", "New Resource", "Admin API Key", "optional override mode", "session-summary", "Logout", "data-scopes=\"resources:read resources:write\"", "X-Odo-CSRF", "/api/v1/session/me", "Resource List", "resource-search", "resource-status-filter", "resource-behavior-filter", "resource-complexity-filter", "resource-tag-filter", "resource-sort", "resource-order", "resource-detail", "Raw JSON Editor", "Export Filtered JSON", "card-list", "resource-card", "details", "The built-in admin UI is intentionally simple. Advanced customization and automation should use the documented JSON APIs.", "Title", "Main domains", "Tags", "Updated at", "Complexity", "Test Rule", "Open Through Proxy", "Fetch Through Proxy", "Load Missed Rewrites", "matched domain rule", "proxy_url", "Load Access Logs", "Load Proxy Diagnostics", "Load API Keys", "New API Key", "Create API Key", "Rotate Selected Key", "Revoke Selected Key", "Delete Selected Key", "Load Users", "New User", "Create User", "Update User", "Set Password", "Revoke Sessions", "Load SAML Providers", "New SAML Provider", "Save SAML Provider", "Delete SAML Provider", "Open SP Metadata", "Load System Info", "app_env", "public_url", "data_dir", "trust_proxy_headers", "Resource Config Builder", "Start with a title, entry URL, and main domain. Generate and validate JSON before saving. Add additional domains only when testing or diagnostics show they are needed.", "docs/resource-how-to.md", "Add Domain", "Anonymous URL Rules", "Add Anonymous Rule", "Content Rewrite Rules", "Add Rewrite Rule", "rewrite_javascript", "Generate JSON", "Validate JSON", "Save as Resource", "Export JSON"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected admin body to contain %q", want)
		}
	}
	if strings.Contains(body, `data-section="proxy"`) || strings.Contains(body, `id="section-proxy"`) {
		t.Fatalf("standalone Proxy Test navigation/section should be folded into Resources")
	}
	if !strings.Contains(body, "/api/v1/api-keys") {
		t.Fatalf("expected admin JS to reference /api/v1/api-keys")
	}
	if strings.Contains(body, `data-odo-js-shim="true"`) {
		t.Fatalf("admin UI should not include proxy JS shim")
	}
}

func TestAuthContextDerivesScopesForAPIKeysAndUsers(t *testing.T) {
	server := newTestServer(t, "secret")
	token, keyID := createTestAPIKey(t, server, "secret", []string{"resources:read"})
	apiReq := httptest.NewRequest(http.MethodGet, "/api/v1/session/me", nil)
	apiReq.Header.Set("Authorization", "Bearer "+token)
	apiRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(apiRec, apiReq)
	if apiRec.Code != http.StatusOK {
		t.Fatalf("expected API key session me 200, got %d body %s", apiRec.Code, apiRec.Body.String())
	}
	if !strings.Contains(apiRec.Body.String(), `"subject_type":"api_key"`) || !strings.Contains(apiRec.Body.String(), keyID) || strings.Contains(apiRec.Body.String(), token) || strings.Contains(apiRec.Body.String(), "key_hash") {
		t.Fatalf("unexpected API key session response: %s", apiRec.Body.String())
	}

	adminUser := createLocalTestUserWithRoles(t, server, "adminuser", "correct horse battery", []string{"admin"})
	adminAuth := authContextForUser(adminUser, "csrf")
	if !hasRequiredScope(adminAuth.Scopes, []string{"admin"}) || !adminAuth.IsAdminLike {
		t.Fatalf("expected legacy admin role to map to admin scope, got %#v", adminAuth)
	}
	regular := createLocalTestUser(t, server, "regular", "correct horse battery")
	regularAuth := authContextForUser(regular, "csrf")
	if regularAuth.IsAdminLike || len(regularAuth.Scopes) != 0 {
		t.Fatalf("expected regular user to have no admin scopes, got %#v", regularAuth)
	}
	resourceAdmin := createLocalTestUserWithRoles(t, server, "resourceadmin", "correct horse battery", []string{"resource_admin"})
	resourceAuth := authContextForUser(resourceAdmin, "csrf")
	for _, scope := range []string{"resources:read", "resources:write", "config:read", "config:write", "diagnostics:read"} {
		if !hasRequiredScope(resourceAuth.Scopes, []string{scope}) {
			t.Fatalf("expected resource_admin to include %s, got %#v", scope, resourceAuth.Scopes)
		}
	}
}

func TestAdminPageRequiresAdminLikeSession(t *testing.T) {
	server := newTestServer(t, "secret")
	createLocalTestUser(t, server, "patron", "correct horse battery")
	createLocalTestUserWithRoles(t, server, "resourceadmin", "correct horse battery", []string{"resource_admin"})
	createLocalTestUserWithRoles(t, server, "super", "correct horse battery", []string{"super_admin"})

	anonReq := httptest.NewRequest(http.MethodGet, "/admin", nil)
	anonRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(anonRec, anonReq)
	if anonRec.Code != http.StatusFound || anonRec.Header().Get("Location") != "/login?next=%2Fadmin" {
		t.Fatalf("expected unauthenticated admin redirect, got %d location %q", anonRec.Code, anonRec.Header().Get("Location"))
	}

	regularCookie := loginTestUser(t, server, "patron", "correct horse battery", "/resources")
	regularReq := httptest.NewRequest(http.MethodGet, "/admin", nil)
	regularReq.AddCookie(regularCookie)
	regularRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(regularRec, regularReq)
	if regularRec.Code != http.StatusForbidden || !strings.Contains(regularRec.Body.String(), "Admin access denied") {
		t.Fatalf("expected regular user admin 403, got %d body %s", regularRec.Code, regularRec.Body.String())
	}

	resourceCookie := loginTestUser(t, server, "resourceadmin", "correct horse battery", "/admin")
	resourceReq := httptest.NewRequest(http.MethodGet, "/admin", nil)
	resourceReq.AddCookie(resourceCookie)
	resourceRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(resourceRec, resourceReq)
	if resourceRec.Code != http.StatusOK || !strings.Contains(resourceRec.Body.String(), "odo admin") {
		t.Fatalf("expected resource_admin admin UI, got %d body %s", resourceRec.Code, resourceRec.Body.String())
	}

	superCookie := loginTestUser(t, server, "super", "correct horse battery", "/admin")
	superReq := httptest.NewRequest(http.MethodGet, "/admin", nil)
	superReq.AddCookie(superCookie)
	superRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(superRec, superReq)
	if superRec.Code != http.StatusOK {
		t.Fatalf("expected super_admin admin UI, got %d body %s", superRec.Code, superRec.Body.String())
	}
}

func TestSessionAuthenticatedAdminAPIsRequireScopesAndCSRF(t *testing.T) {
	server := newTestServer(t, "secret")
	createLocalTestUserWithRoles(t, server, "resourceadmin", "correct horse battery", []string{"resource_admin"})
	createLocalTestUserWithRoles(t, server, "support", "correct horse battery", []string{"support_staff"})
	createLocalTestUser(t, server, "patron", "correct horse battery")

	resourceCookie, csrf := loginTestUserWithCSRF(t, server, "resourceadmin", "correct horse battery", "/admin")
	payload := `{"id":"session-resource","title":"Session Resource","status":"active","entry_urls":["https://www.jstor.org/"],"domains":[{"host":"www.jstor.org","match":"exact","role":"content","action":"proxy"}]}`
	noCSRFReq := httptest.NewRequest(http.MethodPost, "/api/v1/resources", strings.NewReader(payload))
	noCSRFReq.Header.Set("Content-Type", "application/json")
	noCSRFReq.AddCookie(resourceCookie)
	noCSRFRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(noCSRFRec, noCSRFReq)
	if noCSRFRec.Code != http.StatusForbidden || !strings.Contains(noCSRFRec.Body.String(), "csrf") {
		t.Fatalf("expected missing CSRF to fail, got %d body %s", noCSRFRec.Code, noCSRFRec.Body.String())
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/resources", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Odo-CSRF", csrf)
	req.AddCookie(resourceCookie)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected resource_admin with CSRF to write resource, got %d body %s", rec.Code, rec.Body.String())
	}

	apiKeyReq := httptest.NewRequest(http.MethodPost, "/api/v1/resources", strings.NewReader(strings.ReplaceAll(payload, "session-resource", "api-key-resource")))
	apiKeyReq.Header.Set("Content-Type", "application/json")
	apiKeyReq.Header.Set("Authorization", "Bearer secret")
	apiKeyRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(apiKeyRec, apiKeyReq)
	if apiKeyRec.Code != http.StatusOK {
		t.Fatalf("expected bearer API key write without CSRF, got %d body %s", apiKeyRec.Code, apiKeyRec.Body.String())
	}
	events, err := server.store.ListAuditEvents(20)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if !auditEventsContain(events, "csrf_failure") || !auditEventsContain(events, "admin_api_call_by_user") || !auditEventsContain(events, "admin_api_call_by_api_key") {
		t.Fatalf("expected csrf/user/api-key audit events, got %#v", events)
	}

	keyReq := httptest.NewRequest(http.MethodGet, "/api/v1/api-keys", nil)
	keyReq.AddCookie(resourceCookie)
	keyRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(keyRec, keyReq)
	if keyRec.Code != http.StatusForbidden {
		t.Fatalf("expected resource_admin to be unable to manage API keys, got %d body %s", keyRec.Code, keyRec.Body.String())
	}

	supportCookie := loginTestUser(t, server, "support", "correct horse battery", "/admin")
	diagReq := httptest.NewRequest(http.MethodGet, "/api/v1/diagnostics/proxy/recent", nil)
	diagReq.AddCookie(supportCookie)
	diagRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(diagRec, diagReq)
	if diagRec.Code != http.StatusOK {
		t.Fatalf("expected support_staff diagnostics read, got %d body %s", diagRec.Code, diagRec.Body.String())
	}
	supportWriteReq := httptest.NewRequest(http.MethodPost, "/api/v1/resources", strings.NewReader(strings.ReplaceAll(payload, "session-resource", "support-resource")))
	supportWriteReq.Header.Set("Content-Type", "application/json")
	supportWriteReq.AddCookie(supportCookie)
	supportWriteRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(supportWriteRec, supportWriteReq)
	if supportWriteRec.Code != http.StatusForbidden {
		t.Fatalf("expected support_staff resource write forbidden, got %d body %s", supportWriteRec.Code, supportWriteRec.Body.String())
	}

	regularCookie := loginTestUser(t, server, "patron", "correct horse battery", "/resources")
	regularReq := httptest.NewRequest(http.MethodGet, "/api/v1/diagnostics/proxy/recent", nil)
	regularReq.AddCookie(regularCookie)
	regularRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(regularRec, regularReq)
	if regularRec.Code != http.StatusForbidden {
		t.Fatalf("expected regular user admin API forbidden, got %d body %s", regularRec.Code, regularRec.Body.String())
	}
}

func TestRoleChangesRequireAdminScopeAndProtectLastAdmin(t *testing.T) {
	server := newTestServer(t, "secret")
	super := createLocalTestUserWithRoles(t, server, "super", "correct horse battery", []string{"super_admin"})
	createLocalTestUserWithRoles(t, server, "security", "correct horse battery", []string{"security_admin"})
	patron := createLocalTestUser(t, server, "patron", "correct horse battery")

	securityCookie, securityCSRF := loginTestUserWithCSRF(t, server, "security", "correct horse battery", "/admin")
	roleReq := httptest.NewRequest(http.MethodPatch, "/api/v1/users/"+patron.ID, strings.NewReader(`{"roles":["viewer"]}`))
	roleReq.Header.Set("Content-Type", "application/json")
	roleReq.Header.Set("X-Odo-CSRF", securityCSRF)
	roleReq.AddCookie(securityCookie)
	roleRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(roleRec, roleReq)
	if roleRec.Code != http.StatusForbidden {
		t.Fatalf("expected non-admin role change forbidden, got %d body %s", roleRec.Code, roleRec.Body.String())
	}

	removeLastReq := httptest.NewRequest(http.MethodPatch, "/api/v1/users/"+super.ID, strings.NewReader(`{"roles":["viewer"]}`))
	removeLastReq.Header.Set("Content-Type", "application/json")
	removeLastReq.Header.Set("Authorization", "Bearer secret")
	removeLastRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(removeLastRec, removeLastReq)
	if removeLastRec.Code != http.StatusBadRequest {
		t.Fatalf("expected removing last admin to fail, got %d body %s", removeLastRec.Code, removeLastRec.Body.String())
	}
}

func TestSessionMeForUserAndAnonymous(t *testing.T) {
	server := newTestServer(t, "secret")
	createLocalTestUserWithRoles(t, server, "viewer", "correct horse battery", []string{"viewer"})

	anonReq := httptest.NewRequest(http.MethodGet, "/api/v1/session/me", nil)
	anonRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(anonRec, anonReq)
	if anonRec.Code != http.StatusOK || !strings.Contains(anonRec.Body.String(), `"authenticated":false`) {
		t.Fatalf("expected unauthenticated session response, got %d body %s", anonRec.Code, anonRec.Body.String())
	}

	cookie := loginTestUser(t, server, "viewer", "correct horse battery", "/admin")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/session/me", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected user session me 200, got %d body %s", rec.Code, rec.Body.String())
	}
	for _, want := range []string{`"subject_type":"user"`, `"username":"viewer"`, `"roles":["viewer"]`, `"system:read"`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("expected session me to contain %q, got %s", want, rec.Body.String())
		}
	}
	if strings.Contains(rec.Body.String(), "password_hash") || strings.Contains(rec.Body.String(), "session_hash") {
		t.Fatalf("session me exposed sensitive fields: %s", rec.Body.String())
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
	for _, want := range []string{"## Adding resources", "docs/resource-how-to.md", "Resource Config Builder", "integrated Proxy Test in the Resources tab", "intentionally minimal", "documented `/api/v1` JSON endpoints", "build their own custom UI"} {
		if !strings.Contains(string(readme), want) {
			t.Fatalf("expected README to contain %q", want)
		}
	}
	if strings.Contains(strings.ToLower(string(readme)), "ezproxy") || strings.Contains(strings.ToLower(string(doc)), "ezproxy") {
		t.Fatalf("documentation should not reference EZproxy")
	}
}

func TestLoadtestDocsAndFakeVendorResourceExist(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("APP_PROXY_ALLOW_LOCAL_HTTP", "true")
	root := filepath.Join("..", "..")

	readme, err := os.ReadFile(filepath.Join(root, "loadtest", "README.md"))
	if err != nil {
		t.Fatalf("expected loadtest/README.md to exist: %v", err)
	}
	for _, want := range []string{"Do not load-test real vendor sites", "go run ./loadtest/fake-vendor", "k6 run loadtest/k6/smoke.js", "/api/v1/system/runtime", "SQLite"} {
		if !strings.Contains(string(readme), want) {
			t.Fatalf("expected loadtest README to contain %q", want)
		}
	}

	payload, err := os.ReadFile(filepath.Join(root, "loadtest", "fake-vendor-resource.json"))
	if err != nil {
		t.Fatalf("expected fake vendor resource config to exist: %v", err)
	}
	var resource resources.Resource
	if err := json.Unmarshal(payload, &resource); err != nil {
		t.Fatalf("decode fake vendor resource: %v", err)
	}
	if _, err := resources.Validate(resource); err != nil {
		t.Fatalf("expected fake vendor resource to validate: %v", err)
	}
}

func TestDeploymentPackagingAndDocsExist(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, path := range []string{
		"Containerfile",
		filepath.Join("docs", "deploy-container.md"),
		filepath.Join("docs", "install-linux-vm.md"),
		filepath.Join("deploy", "odo.env.example"),
		filepath.Join("deploy", "podman", "odo.container"),
		filepath.Join("packaging", "systemd", "odo.env.example"),
		filepath.Join("packaging", "systemd", "odo.service"),
		filepath.Join("scripts", "install-linux.sh"),
		filepath.Join("scripts", "uninstall-linux.sh"),
		"Makefile",
	} {
		if _, err := os.Stat(filepath.Join(root, path)); err != nil {
			t.Fatalf("expected %s to exist: %v", path, err)
		}
	}

	containerfile, err := os.ReadFile(filepath.Join(root, "Containerfile"))
	if err != nil {
		t.Fatalf("read Containerfile: %v", err)
	}
	for _, want := range []string{"FROM golang:1.23-alpine AS build", "USER odo", "APP_DATA_DIR=/var/lib/odo", "APP_CONFIG_DIR=/etc/odo", "HEALTHCHECK", "EXPOSE 8080"} {
		if !strings.Contains(string(containerfile), want) {
			t.Fatalf("expected Containerfile to contain %q", want)
		}
	}

	readme, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	for _, want := range []string{"## Deployment", "docs/deploy-container.md", "APP_PUBLIC_URL", "persistent data volume"} {
		if !strings.Contains(string(readme), want) {
			t.Fatalf("expected README deployment section to contain %q", want)
		}
	}

	for _, want := range []string{"## Installation", "docs/install-linux-vm.md", "Linux VM install", "Container install"} {
		if !strings.Contains(string(readme), want) {
			t.Fatalf("expected README installation section to contain %q", want)
		}
	}

	unit, err := os.ReadFile(filepath.Join(root, "packaging", "systemd", "odo.service"))
	if err != nil {
		t.Fatalf("read systemd unit: %v", err)
	}
	for _, want := range []string{"User=odo", "Group=odo", "EnvironmentFile=/etc/odo/odo.env", "ExecStart=/usr/local/bin/odo", "WorkingDirectory=/var/lib/odo", "StandardOutput=append:/var/log/odo/odo.log", "NoNewPrivileges=true", "ReadWritePaths=/var/lib/odo /var/log/odo"} {
		if !strings.Contains(string(unit), want) {
			t.Fatalf("expected systemd unit to contain %q", want)
		}
	}

	envExample, err := os.ReadFile(filepath.Join(root, "packaging", "systemd", "odo.env.example"))
	if err != nil {
		t.Fatalf("read systemd env example: %v", err)
	}
	for _, want := range []string{"APP_ENV=production", "APP_BIND_ADDR=127.0.0.1:8080", "APP_DB_PATH=/var/lib/odo/odo.db", "APP_ACCESS_LOG_PATH=/var/log/odo/access.log", "APP_TRUST_PROXY_HEADERS=true"} {
		if !strings.Contains(string(envExample), want) {
			t.Fatalf("expected systemd env example to contain %q", want)
		}
	}

	for _, path := range []string{filepath.Join("scripts", "install-linux.sh"), filepath.Join("scripts", "uninstall-linux.sh")} {
		info, err := os.Stat(filepath.Join(root, path))
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if info.Mode()&0o111 == 0 {
			t.Fatalf("expected %s to be executable, mode is %s", path, info.Mode())
		}
	}

	installer, err := os.ReadFile(filepath.Join(root, "scripts", "install-linux.sh"))
	if err != nil {
		t.Fatalf("read install script: %v", err)
	}
	for _, want := range []string{"if [ -f \"$ENV_FILE\" ] && [ \"$FORCE\" -ne 1 ]", "Keeping existing $ENV_FILE", "Pass --force to overwrite"} {
		if !strings.Contains(string(installer), want) {
			t.Fatalf("expected install script no-overwrite behavior to contain %q", want)
		}
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
	server := newProxyFetchTestServerWithAdmin(t, upstream.URL, "secret")
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

func TestProxyLoginRedirectPreservesPathAndQuery(t *testing.T) {
	t.Setenv("APP_PROXY_REQUIRE_LOGIN", "true")
	server := newProxyFetchTestServer(t, "https://upstream.example")
	createLocalTestUser(t, server, "alice", "correct horse battery")

	req := httptest.NewRequest(http.MethodGet, "/odo/https/www.jstor.org/stable/123456?Search=yes", nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected redirect to login, got %d body %s", rec.Code, rec.Body.String())
	}
	location := rec.Header().Get("Location")
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse redirect location: %v", err)
	}
	if parsed.Path != "/login" || parsed.Query().Get("next") != "/odo/https/www.jstor.org/stable/123456?Search=yes" {
		t.Fatalf("expected login next to preserve path/query, got %q", location)
	}
}

func TestProxyLoginRedirectPreservesQueryStyleProxyURL(t *testing.T) {
	t.Setenv("APP_PROXY_REQUIRE_LOGIN", "true")
	server := newProxyFetchTestServer(t, "https://upstream.example")
	createLocalTestUser(t, server, "alice", "correct horse battery")

	req := httptest.NewRequest(http.MethodGet, "/odo?url=https%3A%2F%2Fwww.jstor.org%2Fstable%2F123456", nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected redirect to login, got %d body %s", rec.Code, rec.Body.String())
	}
	location := rec.Header().Get("Location")
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse redirect location: %v", err)
	}
	if parsed.Path != "/login" || parsed.Query().Get("next") != "/odo?url=https%3A%2F%2Fwww.jstor.org%2Fstable%2F123456" {
		t.Fatalf("expected query-style proxy URL in next, got %q", location)
	}
}

func TestProxyLoginRequiredForResourceEntryURLAndRootPaths(t *testing.T) {
	t.Setenv("APP_PROXY_REQUIRE_LOGIN", "true")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("umn proxied ok"))
	}))
	defer upstream.Close()
	server := newProxyFetchTestServerWithAdmin(t, upstream.URL, "secret")
	createLocalTestUser(t, server, "alice", "correct horse battery")
	if err := server.store.UpsertResource(resources.Resource{
		ID:        "umn",
		Title:     "UMN Libraries",
		Status:    "active",
		EntryURLs: []string{"https://www.lib.umn.edu/"},
		Domains:   []resources.DomainRule{{Host: "www.lib.umn.edu", Match: "exact", Role: "content", Action: "proxy"}},
	}); err != nil {
		t.Fatalf("upsert UMN resource: %v", err)
	}

	for _, path := range []string{"/odo/https/www.lib.umn.edu/", "/odo/https/www.lib.umn.edu", "/odo/https/www.lib.umn.edu/some/page"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Accept", "text/html")
		rec := httptest.NewRecorder()
		server.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusFound {
			t.Fatalf("expected unauthenticated %s to redirect to login, got %d body %s", path, rec.Code, rec.Body.String())
		}
		location := rec.Header().Get("Location")
		parsed, err := url.Parse(location)
		if err != nil {
			t.Fatalf("parse redirect location: %v", err)
		}
		if parsed.Path != "/login" || parsed.Query().Get("next") != path {
			t.Fatalf("expected login next %q, got location %q", path, location)
		}
	}

	cookie := loginTestUser(t, server, "alice", "correct horse battery", "/resources")
	req := httptest.NewRequest(http.MethodGet, "/odo/https/www.lib.umn.edu/", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "umn proxied ok") {
		t.Fatalf("expected authenticated entry URL access, got %d body %s", rec.Code, rec.Body.String())
	}
}

func TestProxyLoginRequiredForQueryStyleEntryURL(t *testing.T) {
	t.Setenv("APP_PROXY_REQUIRE_LOGIN", "true")
	server := newProxyFetchTestServerWithAdmin(t, "https://upstream.example", "secret")
	createLocalTestUser(t, server, "alice", "correct horse battery")
	if err := server.store.UpsertResource(resources.Resource{
		ID:        "umn",
		Title:     "UMN Libraries",
		Status:    "active",
		EntryURLs: []string{"https://www.lib.umn.edu/"},
		Domains:   []resources.DomainRule{{Host: "www.lib.umn.edu", Match: "exact", Role: "content", Action: "proxy"}},
	}); err != nil {
		t.Fatalf("upsert UMN resource: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/odo?url=https%3A%2F%2Fwww.lib.umn.edu%2F", nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("expected query-style entry URL to redirect to login, got %d body %s", rec.Code, rec.Body.String())
	}
	location := rec.Header().Get("Location")
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse redirect location: %v", err)
	}
	if parsed.Path != "/login" || parsed.Query().Get("next") != "/odo?url=https%3A%2F%2Fwww.lib.umn.edu%2F" {
		t.Fatalf("expected query-style next to be preserved, got %q", location)
	}
}

func TestSafeNextPathValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want string
		ok   bool
	}{
		{name: "odo", raw: "/odo/https/www.jstor.org/stable/123456", want: "/odo/https/www.jstor.org/stable/123456", ok: true},
		{name: "resources", raw: "/resources", want: "/resources", ok: true},
		{name: "query style", raw: "/odo?url=https%3A%2F%2Fwww.jstor.org%2Fstable%2F123456", want: "/odo?url=https%3A%2F%2Fwww.jstor.org%2Fstable%2F123456", ok: true},
		{name: "external", raw: "https://evil.example/", want: "/resources", ok: false},
		{name: "scheme-relative", raw: "//evil.example/path", want: "/resources", ok: false},
		{name: "http scheme", raw: "http://evil.example", want: "/resources", ok: false},
		{name: "admin", raw: "/admin", want: "/admin", ok: true},
		{name: "malformed", raw: "%", want: "/resources", ok: false},
		{name: "backslash", raw: `/\evil`, want: "/resources", ok: false},
		{name: "control", raw: "/odo/https/www.jstor.org/\n", want: "/resources", ok: false},
		{name: "unknown local path", raw: "/unknown", want: "/resources", ok: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := safeNextPath(tc.raw)
			if got != tc.want || ok != tc.ok {
				t.Fatalf("safeNextPath(%q) = %q, %v; want %q, %v", tc.raw, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestLoginPageAndPostRedirects(t *testing.T) {
	t.Setenv("APP_PUBLIC_URL", "https://access.example.edu")
	server := newTestServer(t, "secret")
	createLocalTestUser(t, server, "alice", "correct horse battery")

	getReq := httptest.NewRequest(http.MethodGet, "/login?next="+url.QueryEscape("/odo/https/www.jstor.org/"), nil)
	getRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK || !strings.Contains(getRec.Body.String(), "Sign in to continue") || !strings.Contains(getRec.Body.String(), `name="next" value="/odo/https/www.jstor.org/"`) {
		t.Fatalf("expected login form with hidden next, got %d body %s", getRec.Code, getRec.Body.String())
	}

	form := url.Values{}
	form.Set("username", "alice")
	form.Set("password", "correct horse battery")
	form.Set("next", "/odo/https/www.jstor.org/")
	postReq := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(postRec, postReq)
	if postRec.Code != http.StatusFound || postRec.Header().Get("Location") != "/odo/https/www.jstor.org/" {
		t.Fatalf("expected login redirect to next, got %d location %q", postRec.Code, postRec.Header().Get("Location"))
	}
	sessionCookie := findCookie(postRec.Result().Cookies(), browserSessionCookieName)
	if sessionCookie == nil {
		t.Fatalf("expected login to set session cookie")
	}
	if !sessionCookie.HttpOnly || sessionCookie.SameSite != http.SameSiteLaxMode || !sessionCookie.Secure || sessionCookie.Path != "/" {
		t.Fatalf("session cookie missing security attributes: %#v", sessionCookie)
	}
	session, found, err := server.store.GetSession(local.SessionIDFromToken(sessionCookie.Value))
	if err != nil || !found {
		t.Fatalf("expected stored session, found=%v err=%v", found, err)
	}
	if session.SessionHash == "" || session.SessionHash == sessionCookie.Value || strings.Contains(session.SessionHash, ".") {
		t.Fatalf("expected stored session hash, got %#v", session)
	}

	noNextForm := url.Values{}
	noNextForm.Set("username", "alice")
	noNextForm.Set("password", "correct horse battery")
	noNextReq := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(noNextForm.Encode()))
	noNextReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	noNextRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(noNextRec, noNextReq)
	if noNextRec.Code != http.StatusFound || noNextRec.Header().Get("Location") != "/resources" {
		t.Fatalf("expected login without next to redirect to /resources, got %d location %q", noNextRec.Code, noNextRec.Header().Get("Location"))
	}

	queryNext := "/odo?url=https%3A%2F%2Fwww.jstor.org%2Fstable%2F123456"
	queryForm := url.Values{}
	queryForm.Set("username", "alice")
	queryForm.Set("password", "correct horse battery")
	queryForm.Set("next", queryNext)
	queryReq := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(queryForm.Encode()))
	queryReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	queryRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(queryRec, queryReq)
	if queryRec.Code != http.StatusFound || queryRec.Header().Get("Location") != queryNext {
		t.Fatalf("expected login to preserve query-style /odo next, got %d location %q", queryRec.Code, queryRec.Header().Get("Location"))
	}

	for _, unsafeNext := range []string{"https://evil.example/", "//evil.example/path"} {
		badNextForm := url.Values{}
		badNextForm.Set("username", "alice")
		badNextForm.Set("password", "correct horse battery")
		badNextForm.Set("next", unsafeNext)
		badNextReq := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(badNextForm.Encode()))
		badNextReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		badNextRec := httptest.NewRecorder()
		server.Routes().ServeHTTP(badNextRec, badNextReq)
		if badNextRec.Code != http.StatusFound || badNextRec.Header().Get("Location") != "/resources" {
			t.Fatalf("expected unsafe next %q to fall back to /resources, got %d location %q", unsafeNext, badNextRec.Code, badNextRec.Header().Get("Location"))
		}
	}

	badForm := url.Values{}
	badForm.Set("username", "missing")
	badForm.Set("password", "wrong password")
	badReq := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(badForm.Encode()))
	badReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	badRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(badRec, badReq)
	if badRec.Code != http.StatusUnauthorized || !strings.Contains(badRec.Body.String(), "invalid username or password") || strings.Contains(strings.ToLower(badRec.Body.String()), "not found") {
		t.Fatalf("expected generic invalid login response, got %d body %s", badRec.Code, badRec.Body.String())
	}
}

func TestSessionPersistOnRestartConfiguration(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("APP_SESSION_PERSIST_ON_RESTART", "true")
	store, err := db.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatalf("open temp store: %v", err)
	}
	defer store.Close()
	if err := store.Migrate(); err != nil {
		t.Fatalf("migrate temp store: %v", err)
	}
	accessLogger, _ := accesslog.New(accesslog.FormatPrivacy, io.Discard)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server1 := NewServerWithAccessLoggerResolverAndHTTPClient(store, t.TempDir(), "secret", logger, accessLogger, publicTestResolver, proxy.DefaultHTTPClient())
	createLocalTestUser(t, server1, "alice", "correct horse battery")
	cookie := loginTestUser(t, server1, "alice", "correct horse battery", "/resources")

	server2 := NewServerWithAccessLoggerResolverAndHTTPClient(store, t.TempDir(), "secret", logger, accessLogger, publicTestResolver, proxy.DefaultHTTPClient())
	req := httptest.NewRequest(http.MethodGet, "/resources", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	server2.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected persistent session to survive simulated restart, got %d location %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestSessionPersistDisabledRejectsAfterRestart(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("APP_SESSION_PERSIST_ON_RESTART", "false")
	store, err := db.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatalf("open temp store: %v", err)
	}
	defer store.Close()
	if err := store.Migrate(); err != nil {
		t.Fatalf("migrate temp store: %v", err)
	}
	accessLogger, _ := accesslog.New(accesslog.FormatPrivacy, io.Discard)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server1 := NewServerWithAccessLoggerResolverAndHTTPClient(store, t.TempDir(), "secret", logger, accessLogger, publicTestResolver, proxy.DefaultHTTPClient())
	createLocalTestUser(t, server1, "alice", "correct horse battery")
	cookie := loginTestUser(t, server1, "alice", "correct horse battery", "/resources")

	server2 := NewServerWithAccessLoggerResolverAndHTTPClient(store, t.TempDir(), "secret", logger, accessLogger, publicTestResolver, proxy.DefaultHTTPClient())
	req := httptest.NewRequest(http.MethodGet, "/resources", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	server2.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), "/login?next=") {
		t.Fatalf("expected non-persistent session to be rejected after simulated restart, got %d location %q", rec.Code, rec.Header().Get("Location"))
	}
	events, err := store.ListAuditEvents(10)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if !auditEventsContain(events, "session_rejected_restart_generation") {
		t.Fatalf("expected restart generation rejection audit event, got %#v", events)
	}
}

func TestSessionExpiryRevocationIdleTimeoutAndTouchThrottle(t *testing.T) {
	t.Setenv("APP_SESSION_PERSIST_ON_RESTART", "true")
	t.Setenv("APP_SESSION_TTL_MINUTES", "480")
	t.Setenv("APP_SESSION_IDLE_TIMEOUT_MINUTES", "60")
	server := newTestServer(t, "secret")
	user := createLocalTestUser(t, server, "alice", "correct horse battery")

	makeCookie := func(session db.Session, token string) *http.Cookie {
		if err := server.store.CreateSession(session); err != nil {
			t.Fatalf("create session: %v", err)
		}
		return &http.Cookie{Name: browserSessionCookieName, Value: token, Path: "/"}
	}
	requestResources := func(cookie *http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/resources", nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		server.Routes().ServeHTTP(rec, req)
		return rec
	}

	expiredToken, expiredSession, err := server.newBrowserSession(user.ID, httptest.NewRequest(http.MethodGet, "/", nil))
	if err != nil {
		t.Fatalf("new expired session: %v", err)
	}
	expiredSession.ExpiresAt = time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	expiredCookie := makeCookie(expiredSession, expiredToken)
	if rec := requestResources(expiredCookie); rec.Code != http.StatusFound {
		t.Fatalf("expected expired session redirect, got %d", rec.Code)
	}

	revokedToken, revokedSession, err := server.newBrowserSession(user.ID, httptest.NewRequest(http.MethodGet, "/", nil))
	if err != nil {
		t.Fatalf("new revoked session: %v", err)
	}
	revokedCookie := makeCookie(revokedSession, revokedToken)
	if err := server.store.RevokeSession(revokedSession.ID); err != nil {
		t.Fatalf("revoke session: %v", err)
	}
	if rec := requestResources(revokedCookie); rec.Code != http.StatusFound {
		t.Fatalf("expected revoked session redirect, got %d", rec.Code)
	}

	idleToken, idleSession, err := server.newBrowserSession(user.ID, httptest.NewRequest(http.MethodGet, "/", nil))
	if err != nil {
		t.Fatalf("new idle session: %v", err)
	}
	idleSession.LastSeenAt = time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)
	idleCookie := makeCookie(idleSession, idleToken)
	if rec := requestResources(idleCookie); rec.Code != http.StatusFound {
		t.Fatalf("expected idle session redirect, got %d", rec.Code)
	}

	freshToken, freshSession, err := server.newBrowserSession(user.ID, httptest.NewRequest(http.MethodGet, "/", nil))
	if err != nil {
		t.Fatalf("new fresh session: %v", err)
	}
	freshCookie := makeCookie(freshSession, freshToken)
	if rec := requestResources(freshCookie); rec.Code != http.StatusOK {
		t.Fatalf("expected fresh session success, got %d", rec.Code)
	}
	got, found, err := server.store.GetSession(freshSession.ID)
	if err != nil || !found {
		t.Fatalf("get fresh session: found=%v err=%v", found, err)
	}
	if got.LastSeenAt != freshSession.LastSeenAt {
		t.Fatalf("expected last_seen_at touch to be throttled, before %q after %q", freshSession.LastSeenAt, got.LastSeenAt)
	}

	events, err := server.store.ListAuditEvents(20)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	for _, want := range []string{"session_rejected_expired", "session_rejected_revoked", "session_rejected_idle_timeout"} {
		if !auditEventsContain(events, want) {
			t.Fatalf("expected audit event %q, got %#v", want, events)
		}
	}
}

func TestUnauthenticatedProxyFetchGetsJSONLoginRequired(t *testing.T) {
	t.Setenv("APP_PROXY_REQUIRE_LOGIN", "true")
	server := newProxyFetchTestServer(t, "https://upstream.example")
	createLocalTestUser(t, server, "alice", "correct horse battery")

	req := httptest.NewRequest(http.MethodGet, "/odo/https/www.jstor.org/data.json", nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d body %s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode login required response: %v", err)
	}
	if body["error"] != "login_required" || body["login_url"] != "/login" || body["reason"] != "proxy access requires login" {
		t.Fatalf("unexpected login required response: %#v", body)
	}
}

func TestProxyLoginRequiredAccessLogIsPrivacySafe(t *testing.T) {
	t.Setenv("APP_PROXY_REQUIRE_LOGIN", "true")
	var buf bytes.Buffer
	accessLogger, err := accesslog.New(accesslog.FormatPrivacy, &buf)
	if err != nil {
		t.Fatalf("create access logger: %v", err)
	}
	server := newProxyFetchTestServerWithAccessLog(t, "https://upstream.example", accessLogger)
	createLocalTestUser(t, server, "alice", "correct horse battery")

	req := httptest.NewRequest(http.MethodGet, "/odo/https/www.jstor.org/stable/123456?token=secret", nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	logs := buf.String()
	for _, want := range []string{"decision=login_required", "route=/odo", "target_host=www.jstor.org", "resource_id=jstor", "next_path=/odo/https/www.jstor.org/stable/123456"} {
		if !strings.Contains(logs, want) {
			t.Fatalf("expected privacy access log to contain %q, got:\n%s", want, logs)
		}
	}
	if strings.Contains(logs, "token=secret") || strings.Contains(logs, "stable/123456?") {
		t.Fatalf("login-required access log should not include query/full URL, got:\n%s", logs)
	}
}

func TestProxyRequireLoginFalseAllowsDevProxyAccess(t *testing.T) {
	t.Setenv("APP_PROXY_REQUIRE_LOGIN", "false")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("dev proxied ok"))
	}))
	defer upstream.Close()
	server := newProxyFetchTestServerWithAdmin(t, upstream.URL, "secret")

	req := httptest.NewRequest(http.MethodGet, "/odo/https/www.jstor.org/", nil)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "dev proxied ok") {
		t.Fatalf("expected dev proxy access, got %d body %s", rec.Code, rec.Body.String())
	}
}

func TestAnonymousURLRuleBypassesProxyLoginForMatchingAsset(t *testing.T) {
	t.Setenv("APP_PROXY_REQUIRE_LOGIN", "true")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("public asset"))
	}))
	defer upstream.Close()
	server := newProxyFetchTestServerWithAdmin(t, upstream.URL, "secret")
	createLocalTestUser(t, server, "alice", "correct horse battery")
	if err := server.store.UpsertResource(resources.Resource{
		ID:     "economist",
		Title:  "Economist",
		Status: "active",
		Domains: []resources.DomainRule{
			{Host: "www.economist.com", Match: "exact", Action: "proxy"},
		},
		AnonymousURLRules: []resources.AnonymousURLRule{
			{Pattern: "https://cms-films.economist.com/*", Behavior: "allow_public_proxy", Methods: []string{"GET", "HEAD"}},
		},
	}); err != nil {
		t.Fatalf("upsert anonymous resource: %v", err)
	}

	assetReq := httptest.NewRequest(http.MethodGet, "/odo/https/cms-films.economist.com/trailer.js", nil)
	assetRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(assetRec, assetReq)
	if assetRec.Code != http.StatusOK || !strings.Contains(assetRec.Body.String(), "public asset") {
		t.Fatalf("expected anonymous asset through proxy, got %d body %s", assetRec.Code, assetRec.Body.String())
	}

	apiReq := httptest.NewRequest(http.MethodGet, "/api/v1/system", nil)
	apiRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(apiRec, apiReq)
	if apiRec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous URL rules should not bypass admin APIs, got %d body %s", apiRec.Code, apiRec.Body.String())
	}
}

func TestResourcesPageRequiresLoginAndLogoutRevokesSession(t *testing.T) {
	t.Setenv("APP_PROXY_REQUIRE_LOGIN", "true")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("proxied after login"))
	}))
	defer upstream.Close()
	server := newProxyFetchTestServer(t, upstream.URL)
	createLocalTestUser(t, server, "alice", "correct horse battery")

	resourcesReq := httptest.NewRequest(http.MethodGet, "/resources", nil)
	resourcesRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(resourcesRec, resourcesReq)
	if resourcesRec.Code != http.StatusFound || resourcesRec.Header().Get("Location") != "/login?next=%2Fresources" {
		t.Fatalf("expected unauthenticated resources redirect, got %d location %q", resourcesRec.Code, resourcesRec.Header().Get("Location"))
	}

	cookie := loginTestUser(t, server, "alice", "correct horse battery", "/resources")
	logoutReq := httptest.NewRequest(http.MethodPost, "/logout", nil)
	logoutReq.AddCookie(cookie)
	logoutRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(logoutRec, logoutReq)
	if logoutRec.Code != http.StatusFound || logoutRec.Header().Get("Location") != "/login" {
		t.Fatalf("expected logout redirect to login, got %d location %q", logoutRec.Code, logoutRec.Header().Get("Location"))
	}
	cleared := findCookie(logoutRec.Result().Cookies(), browserSessionCookieName)
	if cleared == nil || cleared.MaxAge >= 0 {
		t.Fatalf("expected logout to clear session cookie, got %#v", cleared)
	}

	proxyReq := httptest.NewRequest(http.MethodGet, "/odo/https/www.jstor.org/", nil)
	proxyReq.Header.Set("Accept", "text/html")
	proxyReq.AddCookie(cookie)
	proxyRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(proxyRec, proxyReq)
	if proxyRec.Code != http.StatusFound || !strings.HasPrefix(proxyRec.Header().Get("Location"), "/login?next=") {
		t.Fatalf("expected logged-out proxy request to redirect to login, got %d location %q", proxyRec.Code, proxyRec.Header().Get("Location"))
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
	if err := server.store.UpsertResource(resources.Resource{
		ID:      "ebscohost",
		Name:    "EBSCOhost",
		Status:  "active",
		Domains: []resources.DomainRule{{Host: "search.ebscohost.com", Match: "exact"}},
	}); err != nil {
		t.Fatalf("upsert EBSCOhost resource: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/c/pjt2xq/search", nil)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Referer", "http://127.0.0.1:8080/odo/https/search.ebscohost.com/login.aspx")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected document recovery redirect, got %d with body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "/odo/https/search.ebscohost.com/c/pjt2xq/search" {
		t.Fatalf("expected canonical proxy redirect, got %q", got)
	}
	events := server.missedDiag.Recent()
	if len(events) == 0 {
		t.Fatal("expected missed rewrite diagnostics event")
	}
	event := events[0]
	if event.Type != proxy.MissedRewriteRecoveredEventType || event.RequestKind != proxy.RequestKindDocument || event.RecoveryAction != proxy.RecoveryActionRedirectedToCanonical || !event.Recovered {
		t.Fatalf("expected document redirect diagnostics, got %#v", event)
	}
	if event.CanonicalProxyPath != "/odo/https/search.ebscohost.com/c/pjt2xq/search" || event.Path != "/c/pjt2xq/search" || event.LocalPath != "/c/pjt2xq/search" || event.RecoveredTargetHost != "search.ebscohost.com" {
		t.Fatalf("expected canonical path without query, got %q", event.CanonicalProxyPath)
	}
}

func TestUnknownDocumentPathRedirectPreservesQuery(t *testing.T) {
	server := newProxyFetchTestServer(t, "http://127.0.0.1")
	req := httptest.NewRequest(http.MethodGet, "/action/doBasicSearch?Query=science", nil)
	req.Header.Set("Accept", "text/html")
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

func TestUnknownLocalAPIPathIsNotRecovered(t *testing.T) {
	server := newProxyFetchTestServer(t, "http://127.0.0.1")
	req := httptest.NewRequest(http.MethodGet, "/api/foo", nil)
	req.Header.Set("Referer", "http://127.0.0.1:8080/odo/https/www.jstor.org/")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected local API path to remain protected, got %d with body %s", rec.Code, rec.Body.String())
	}
	events := server.missedDiag.Recent()
	if len(events) == 0 || events[0].Reason != "protected app path" || events[0].Recovered {
		t.Fatalf("expected protected-path diagnostics, got %#v", events)
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

func TestRecoveredAssetRequiresLoginUnlessAnonymousRuleMatches(t *testing.T) {
	t.Setenv("APP_PROXY_REQUIRE_LOGIN", "true")
	server := newProxyFetchTestServer(t, "http://127.0.0.1")
	createLocalTestUser(t, server, "alice", "correct horse battery")

	req := httptest.NewRequest(http.MethodGet, "/assets/app.js", nil)
	req.Header.Set("Accept", "application/javascript,*/*")
	req.Header.Set("Sec-Fetch-Dest", "script")
	req.Header.Set("Referer", "http://127.0.0.1:8080/odo/https/www.jstor.org/")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthenticated recovered asset to require login, got %d body %s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode login required response: %v", err)
	}
	if body["error"] != "login_required" {
		t.Fatalf("expected login_required response, got %#v", body)
	}

	events := server.missedDiag.Recent()
	if len(events) == 0 || events[0].RecoveryAction != proxy.RecoveryActionDenied || events[0].Reason != "proxy access requires login" {
		t.Fatalf("expected denied recovery diagnostics, got %#v", events)
	}
}

func TestRecoveredAssetAnonymousRuleBypassesLogin(t *testing.T) {
	t.Setenv("APP_PROXY_REQUIRE_LOGIN", "true")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("anonymous recovered asset"))
	}))
	defer upstream.Close()
	server := newProxyFetchTestServer(t, upstream.URL)
	createLocalTestUser(t, server, "alice", "correct horse battery")
	if err := server.store.UpsertResource(resources.Resource{
		ID:        "jstor",
		Title:     "JSTOR",
		Status:    "active",
		EntryURLs: []string{"https://www.jstor.org/"},
		Domains:   []resources.DomainRule{{Host: "www.jstor.org", Match: "exact", Action: "proxy"}},
		AnonymousURLRules: []resources.AnonymousURLRule{
			{Pattern: "https://www.jstor.org/assets/*", Behavior: "allow_public_proxy", Methods: []string{"GET", "HEAD"}},
		},
	}); err != nil {
		t.Fatalf("upsert anonymous recovery resource: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/assets/app.js", nil)
	req.Header.Set("Accept", "application/javascript,*/*")
	req.Header.Set("Sec-Fetch-Dest", "script")
	req.Header.Set("Referer", "http://127.0.0.1:8080/odo/https/www.jstor.org/")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "anonymous recovered asset") {
		t.Fatalf("expected anonymous recovered asset to be proxied, got %d body %s", rec.Code, rec.Body.String())
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

	noRefererReq := httptest.NewRequest(http.MethodGet, "/c/pjt2xq/search", nil)
	noRefererReq.Header.Set("Accept", "text/html")
	noReferer := httptest.NewRecorder()
	server.Routes().ServeHTTP(noReferer, noRefererReq)
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
	for _, path := range []string{"/api/v1/search", "/api/search", "/admin/assets/app.js", "/login/vendor", "/logout/vendor", "/resources/vendor", "/odometer"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Referer", "http://127.0.0.1:8080/odo/https/www.jstor.org/")
		rec := httptest.NewRecorder()
		server.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected protected path %s to return 404, got %d", path, rec.Code)
		}
	}
}

func TestLocalDocumentRoutesRemainLocalWithProxiedReferer(t *testing.T) {
	server := newProxyFetchTestServer(t, "http://127.0.0.1")
	for _, path := range []string{"/login", "/admin", "/resources"} {
		before := len(server.missedDiag.Recent())
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Accept", "text/html")
		req.Header.Set("Referer", "http://127.0.0.1:8080/odo/https/www.jstor.org/")
		rec := httptest.NewRecorder()
		server.Routes().ServeHTTP(rec, req)
		if strings.HasPrefix(rec.Header().Get("Location"), proxy.PublicProxyPath) {
			t.Fatalf("local route %s was recovered to %q", path, rec.Header().Get("Location"))
		}
		if got := len(server.missedDiag.Recent()); got != before {
			t.Fatalf("local route %s recorded missed rewrite diagnostics", path)
		}
	}
}

func TestRecoveredDocumentRequiresLoginAtCanonicalPath(t *testing.T) {
	t.Setenv("APP_PROXY_REQUIRE_LOGIN", "true")
	server := newProxyFetchTestServer(t, "http://127.0.0.1")
	createLocalTestUser(t, server, "alice", "correct horse battery")
	canonical := "/odo/https/www.jstor.org/c/pjt2xq/search?query=history"

	req := httptest.NewRequest(http.MethodGet, "/c/pjt2xq/search?query=history", nil)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Referer", "http://127.0.0.1:8080/odo/https/www.jstor.org/login.aspx")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/login?next="+url.QueryEscape(canonical) {
		t.Fatalf("expected canonical login redirect, got %d location %q", rec.Code, rec.Header().Get("Location"))
	}

	cookie := loginTestUser(t, server, "alice", "correct horse battery", "/resources")
	authReq := httptest.NewRequest(http.MethodGet, "/c/pjt2xq/search?query=history", nil)
	authReq.Header.Set("Accept", "text/html")
	authReq.Header.Set("Referer", "http://127.0.0.1:8080/odo/https/www.jstor.org/login.aspx")
	authReq.AddCookie(cookie)
	authRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(authRec, authReq)
	if authRec.Code != http.StatusFound || authRec.Header().Get("Location") != canonical {
		t.Fatalf("expected authenticated canonical redirect, got %d location %q", authRec.Code, authRec.Header().Get("Location"))
	}
}

func TestRecoveredDocumentAnonymousRuleIsOnlyLoginBypass(t *testing.T) {
	t.Setenv("APP_PROXY_REQUIRE_LOGIN", "true")
	server := newProxyFetchTestServer(t, "http://127.0.0.1")
	createLocalTestUser(t, server, "alice", "correct horse battery")
	if err := server.store.UpsertResource(resources.Resource{
		ID:        "jstor",
		Title:     "JSTOR",
		Status:    "active",
		EntryURLs: []string{"https://www.jstor.org/"},
		Domains:   []resources.DomainRule{{Host: "www.jstor.org", Match: "exact", Action: "proxy"}},
		AnonymousURLRules: []resources.AnonymousURLRule{
			{Pattern: "https://www.jstor.org/c/*", Behavior: "allow_public_proxy", Methods: []string{"GET"}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/c/pjt2xq/search", nil)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Referer", "http://127.0.0.1:8080/odo/https/www.jstor.org/login.aspx")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/odo/https/www.jstor.org/c/pjt2xq/search" {
		t.Fatalf("expected anonymous-rule canonical redirect, got %d location %q", rec.Code, rec.Header().Get("Location"))
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
	req.Header.Set("Authorization", "Bearer secret")
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
	req.Header.Set("Authorization", "Bearer secret")
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
	return createLocalTestUserWithRoles(t, server, username, password, []string{"user"})
}

func createLocalTestUserWithRoles(t *testing.T, server *Server, username, password string, roles []string) db.User {
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
		Roles:        roles,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := server.store.CreateUser(user); err != nil {
		t.Fatalf("create local test user: %v", err)
	}
	return user
}

func loginTestUser(t *testing.T, server *Server, username, password, next string) *http.Cookie {
	cookie, _ := loginTestUserWithCSRF(t, server, username, password, next)
	return cookie
}

func loginTestUserWithCSRF(t *testing.T, server *Server, username, password, next string) (*http.Cookie, string) {
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
	sessionCookie := findCookie(rec.Result().Cookies(), browserSessionCookieName)
	if sessionCookie == nil {
		t.Fatalf("login did not set %s cookie; headers=%v", browserSessionCookieName, rec.Header())
	}
	if !sessionCookie.HttpOnly || sessionCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("login session cookie missing security attributes: %#v", sessionCookie)
	}
	csrf := findCookie(rec.Result().Cookies(), csrfCookieName)
	if csrf == nil || csrf.Value == "" || csrf.HttpOnly {
		t.Fatalf("login did not set usable CSRF cookie; cookies=%v", rec.Result().Cookies())
	}
	return sessionCookie, csrf.Value
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func auditEventsContain(events []db.AuditEvent, event string) bool {
	for _, item := range events {
		if item.Event == event {
			return true
		}
	}
	return false
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
