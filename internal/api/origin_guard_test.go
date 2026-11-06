package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"example.org/odo/internal/proxy"
)

func TestCentralOriginRequiresConfiguredHTTPSAuthority(t *testing.T) {
	config, err := proxy.NewHostRoutingConfig("https://odo.example", "proxy.example")
	if err != nil {
		t.Fatal(err)
	}
	for _, origin := range []string{"https://odo.example", "https://ODO.EXAMPLE.:443"} {
		if !centralOriginAllowed(origin, config) {
			t.Fatalf("rejected central origin %q", origin)
		}
	}
	for _, origin := range []string{
		"", "null", "http://odo.example", "https://odo.example:8443", "https://vendor.proxy.example",
		"https://odo.example.evil", "https://evil.example", "https://user@odo.example",
		"https://odo.example/", "https://odo.example?", "https://odo.example#", "https://odo.example?q=x",
		"https://odo.example https://evil.example", "https://odo.example,https://evil.example",
		" https://odo.example", "https://odo.example ", "https:odo.example", "https://odo%2eexample",
	} {
		if centralOriginAllowed(origin, config) {
			t.Fatalf("accepted hostile origin %q", origin)
		}
	}
}

func TestOriginGuardPolicyAndBearerException(t *testing.T) {
	t.Setenv("APP_HOST_GUARD", "true")
	t.Setenv("APP_PUBLIC_URL", "https://odo.example")
	t.Setenv("APP_PROXY_BASE_DOMAIN", "proxy.example")
	for _, tc := range []struct {
		name, method, path, bearer string
		origins                    []string
		want                       int
	}{
		{"login central", "POST", "/login", "", []string{"https://odo.example"}, 204},
		{"login missing", "POST", "/login", "", nil, 403},
		{"login cannot use bearer exception", "POST", "/login", "secret", nil, 403},
		{"logout central", "POST", "/logout", "", []string{"https://odo.example"}, 204},
		{"logout missing", "POST", "/logout", "", nil, 403},
		{"logout cannot use bearer exception", "POST", "/logout", "secret", nil, 403},
		{"logout same site", "POST", "/logout", "", []string{"https://vendor.proxy.example"}, 403},
		{"logout GET", "GET", "/logout", "", nil, 405},
		{"logout HEAD", "HEAD", "/logout", "", nil, 405},
		{"API central", "PATCH", "/api/v1/resources/vendor", "", []string{"https://odo.example"}, 204},
		{"API missing", "DELETE", "/api/v1/resources/vendor", "", nil, 403},
		{"API bearer no Origin", "POST", "/api/v1/resources", "secret", nil, 204},
		{"API bearer hostile Origin", "POST", "/api/v1/resources", "secret", []string{"https://evil.example"}, 403},
		{"API null", "POST", "/api/v1/resources", "", []string{"null"}, 403},
		{"API duplicate", "POST", "/api/v1/resources", "", []string{"https://odo.example", "https://odo.example"}, 403},
		{"login GET", "GET", "/login", "", nil, 204},
		{"vendor POST", "POST", "/odo/https/vendor.example/form", "", []string{"https://vendor.example"}, 204},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			handler := (&Server{}).guardCentralOrigin(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { called = true; w.WriteHeader(204) }))
			req := httptest.NewRequest(tc.method, tc.path, nil)
			for _, origin := range tc.origins {
				req.Header.Add("Origin", origin)
			}
			if tc.bearer != "" {
				req.Header.Set("Authorization", "Bearer "+tc.bearer)
			}
			req.Header.Set("Sec-Fetch-Site", "same-site")
			req.Header.Set("Referer", "https://odo.example/admin")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.want || called != (tc.want == 204) {
				t.Fatalf("got %d want %d, called=%v", rec.Code, tc.want, called)
			}
		})
	}
}

func TestOriginGuardRejectsBeforeAuthentication(t *testing.T) {
	t.Setenv("APP_HOST_GUARD", "true")
	t.Setenv("APP_PUBLIC_URL", "https://odo.example")
	t.Setenv("APP_PROXY_BASE_DOMAIN", "proxy.example")
	// Rejected requests must not touch the absent database or session state.
	handler := (&Server{}).Routes()
	for _, path := range []string{"/login", "/logout", "/api/v1/resources"} {
		req := httptest.NewRequest("POST", path, strings.NewReader("untrusted body"))
		req.Host = "odo.example"
		req.Header.Set("Origin", "https://vendor.proxy.example")
		req.Header.Set("Authorization", "Bearer secret")
		req.AddCookie(&http.Cookie{Name: "__Host-odo_session", Value: "untrusted"})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != 403 || len(rec.Result().Cookies()) != 0 || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("origin reached authentication: %d %s", rec.Code, rec.Body.String())
		}
	}
}

func TestOriginGuardDisabledPreservesLegacyBehavior(t *testing.T) {
	t.Setenv("APP_HOST_GUARD", "false")
	handler := (&Server{}).guardCentralOrigin(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	for _, method := range []string{"GET", "POST"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(method, "/logout", nil))
		if rec.Code != 204 {
			t.Fatalf("legacy request changed: %d", rec.Code)
		}
	}
}
