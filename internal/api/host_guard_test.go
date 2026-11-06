package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"example.org/odo/internal/accesslog"
)

func TestHostGuardClassifiesBeforeCallingNext(t *testing.T) {
	t.Setenv("APP_HOST_GUARD", "true")
	t.Setenv("APP_PUBLIC_URL", "https://odo.example")
	t.Setenv("APP_PROXY_BASE_DOMAIN", "proxy.example")
	server := newTestServer(t, "secret")
	calls := 0
	handler := server.guardHost(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, tc := range []struct {
		name, host, absolute string
		want                 int
	}{
		{"central", "odo.example", "", 204},
		{"central equivalent", "ODO.EXAMPLE.:443", "", 204},
		{"absolute equivalent", "odo.example", "https://ODO.EXAMPLE.:443/about", 204},
		{"unknown", "evil.example", "", 421},
		{"vendor candidate", "h-abc.proxy.example", "", 421},
		{"conflicting absolute", "odo.example", "https://evil.example/about", 421},
		{"conflicting Host", "evil.example", "https://odo.example/about", 421},
		{"absolute http", "odo.example", "http://odo.example/about", 421},
		{"unexpected port", "odo.example:8443", "", 421},
		{"absent Host", "", "", 421},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := "/about"
			if tc.absolute != "" {
				target = tc.absolute
			}
			req := httptest.NewRequest("GET", target, nil)
			req.Host = tc.host
			req.Header.Set("X-Forwarded-Host", "odo.example")
			req.Header.Set("Forwarded", "host=odo.example;proto=https")
			if tc.want == 204 {
				req.Header.Set("X-Forwarded-Host", "evil.example")
				req.Header.Set("Forwarded", "host=evil.example;proto=http")
			}
			rec := httptest.NewRecorder()
			before := calls
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("got %d want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
			if tc.want != 204 && (calls != before || len(rec.Result().Cookies()) != 0 || rec.Header().Get("Cache-Control") != "no-store") {
				t.Fatal("rejected authority reached next handler or created cookies")
			}
		})
	}
	record, err := server.store.RegisterProxyHostname("vendor.example", "odo.example", "proxy.example")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/about", nil)
	req.Host = record.Label + ".proxy.example"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 421 {
		t.Fatalf("registered vendor reached central application: %d", rec.Code)
	}
}

func TestHostGuardRejectsBeforeCredentialAndDatabaseProcessing(t *testing.T) {
	t.Setenv("APP_HOST_GUARD", "true")
	t.Setenv("APP_PUBLIC_URL", "https://odo.example")
	t.Setenv("APP_PROXY_BASE_DOMAIN", "proxy.example")
	// No store, HTTP client, registry, or session state exists to be accessed.
	server := &Server{}
	handler := server.Routes()
	for _, path := range []string{"/login", "/admin", "/api/v1/resources", "/api/v1/proxy-hostnames/reconcile", "/launch", "/odo/https/vendor.example/", "/about"} {
		for _, method := range []string{"GET", "POST"} {
			req := httptest.NewRequest(method, path, nil)
			req.Host = "h-abc.proxy.example"
			req.Header.Set("Authorization", "Bearer secret")
			req.AddCookie(&http.Cookie{Name: browserSessionCookieName, Value: "untrusted-session"})
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != 421 || len(rec.Result().Cookies()) != 0 {
				t.Fatalf("%s %s reached application processing: %d %s", method, path, rec.Code, rec.Body.String())
			}
		}
	}
}

func TestHostGuardDisabledAndMisconfiguration(t *testing.T) {
	t.Setenv("APP_PUBLIC_URL", "")
	t.Setenv("APP_PROXY_BASE_DOMAIN", "")
	for _, flag := range []string{"", "false", "off", "0", "true", "on", "typo"} {
		t.Run(flag, func(t *testing.T) {
			t.Setenv("APP_HOST_GUARD", flag)
			called := false
			handler := (&Server{}).guardHost(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { called = true; w.WriteHeader(204) }))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest("GET", "/about", nil))
			disabled := flag == "" || flag == "false" || flag == "off" || flag == "0"
			if disabled {
				if !called || rec.Code != 204 || ValidateHostGuardConfig() != nil {
					t.Fatal("disabled guard changed legacy behavior")
				}
			} else if called || rec.Code != 503 || ValidateHostGuardConfig() == nil {
				t.Fatal("invalid enabled configuration did not fail closed")
			}
		})
	}
}

func TestHostGuardRejectionUsesPrivacySafeRoute(t *testing.T) {
	t.Setenv("APP_HOST_GUARD", "true")
	t.Setenv("APP_PUBLIC_URL", "https://odo.example")
	t.Setenv("APP_PROXY_BASE_DOMAIN", "proxy.example")
	var logs bytes.Buffer
	logger, err := accesslog.New(accesslog.FormatPrivacy, &logs)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{accessLog: logger}
	req := httptest.NewRequest("GET", "/private-title?term=private-query", nil)
	req.Host = "unknown.example"
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != 421 || !strings.Contains(logs.String(), "host_rejected") || strings.Contains(logs.String(), "private-") {
		t.Fatalf("unsafe rejection log: status=%d log=%s", rec.Code, logs.String())
	}
}
