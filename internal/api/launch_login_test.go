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
)

func TestLaunchLoginContinuationFlowAndPrivacy(t *testing.T) {
	t.Setenv("APP_PUBLIC_URL", "https://odo.example")
	t.Setenv("APP_PROXY_REQUIRE_LOGIN", "true")
	var logs bytes.Buffer
	logger, err := accesslog.New(accesslog.FormatPrivacy, &logs)
	if err != nil {
		t.Fatal(err)
	}
	server := newTestServerWithConfigAndAccessLog(t, "secret", t.TempDir(), logger)
	server.httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("login continuation fetched upstream")
		return nil, errors.New("unexpected fetch")
	})}
	upsertTestResource(t, server, "vendor")
	createLocalTestUser(t, server, "alice", "correct horse battery")
	target := "https://vendor.example.org/a%2Fb?url=https%3A%2F%2Fother.example%2F&term=private-search"
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, httptest.NewRequest("GET", "/launch?url="+url.QueryEscape(target), nil))
	if rec.Code != 302 {
		t.Fatalf("launch to login: %d %s", rec.Code, rec.Body.String())
	}
	login, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || login.Path != "/login" || strings.Contains(login.String(), "vendor") || strings.Contains(login.String(), "private-search") {
		t.Fatalf("unsafe login location: %v err=%v", login, err)
	}
	next := login.Query().Get("next")
	continuation, err := url.Parse(next)
	if err != nil {
		t.Fatal(err)
	}
	token := continuation.Query().Get("token")
	page := httptest.NewRecorder()
	server.Routes().ServeHTTP(page, httptest.NewRequest("GET", login.String(), nil))
	if page.Code != 200 || page.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("continuation login page is cacheable: %d %s", page.Code, page.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("nonce cookies: %v", cookies)
	}
	nonce := cookies[0]
	if nonce.Name != "__Host-"+launchNonceCookieName || !nonce.HttpOnly || !nonce.Secure || nonce.Domain != "" || nonce.Path != "/" || nonce.SameSite != http.SameSiteLaxMode {
		t.Fatalf("unsafe browser binding cookie: %+v", nonce)
	}
	session := loginTestUser(t, server, "alice", "correct horse battery", next)
	unsigned := httptest.NewRequest("GET", next, nil)
	unsigned.AddCookie(nonce)
	unsignedRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(unsignedRec, unsigned)
	if unsignedRec.Code != 401 {
		t.Fatalf("continuation accepted without login: %d", unsignedRec.Code)
	}
	// A copied URL without the browser nonce cannot redeem the destination.
	wrong := httptest.NewRequest("GET", next, nil)
	wrong.AddCookie(session)
	wrongRec := httptest.NewRecorder()
	server.Routes().ServeHTTP(wrongRec, wrong)
	if wrongRec.Code != 404 {
		t.Fatalf("missing browser binding accepted: %d", wrongRec.Code)
	}
	for attempt, want := range []int{302, 404} {
		req := httptest.NewRequest("GET", next, nil)
		req.AddCookie(session)
		req.AddCookie(nonce)
		result := httptest.NewRecorder()
		server.Routes().ServeHTTP(result, req)
		if result.Code != want {
			t.Fatalf("redemption %d: got %d want %d: %s", attempt, result.Code, want, result.Body.String())
		}
		if attempt == 0 && result.Header().Get("Location") != "/odo/https/vendor.example.org/a%2Fb?url=https%3A%2F%2Fother.example%2F&term=private-search" {
			t.Fatalf("destination changed: %q", result.Header().Get("Location"))
		}
	}
	events, err := server.store.ListAuditEvents(100)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{token, nonce.Value, "private-search", "other.example"} {
		if strings.Contains(logs.String(), secret) {
			t.Fatalf("access log leaked continuation data: %s", logs.String())
		}
		for _, event := range events {
			if strings.Contains(event.Detail, secret) {
				t.Fatalf("audit leaked continuation data: %s", event.Detail)
			}
		}
	}
}

func TestLaunchContinuationRechecksPolicyAndDNS(t *testing.T) {
	t.Setenv("APP_PROXY_REQUIRE_LOGIN", "true")
	for _, change := range []string{"disabled", "GET denied", "unsafe DNS"} {
		t.Run(change, func(t *testing.T) {
			server := newTestServer(t, "secret")
			upsertTestResource(t, server, "vendor")
			createLocalTestUser(t, server, "alice", "correct horse battery")
			rec := httptest.NewRecorder()
			server.Routes().ServeHTTP(rec, httptest.NewRequest("GET", "/launch?url=https://vendor.example.org/private", nil))
			if rec.Code != 302 {
				t.Fatalf("begin launch: %d %s", rec.Code, rec.Body.String())
			}
			login, _ := url.Parse(rec.Header().Get("Location"))
			next := login.Query().Get("next")
			cookie := loginTestUser(t, server, "alice", "correct horse battery", next)
			if change == "unsafe DNS" {
				server.ipLookup = func(context.Context, string) ([]net.IPAddr, error) {
					return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
				}
			} else {
				item, _, err := server.store.GetResource("vendor")
				if err != nil {
					t.Fatal(err)
				}
				if change == "disabled" {
					item.Status = "disabled"
				} else {
					item.HTTPMethods = []string{"POST"}
				}
				if err := server.store.UpsertResource(item); err != nil {
					t.Fatal(err)
				}
			}
			req := httptest.NewRequest("GET", next, nil)
			req.AddCookie(cookie)
			req.AddCookie(rec.Result().Cookies()[0])
			result := httptest.NewRecorder()
			server.Routes().ServeHTTP(result, req)
			if result.Code != 403 || result.Header().Get("Location") != "" {
				t.Fatalf("changed policy bypassed: %d %s", result.Code, result.Body.String())
			}
		})
	}
}
