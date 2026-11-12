package api

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"example.org/odo/internal/accesslog"
	"example.org/odo/internal/proxy"
	"example.org/odo/internal/resources"
)

func TestExperimentalLegacyMigrationBookmarks(t *testing.T) {
	b := newHandoffBrowser(t, true, false)
	target := "https://vendor.example/a%2Fb?q=a+b&nested=https%3A%2F%2Fother.example%2Fx%3Fa%3D1%26b%3D2&url=vendor-data"
	for _, bookmark := range []string{
		"/odo?" + url.Values{"url": {target}}.Encode(),
		"/odo/?" + url.Values{"url": {target}}.Encode(),
		"/p?" + url.Values{"url": {target}}.Encode(),
		"/odo?url=" + target, // Supported raw-prefix compatibility.
		"/odo/https/vendor.example/a%2Fb?" + strings.SplitN(target, "?", 2)[1],
	} {
		t.Run(bookmark, func(t *testing.T) {
			response, body := b.request(t, "GET", "https://odo.example"+bookmark, nil)
			location, err := url.Parse(response.Header.Get("Location"))
			if response.StatusCode != 303 || err != nil || location.Scheme != "https" || location.Host != "odo.example" || location.Path != handoffStartPath || body != "" {
				t.Fatalf("migration response: %d %q", response.StatusCode, response.Header.Get("Location"))
			}
			token, valid := launchContinuationToken(location.RawQuery)
			stored, found := b.h.server.launchContinuations.peek(token, "", time.Now())
			if !valid || !found || stored != target {
				t.Fatal("opaque migration changed target bytes")
			}
			if len(response.Cookies()) != 0 || len(b.h.state.entries) != 0 || b.h.server.sessions.Count() != 0 {
				t.Fatal("migration created credentials or state")
			}
		})
	}
	// The normal launch/login continuation remains responsible for authentication.
	response, _ := b.request(t, "GET", "https://odo.example/p?"+url.Values{"url": {target}}.Encode(), nil)
	login, _ := b.request(t, "GET", response.Header.Get("Location"), nil)
	if login.StatusCode != 302 || !strings.HasPrefix(login.Header.Get("Location"), "/login?next=") || strings.Contains(login.Header.Get("Location"), "vendor.example") {
		t.Fatal("migration did not reach opaque login continuation")
	}
}

func TestExperimentalLegacyMigrationRejectsInvalidAndUnsafeTargets(t *testing.T) {
	b := newHandoffBrowser(t, true, true)
	for _, bookmark := range []string{
		"/odo", "/odo/", "/p", "/odo?url=", "/odo?url=%zz",
		"/odo?" + url.Values{"url": {b.target, "https://other.example/"}}.Encode(),
		"/p?" + url.Values{"url": {b.target}, "extra": {"bad"}}.Encode(),
		"/odo?" + url.Values{"url": {"https://vendor.example/?q=%zz"}}.Encode(),
		"/odo?" + url.Values{"url": {"https://vendor.example/#fragment"}}.Encode(),
		"/odo?" + url.Values{"url": {"https://user:pass@vendor.example/"}}.Encode(),
		"/odo?" + url.Values{"url": {"http://vendor.example/"}}.Encode(),
		"/odo?" + url.Values{"url": {"https://127.0.0.1/"}}.Encode(),
		"/odo?" + url.Values{"url": {"https://unauthorized.example/"}}.Encode(),
		"/odo/https/vendor.example/x?q=%zz",
		"/odo/https/vendor.example:8443/", "/odo/http/vendor.example/",
		"/%6fdo/https/vendor.example/", "/odo%2fhttps/vendor.example/",
		"/x/../odo/https/vendor.example/", "//odo/https/vendor.example/",
		"/api/v1/../../odo/https/vendor.example/",
		"/odo?url=" + strings.Repeat("x", proxy.MaxLaunchQueryBytes),
	} {
		response, body := b.request(t, "GET", "https://odo.example"+bookmark, nil)
		if response.StatusCode < 400 || response.Header.Get("Location") != "" || len(response.Cookies()) != 0 || strings.Contains(body, "<script") {
			t.Fatalf("invalid bookmark accepted: %q status=%d", bookmark, response.StatusCode)
		}
	}
	if len(b.h.state.entries) != 0 || b.h.server.sessions.Count() != 0 {
		t.Fatal("rejected migration allocated state")
	}
}

func TestExperimentalLegacyMigrationRevalidatesPolicyAndDNS(t *testing.T) {
	b := newHandoffBrowser(t, true, true)
	bookmark := "https://odo.example/p?" + url.Values{"url": {b.target}}.Encode()
	resource := resources.Resource{ID: "vendor", Name: "Vendor", Domains: []resources.DomainRule{{Host: "vendor.example"}}}
	for _, kind := range []string{"method", "disabled", "blocked", "private DNS", "DNS error", "database error"} {
		t.Run(kind, func(t *testing.T) {
			current := resource
			b.h.server.ipLookup = publicTestResolver
			switch kind {
			case "method":
				current.HTTPMethods = []string{"POST"}
			case "disabled":
				current.Status = "disabled"
			case "blocked":
				current.Domains = []resources.DomainRule{{Host: "vendor.example", Action: "block"}}
			case "private DNS":
				b.h.server.ipLookup = func(context.Context, string) ([]net.IPAddr, error) {
					return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
				}
			case "DNS error":
				b.h.server.ipLookup = func(context.Context, string) ([]net.IPAddr, error) { return nil, context.DeadlineExceeded }
			}
			if err := b.h.server.store.UpsertResource(current); err != nil {
				t.Fatal(err)
			}
			if kind == "database error" {
				if err := b.h.server.store.Close(); err != nil {
					t.Fatal(err)
				}
			}
			response, _ := b.request(t, "GET", bookmark, nil)
			if response.StatusCode < 400 || response.Header.Get("Location") != "" || len(response.Cookies()) != 0 || len(b.h.state.entries) != 0 {
				t.Fatal("failed live validation allowed migration")
			}
		})
	}
}

func TestExperimentalLegacyMigrationRejectsMethodsWithoutReadingBody(t *testing.T) {
	b := newHandoffBrowser(t, true, true)
	handler := b.h.server.Routes()
	for _, method := range []string{"HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"} {
		for _, path := range []string{"/odo", "/odo/", "/odo/https/vendor.example/article", "/p"} {
			body := strings.NewReader("private-request-body")
			req := httptest.NewRequest(method, path+"?url="+url.QueryEscape(b.target), body)
			req.Host = "odo.example"
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != 405 || rec.Header().Get("Allow") != "GET" || rec.Header().Get("Location") != "" || len(rec.Result().Cookies()) != 0 || body.Len() != len("private-request-body") {
				t.Fatalf("method %s on %s replayed, read, or redirected: %d", method, path, rec.Code)
			}
			if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Referrer-Policy") != "no-referrer" {
				t.Fatal("missing migration privacy headers")
			}
		}
	}
	if len(b.h.state.entries) != 0 {
		t.Fatal("unsafe method initiated handoff")
	}
}

func TestExperimentalLegacyMigrationBlocksRecoveryAndDiagnosticBodies(t *testing.T) {
	b := newHandoffBrowser(t, true, true)
	t.Setenv("APP_PROXY_REFERER_RECOVERY", "true")
	var fetches int
	b.h.server.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		fetches++
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}}, Body: io.NopCloser(strings.NewReader(`<script>vendorCode()</script>`)), Request: r}, nil
	})}
	handler := b.h.server.Routes()
	for _, path := range []string{"/article", "/script.js", "/p/https/vendor.example/", "/api/v1/proxy/test-fetch"} {
		method := "GET"
		if strings.HasPrefix(path, "/api/") {
			method = "POST"
		}
		body := strings.NewReader(`{"url":"https://vendor.example/"}`)
		unread := body.Len()
		req := httptest.NewRequest(method, "https://odo.example"+path, body)
		req.Header.Set("Origin", "https://odo.example")
		req.Header.Set("Authorization", "Bearer secret")
		req.Header.Set("Referer", "https://odo.example/odo/https/vendor.example/article")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code < 400 || strings.Contains(rec.Body.String(), "vendorCode") {
			t.Fatalf("alternate path delivered vendor content: %s %d", path, rec.Code)
		}
		if method == "POST" && (rec.Code != 403 || !strings.Contains(rec.Body.String(), "vendor content delivery is disabled") || body.Len() != unread) {
			t.Fatal("diagnostic fetch was not blocked before reading its body")
		}
	}
	// Even a future alternate caller of the proxy engine receives the blocker.
	rec := httptest.NewRecorder()
	b.h.server.proxyH.ServeHTTP(rec, httptest.NewRequest("GET", "/odo/https/vendor.example/", nil))
	if rec.Code != 403 || fetches != 0 {
		t.Fatal("experimental boundary reached upstream transport")
	}
}

func TestExperimentalLegacyMigrationLogPrivacy(t *testing.T) {
	b := newHandoffBrowser(t, true, true)
	for _, format := range []string{"privacy", "common", "combined", "json"} {
		for _, path := range []string{"/odo/https/vendor.example/private-path", "/api/v1/../../odo/https/vendor.example/private-path"} {
			b.logs.Reset()
			b.h.server.accessLog, _ = accesslog.New(format, b.logs)
			req := httptest.NewRequest("GET", "https://odo.example"+path+"?search=private-search", nil)
			req.Header.Set("Referer", "https://odo.example/private-referer")
			req.Header.Set("User-Agent", "private-agent")
			req.Header.Set("Cookie", "odo_proxy_sid=private-cookie")
			rec := httptest.NewRecorder()
			b.h.server.Routes().ServeHTTP(rec, req)
			want := 303
			if strings.HasPrefix(path, "/api/") {
				want = 400
			}
			if rec.Code != want {
				t.Fatalf("migration status: %d", rec.Code)
			}
			for _, secret := range []string{"private-path", "private-search", "private-referer", "private-agent", "private-cookie", "https://vendor.example"} {
				if strings.Contains(b.logs.String(), secret) {
					t.Fatalf("%s logs disclosed %s", format, secret)
				}
			}
		}
	}
}

func TestExperimentalLegacyMigrationPreservesCentralApplicationRoutes(t *testing.T) {
	b := newHandoffBrowser(t, true, true)
	handler := b.h.server.Routes()
	for _, path := range []string{"/admin", "/login", "/api/v1/health", "/about", "/openapi.yaml"} {
		for _, host := range []string{"odo.example", b.authority} {
			req := httptest.NewRequest("GET", "https://"+host+path, nil)
			req.Header.Set("Authorization", "Bearer secret")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			want := 200
			if host == b.authority {
				// Vendor hosts never reach central routes. Without a grant, the
				// experimental content boundary restarts the handoff at central
				// /launch (a navigation) before any upstream fetch.
				want = 303
			}
			if rec.Code != want || (host == b.authority && strings.Contains(rec.Body.String(), "<html")) {
				t.Fatalf("%s%s: got %d, want %d", host, path, rec.Code, want)
			}
		}
	}
}

func TestExperimentalLegacyMigrationDisabledPreservesDelivery(t *testing.T) {
	for _, mode := range []string{"path", "query", "dual"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("APP_PROXY_URL_MODE", mode)
			b := newHandoffBrowser(t, false, true)
			var fetches int
			b.h.server.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				fetches++
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}}, Body: io.NopCloser(strings.NewReader(`<html><script>vendorMarker()</script></html>`)), Request: r}, nil
			})}
			target, err := url.Parse(b.target)
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("GET", "https://odo.example"+proxy.BuildProxyURL(target), nil)
			req.AddCookie(&http.Cookie{Name: "__Host-odo_session", Value: b.central})
			rec := httptest.NewRecorder()
			b.h.server.Routes().ServeHTTP(rec, req)
			if rec.Code != 200 || fetches != 1 || !strings.Contains(rec.Body.String(), "vendorMarker") {
				t.Fatalf("disabled mode changed %s delivery: status=%d fetches=%d", mode, rec.Code, fetches)
			}
		})
	}
}
