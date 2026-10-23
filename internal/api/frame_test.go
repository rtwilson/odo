package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"example.org/odo/internal/proxy"
)

func TestFrameRecoveryIsSilentAndPrivate(t *testing.T) {
	for _, tc := range []struct{ destination, path, contentType string }{
		{"iframe", "/private-title/viewer.html", "text/html"},
		{"frame", "/private-title/article.pdf", "application/pdf"},
		{"object", "/private-title/article.pdf", "application/pdf"},
		{"embed", "/private-title/article.pdf", "application/pdf"},
		{"iframe", "/private-title/data.json", "application/json"},
		{"iframe", "/private-title/api/data", "application/json"},
	} {
		t.Run(tc.destination+tc.path, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tc.path || r.URL.RawQuery != "private-query" {
					t.Errorf("wrong upstream target: %s", r.URL)
				}
				w.Header().Set("Content-Type", tc.contentType)
				w.Header().Set("X-Frame-Options", "DENY")
				w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
				_, _ = w.Write([]byte("frame body"))
			}))
			defer upstream.Close()
			server := newProxyFetchTestServer(t, upstream.URL)
			req := httptest.NewRequest("GET", tc.path+"?private-query", nil)
			req.Header.Set("Referer", "http://127.0.0.1:8080/odo/https/www.jstor.org/private-referrer")
			req.Header.Set("Sec-Fetch-Dest", tc.destination)
			req.Header.Set("Sec-Fetch-Mode", "navigate")
			req.Header.Set("Accept", "text/html,application/pdf;private-accept")
			rec := httptest.NewRecorder()
			server.Routes().ServeHTTP(rec, req)
			if rec.Code != 200 || !strings.Contains(rec.Body.String(), "frame body") || rec.Header().Get("Location") != "" {
				t.Fatalf("frame recovery = %d %s", rec.Code, rec.Body.String())
			}
			if rec.Header().Get("X-Frame-Options") != "" || rec.Header().Get("Content-Security-Policy") != "" {
				t.Fatal("frame blocked by response headers")
			}
			events := server.missedDiag.Recent()
			if len(events) != 1 || events[0].RequestKind != proxy.RequestKindFrame || events[0].RecoveryAction != proxy.RecoveryActionSilentlyProxied {
				t.Fatalf("unexpected recovery diagnostic: %#v", events)
			}
			payload, err := json.Marshal(events)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(payload), "private-") {
				t.Fatalf("private recovery values leaked: %s", payload)
			}
		})
	}
}

func TestFrameRecoveryRetainsAccessChecks(t *testing.T) {
	for _, tc := range []struct {
		name, path, referer string
		login               bool
		status              int
	}{
		{"unlisted host", "/viewer.pdf", "https://bad.example/", false, 403},
		{"login required", "/viewer.pdf", "https://www.jstor.org/", true, 401},
		{"protected API", "/api/private-frame", "https://www.jstor.org/", false, 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.login {
				t.Setenv("APP_PROXY_REQUIRE_LOGIN", "true")
			} else {
				t.Setenv("APP_PROXY_REQUIRE_LOGIN", "false")
			}
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("denied frame reached upstream") }))
			defer upstream.Close()
			server := newProxyFetchTestServer(t, upstream.URL)
			req := httptest.NewRequest("GET", tc.path, nil)
			req.Header.Set("Referer", "http://127.0.0.1:8080/odo/https/"+strings.TrimPrefix(tc.referer, "https://"))
			req.Header.Set("Sec-Fetch-Dest", "iframe")
			req.Header.Set("Accept", "text/html")
			rec := httptest.NewRecorder()
			server.Routes().ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.status, rec.Body.String())
			}
			if tc.status != http.StatusForbidden && (rec.Header().Get("X-Frame-Options") != "DENY" || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'")) {
				t.Fatal("Odo-owned error lost security headers")
			}
		})
	}
}

func TestFramedPDFRangeRetainsVendorSession(t *testing.T) {
	const pdf = "%PDF-1.7\x00\xff"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.SetCookie(w, &http.Cookie{Name: "vendor", Value: "private-session", Path: "/"})
			_, _ = w.Write([]byte("session ready"))
			return
		}
		cookie, err := r.Cookie("vendor")
		if err != nil || cookie.Value != "private-session" {
			t.Error("framed PDF lost upstream cookie session")
		}
		if r.Header.Get("Range") != "bytes=0-9" {
			t.Error("framed PDF lost range request")
		}
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Range", "bytes 0-9/100")
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("Content-Disposition", "inline")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write([]byte(pdf))
	}))
	defer upstream.Close()
	server := newProxyFetchTestServer(t, upstream.URL)
	handler := server.Routes()
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest("GET", "/odo/https/www.jstor.org/start", nil))
	cookie := findCookie(first.Result().Cookies(), proxy.ProxySessionCookieName)
	if cookie == nil {
		t.Fatal("missing proxy session cookie")
	}
	req := httptest.NewRequest("GET", "/private-article.pdf", nil)
	req.AddCookie(cookie)
	req.Header.Set("Referer", "http://127.0.0.1:8080/odo/https/www.jstor.org/start")
	req.Header.Set("Sec-Fetch-Dest", "iframe")
	req.Header.Set("Range", "bytes=0-9")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 206 || rec.Body.String() != pdf || rec.Header().Get("Content-Range") != "bytes 0-9/100" || rec.Header().Get("Content-Disposition") != "inline" {
		t.Fatalf("framed PDF range changed: %d %v", rec.Code, rec.Header())
	}
	for _, value := range rec.Header().Values("Set-Cookie") {
		if strings.Contains(value, "private-session") {
			t.Fatal("upstream session cookie leaked to browser")
		}
	}
}
