package api

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFaviconIsPublicAndOdoOwned(t *testing.T) {
	server := newTestServer(t, "secret")
	handler := server.Routes()
	for _, referer := range []string{"", "http://odo.example/odo/https/vendor.example/"} {
		req := httptest.NewRequest(http.MethodGet, "/favicon.ico", nil)
		req.Header.Set("Referer", referer)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		if got := rec.Header().Get("Content-Type"); got != "image/x-icon" {
			t.Fatalf("unexpected content type: %q", got)
		}
		if got := rec.Header().Get("Cache-Control"); got != "public, max-age=86400" {
			t.Fatalf("unexpected cache policy: %q", got)
		}
		if cookies := rec.Header().Values("Set-Cookie"); len(cookies) != 0 {
			t.Fatalf("favicon must not set cookies: %v", cookies)
		}
		if !bytes.Equal(rec.Body.Bytes(), faviconICO) || !bytes.HasPrefix(rec.Body.Bytes(), []byte{0, 0, 1, 0, 1, 0}) {
			t.Fatal("expected the embedded Odo ICO asset")
		}
	}
}

func TestOdoPagesDeclareFavicon(t *testing.T) {
	server := newTestServer(t, "secret")
	createLocalTestUser(t, server, "alice", "correct horse battery")
	cookie := loginTestUser(t, server, "alice", "correct horse battery", "/resources")
	handler := server.Routes()
	for _, path := range []string{"/login", "/admin", "/resources"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Header.Set("Referer", "http://odo.example/odo/https/vendor.example/")
			if path == "/admin" {
				req.Header.Set("Authorization", "Bearer secret")
			}
			if path == "/resources" {
				req.AddCookie(cookie)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
			}
			assertOdoFaviconHead(t, rec.Body.String())
		})
	}
	rec := httptest.NewRecorder()
	writeAdminForbidden(rec, "access denied")
	assertOdoFaviconHead(t, rec.Body.String())
	for _, path := range []string{"/login", "/admin", "/resources"} {
		rec := httptest.NewRecorder()
		server.internalError(rec, httptest.NewRequest(http.MethodGet, path, nil), errors.New("test error"))
		assertOdoFaviconHead(t, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1", nil))
	if strings.Contains(rec.Body.String(), "favicon") {
		t.Fatal("API response must not contain favicon markup")
	}
}

func assertOdoFaviconHead(t *testing.T, body string) {
	t.Helper()
	_, head, found := strings.Cut(body, "<head>")
	head, _, closed := strings.Cut(head, "</head>")
	if !found || !closed || !strings.Contains(head, `<link rel="icon" href="/favicon.ico">`) {
		t.Fatalf("expected explicit Odo favicon in head: %s", body)
	}
}

func TestProxiedHTMLKeepsVendorFavicons(t *testing.T) {
	t.Setenv("APP_PROXY_URL_MODE", "path")
	for _, icons := range []string{"", `<link rel="icon" href="/favicon.ico"><link rel="shortcut icon" href="/favicon.ico"><link rel="apple-touch-icon" href="/apple-touch-icon.png">`} {
		t.Run(icons, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				_, _ = w.Write([]byte("<html><head>" + icons + "</head><body>vendor</body></html>"))
			}))
			defer upstream.Close()
			server := newProxyFetchTestServer(t, upstream.URL)
			rec := httptest.NewRecorder()
			server.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/odo/https/www.jstor.org/", nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
			}
			body := rec.Body.String()
			if strings.Contains(body, `href="/favicon.ico"`) {
				t.Fatalf("proxy has Odo-owned favicon: %s", body)
			}
			if icons != "" {
				if strings.Count(body, `href="/odo/https/www.jstor.org/favicon.ico"`) != 2 || !strings.Contains(body, `href="/odo/https/www.jstor.org/apple-touch-icon.png"`) {
					t.Fatalf("vendor icon links were not rewritten: %s", body)
				}
			} else if strings.Contains(body, "favicon") {
				t.Fatalf("proxy injected a favicon: %s", body)
			}
		})
	}
}
