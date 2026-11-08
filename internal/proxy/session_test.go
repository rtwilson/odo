package proxy

import (
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRandomSessionIDRequiresFullRandomInput(t *testing.T) {
	for _, input := range []string{"", "partial"} {
		t.Run(input, func(t *testing.T) {
			id, err := randomSessionID(strings.NewReader(input))
			want := io.EOF
			if input != "" {
				want = io.ErrUnexpectedEOF
			}
			if id != "" || !errors.Is(err, want) {
				t.Fatalf("incomplete randomness produced an ID: id=%q err=%v", id, err)
			}
		})
	}
	raw := strings.Repeat("x", 32)
	id, err := randomSessionID(strings.NewReader(raw))
	decoded, decodeErr := base64.RawURLEncoding.DecodeString(id)
	if err != nil || decodeErr != nil || string(decoded) != raw {
		t.Fatal("session ID did not encode all 32 random bytes")
	}
}

func TestSessionStoreRandomFailureCreatesNoStateOrCookie(t *testing.T) {
	store := NewSessionStore(0)
	store.random = strings.NewReader("")
	rec := httptest.NewRecorder()
	info, err := store.GetOrCreate(httptest.NewRequest("GET", "/odo", nil), rec)
	if !errors.Is(err, io.EOF) || info != (SessionInfo{}) || store.Count() != 0 || len(rec.Result().Cookies()) != 0 {
		t.Fatal("random failure created a proxy session or cookie")
	}
}

func TestSessionStoreReusesExistingSessionWithoutNewRandomness(t *testing.T) {
	store := NewSessionStore(0)
	rec := httptest.NewRecorder()
	first, err := store.GetOrCreate(httptest.NewRequest("GET", "/odo", nil), rec)
	if err != nil || !first.Created || first.Jar == nil {
		t.Fatalf("session creation failed: %v", err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(first.ID)
	if err != nil || len(decoded) != 32 {
		t.Fatal("session ID is not 32 random bytes")
	}
	cookie := findCookie(rec.Result().Cookies(), ProxySessionCookieName)
	if cookie == nil || cookie.Value != first.ID {
		t.Fatal("session cookie missing or changed")
	}
	store.random = strings.NewReader("")
	req := httptest.NewRequest("GET", "/odo", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	again, err := store.GetOrCreate(req, rec)
	if err != nil || again.Created || again.ID != first.ID || again.Jar != first.Jar || store.Count() != 1 || len(rec.Result().Cookies()) != 0 {
		t.Fatal("existing session required new randomness or changed jars")
	}
}

func TestFetchHandlerRandomFailureStopsBeforeUpstream(t *testing.T) {
	for _, mode := range []string{"path", "query", "dual"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("APP_PROXY_URL_MODE", mode)
			store := NewSessionStore(0)
			store.random = strings.NewReader("")
			var fetches int
			handler := FetchHandlerWithOptions(FetchOptions{
				Sessions: store,
				Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
				Client: roundTripFunc(func(*http.Request) (*http.Response, error) {
					fetches++
					return nil, io.ErrUnexpectedEOF
				}).client(),
				Check: allowedTargetCheck,
			})
			for _, path := range []string{"/odo/https/www.jstor.org/private?search=patron-query", "/odo?url=https%3A%2F%2Fwww.jstor.org%2Fprivate%3Fsearch%3Dpatron-query"} {
				body := strings.NewReader("private-request-body")
				req := httptest.NewRequest("POST", path, body)
				req.Header.Set("Cookie", "browser=private-cookie")
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code != 500 || rec.Header().Get("Cache-Control") != "no-store" || len(rec.Result().Cookies()) != 0 || store.Count() != 0 || fetches != 0 || body.Len() != len("private-request-body") {
					t.Fatalf("random failure did not stop proxying safely: status=%d fetches=%d", rec.Code, fetches)
				}
				for _, secret := range []string{"patron-query", "private-request-body", "private-cookie", "EOF"} {
					if strings.Contains(rec.Body.String(), secret) {
						t.Fatal("session failure disclosed request data or internal cause")
					}
				}
			}
		})
	}
}
