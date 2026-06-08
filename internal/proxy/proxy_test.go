package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"example.org/odo/internal/resources"
)

func TestFetchHandlerRejectsUnsupportedMethod(t *testing.T) {
	handler := FetchHandler(http.DefaultClient, func(ctx context.Context, rawURL string) (*url.URL, resources.TestResult) {
		t.Fatal("target check should not run for unsupported methods")
		return nil, resources.TestResult{}
	})

	req := httptest.NewRequest(http.MethodPost, "/p?url=https://www.jstor.org/stable/example", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d with body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "method not allowed") {
		t.Fatalf("expected method not allowed JSON, got %s", rec.Body.String())
	}
}

func TestFetchHandlerDeniesUnmatchedURL(t *testing.T) {
	handler := FetchHandler(http.DefaultClient, func(ctx context.Context, rawURL string) (*url.URL, resources.TestResult) {
		return nil, resources.TestResult{Allowed: false, Reason: "no active resource domain rule matched"}
	})

	req := httptest.NewRequest(http.MethodGet, "/p?url="+url.QueryEscape("https://example.org/"), nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d with body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "target URL is not allowed") {
		t.Fatalf("expected safe denial response, got %s", rec.Body.String())
	}
}

func TestFetchHandlerFetchesAllowedURL(t *testing.T) {
	client := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type":  []string{"text/plain"},
				"Set-Cookie":    []string{"session=secret"},
				"Cache-Control": []string{"max-age=60"},
			},
			Body:          io.NopCloser(strings.NewReader("hello")),
			ContentLength: 5,
			Request:       req,
		}, nil
	}).client()
	handler := FetchHandler(client, allowedTargetCheck)

	req := httptest.NewRequest(http.MethodGet, "/p?url=https://www.jstor.org/stable/example", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d with body %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "hello" {
		t.Fatalf("expected upstream body, got %q", rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != "text/plain" {
		t.Fatalf("expected safe response header to be copied, got %q", rec.Header().Get("Content-Type"))
	}
	if rec.Header().Get("Set-Cookie") != "" {
		t.Fatalf("expected Set-Cookie not to be copied, got %q", rec.Header().Get("Set-Cookie"))
	}
}

func allowedTargetCheck(ctx context.Context, rawURL string) (*url.URL, resources.TestResult) {
	target, _ := url.Parse(rawURL)
	return target, resources.TestResult{
		Allowed:    true,
		ResourceID: "jstor",
		Matched:    &resources.DomainRule{Host: "www.jstor.org", Match: "exact"},
		Reason:     "matched active resource domain rule",
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func (f roundTripFunc) client() *http.Client {
	return &http.Client{
		Transport: f,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
