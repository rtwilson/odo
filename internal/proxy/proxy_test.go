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

func TestFetchHandlerRewritesHTMLAssetAttributes(t *testing.T) {
	html := `<html><head>` +
		`<link rel="stylesheet" href="/style.css">` +
		`<script src="/app.js"></script>` +
		`</head><body>` +
		`<img src="/image.png" data-src="/lazy.png">` +
		`<source src="/movie.mp4">` +
		`<iframe src="/frame.html"></iframe>` +
		`<video poster="/poster.jpg"></video>` +
		`<form action="/search"></form>` +
		`<a data-href="/data-link" href="/article"></a>` +
		`</body></html>`
	body, headers := fetchBody(t, "text/html; charset=utf-8", html, allowedHostTargetCheck)

	for _, want := range []string{
		`href="/p?url=https%3A%2F%2Fwww.jstor.org%2Fstyle.css"`,
		`src="/p?url=https%3A%2F%2Fwww.jstor.org%2Fapp.js"`,
		`src="/p?url=https%3A%2F%2Fwww.jstor.org%2Fimage.png"`,
		`data-src="/p?url=https%3A%2F%2Fwww.jstor.org%2Flazy.png"`,
		`src="/p?url=https%3A%2F%2Fwww.jstor.org%2Fmovie.mp4"`,
		`src="/p?url=https%3A%2F%2Fwww.jstor.org%2Fframe.html"`,
		`poster="/p?url=https%3A%2F%2Fwww.jstor.org%2Fposter.jpg"`,
		`action="/p?url=https%3A%2F%2Fwww.jstor.org%2Fsearch"`,
		`data-href="/p?url=https%3A%2F%2Fwww.jstor.org%2Fdata-link"`,
		`href="/p?url=https%3A%2F%2Fwww.jstor.org%2Farticle"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected rewritten HTML to contain %s, got %s", want, body)
		}
	}
	if headers.Get("Content-Length") != "" {
		t.Fatalf("transformed HTML copied stale Content-Length: %q", headers.Get("Content-Length"))
	}
}

func TestFetchHandlerRewritesSrcset(t *testing.T) {
	html := `<img srcset="/small.jpg 1x, /large.jpg 2x">`
	body, _ := fetchBody(t, "text/html", html, allowedHostTargetCheck)

	for _, want := range []string{
		`/p?url=https%3A%2F%2Fwww.jstor.org%2Fsmall.jpg 1x`,
		`/p?url=https%3A%2F%2Fwww.jstor.org%2Flarge.jpg 2x`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected rewritten srcset to contain %s, got %s", want, body)
		}
	}
}

func TestFetchHandlerRewritesInlineStyleURLs(t *testing.T) {
	html := `<div style="background: url('/asset.png')"></div>`
	body, _ := fetchBody(t, "text/html", html, allowedHostTargetCheck)

	if !strings.Contains(body, `url('/p?url=https%3A%2F%2Fwww.jstor.org%2Fasset.png')`) {
		t.Fatalf("expected inline style URL rewrite, got %s", body)
	}
}

func TestFetchHandlerRewritesCSSURLs(t *testing.T) {
	css := `body{background:url(/asset.css)} @font-face{src:url("../font.woff2")} .data{background:url(data:image/png;base64,aaa)}`
	body, headers := fetchBody(t, "text/css", css, allowedHostTargetCheck)

	for _, want := range []string{
		`url(/p?url=https%3A%2F%2Fwww.jstor.org%2Fasset.css)`,
		`url("/p?url=https%3A%2F%2Fwww.jstor.org%2Ffont.woff2")`,
		`url(data:image/png;base64,aaa)`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected rewritten CSS to contain %s, got %s", want, body)
		}
	}
	if headers.Get("Content-Length") != "" {
		t.Fatalf("transformed CSS copied stale Content-Length: %q", headers.Get("Content-Length"))
	}
}

func TestFetchHandlerLeavesNonAllowlistedAssetURLUnchanged(t *testing.T) {
	html := `<img src="https://cdn.example.org/image.png"><img src="https://tracking.jstor.org/pixel.gif"><img src="/allowed.png">`
	body, _ := fetchBody(t, "text/html", html, allowedHostTargetCheck)

	if !strings.Contains(body, `src="https://cdn.example.org/image.png"`) {
		t.Fatalf("expected non-allowlisted URL unchanged, got %s", body)
	}
	if !strings.Contains(body, `src="https://tracking.jstor.org/pixel.gif"`) {
		t.Fatalf("expected blocked URL unchanged, got %s", body)
	}
	if !strings.Contains(body, `src="/p?url=https%3A%2F%2Fwww.jstor.org%2Fallowed.png"`) {
		t.Fatalf("expected allowlisted relative URL rewritten, got %s", body)
	}
}

func allowedTargetCheck(ctx context.Context, rawURL string) (*url.URL, resources.TestResult) {
	target, _ := url.Parse(rawURL)
	return target, resources.TestResult{
		Allowed:    true,
		ResourceID: "jstor",
		RuleHost:   "www.jstor.org",
		RuleMatch:  "exact",
		Role:       "content",
		Action:     "proxy",
		Matched:    &resources.DomainRule{Host: "www.jstor.org", Match: "exact"},
		Reason:     "matched active resource domain rule",
	}
}

func allowedHostTargetCheck(ctx context.Context, rawURL string) (*url.URL, resources.TestResult) {
	target, _ := url.Parse(rawURL)
	if target != nil && target.Hostname() == "tracking.jstor.org" {
		return nil, resources.TestResult{
			Allowed:    false,
			Blocked:    true,
			ResourceID: "jstor",
			RuleHost:   "tracking.jstor.org",
			RuleMatch:  "exact",
			Role:       "blocked",
			Action:     "block",
			Reason:     "explicitly_blocked",
		}
	}
	if target == nil || target.Hostname() != "www.jstor.org" {
		return nil, resources.TestResult{Allowed: false, Reason: "no active resource domain rule matched"}
	}
	return target, resources.TestResult{
		Allowed:    true,
		ResourceID: "jstor",
		RuleHost:   "www.jstor.org",
		RuleMatch:  "exact",
		Role:       "content",
		Action:     "proxy",
		Matched:    &resources.DomainRule{Host: "www.jstor.org", Match: "exact"},
		Reason:     "matched active resource domain rule",
	}
}

func fetchBody(t *testing.T, contentType, body string, check TargetCheck) (string, http.Header) {
	t.Helper()

	client := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type":   []string{contentType},
				"Content-Length": []string{"9999"},
			},
			Body:          io.NopCloser(strings.NewReader(body)),
			ContentLength: int64(len(body)),
			Request:       req,
		}, nil
	}).client()
	handler := FetchHandler(client, check)

	req := httptest.NewRequest(http.MethodGet, "/p?url=https://www.jstor.org/path/page.html", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d with body %s", rec.Code, rec.Body.String())
	}
	return rec.Body.String(), rec.Header()
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
