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

	req := httptest.NewRequest(http.MethodPost, "/odo?url=https://www.jstor.org/stable/example", nil)
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

	req := httptest.NewRequest(http.MethodGet, "/odo?url="+url.QueryEscape("https://example.org/"), nil)
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

	req := httptest.NewRequest(http.MethodGet, "/odo?url=https://www.jstor.org/stable/example", nil)
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
	if strings.Contains(rec.Header().Get("Set-Cookie"), "session=secret") {
		t.Fatalf("expected upstream Set-Cookie not to be copied, got %q", rec.Header().Get("Set-Cookie"))
	}
}

func TestFetchHandlerCreatesProxySessionCookie(t *testing.T) {
	handler := FetchHandler(roundTripFunc(okResponse).client(), allowedTargetCheck)

	req := httptest.NewRequest(http.MethodGet, "/odo?url=https://www.jstor.org/stable/example", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	cookie := findCookie(rec.Result().Cookies(), ProxySessionCookieName)
	if cookie == nil {
		t.Fatalf("expected %s cookie, got %#v", ProxySessionCookieName, rec.Result().Cookies())
	}
	if !cookie.HttpOnly {
		t.Fatal("expected proxy session cookie to be HttpOnly")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("expected SameSite=Lax, got %#v", cookie.SameSite)
	}
}

func TestFetchHandlerReusesExistingProxySessionCookie(t *testing.T) {
	handler := FetchHandler(roundTripFunc(okResponse).client(), allowedTargetCheck)

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/odo?url=https://www.jstor.org/one", nil))
	cookie := findCookie(first.Result().Cookies(), ProxySessionCookieName)
	if cookie == nil {
		t.Fatal("expected first request to create proxy session cookie")
	}

	secondReq := httptest.NewRequest(http.MethodGet, "/odo?url=https://www.jstor.org/two", nil)
	secondReq.AddCookie(cookie)
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, secondReq)

	if findCookie(second.Result().Cookies(), ProxySessionCookieName) != nil {
		t.Fatalf("expected existing proxy session to be reused without setting a new cookie, got %#v", second.Result().Cookies())
	}
}

func TestFetchHandlerStoresAndSendsUpstreamCookiesPerSession(t *testing.T) {
	var seen []string
	handler := FetchHandler(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		seen = append(seen, req.Header.Get("Cookie"))
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Set-Cookie": []string{"vendor=abc; Path=/"}},
			Body:       io.NopCloser(strings.NewReader("ok")),
			Request:    req,
		}, nil
	}).client(), allowedTargetCheck)

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/odo?url=https://www.jstor.org/one", nil))
	sessionCookie := findCookie(first.Result().Cookies(), ProxySessionCookieName)
	if sessionCookie == nil {
		t.Fatal("expected proxy session cookie")
	}
	if strings.Contains(first.Header().Get("Set-Cookie"), "vendor=abc") {
		t.Fatalf("vendor cookie leaked to browser: %q", first.Header().Get("Set-Cookie"))
	}

	secondReq := httptest.NewRequest(http.MethodGet, "/odo?url=https://www.jstor.org/two", nil)
	secondReq.AddCookie(sessionCookie)
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, secondReq)

	if len(seen) != 2 {
		t.Fatalf("expected two upstream requests, got %d", len(seen))
	}
	if seen[0] != "" {
		t.Fatalf("first upstream request should not have vendor cookie, got %q", seen[0])
	}
	if !strings.Contains(seen[1], "vendor=abc") {
		t.Fatalf("second upstream request should include stored vendor cookie, got %q", seen[1])
	}
}

func TestFetchHandlerDoesNotShareUpstreamCookiesAcrossProxySessions(t *testing.T) {
	var seen []string
	handler := FetchHandler(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		seen = append(seen, req.Header.Get("Cookie"))
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Set-Cookie": []string{"vendor=abc; Path=/"}},
			Body:       io.NopCloser(strings.NewReader("ok")),
			Request:    req,
		}, nil
	}).client(), allowedTargetCheck)

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/odo?url=https://www.jstor.org/one", nil))

	second := httptest.NewRecorder()
	handler.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/odo?url=https://www.jstor.org/two", nil))

	if len(seen) != 2 {
		t.Fatalf("expected two upstream requests, got %d", len(seen))
	}
	if seen[0] != "" || seen[1] != "" {
		t.Fatalf("different proxy sessions should not share vendor cookies, got %#v", seen)
	}
}

func TestFetchHandlerDebugHeadersExposeCountsNotCookieValues(t *testing.T) {
	handler := FetchHandlerWithOptions(FetchOptions{
		Client: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Set-Cookie": []string{"vendor=supersecret; Path=/"}},
				Body:       io.NopCloser(strings.NewReader("ok")),
				Request:    req,
			}, nil
		}).client(),
		Check:        allowedTargetCheck,
		DebugHeaders: true,
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/odo?url=https://www.jstor.org/one", nil))

	if rec.Header().Get("X-Odo-Proxy-Session") != "true" {
		t.Fatalf("expected proxy session debug header, got %#v", rec.Header())
	}
	if rec.Header().Get("X-Odo-Upstream-Cookies-Stored") != "1" {
		t.Fatalf("expected stored cookie count, got %#v", rec.Header())
	}
	for name, values := range rec.Header() {
		for _, value := range values {
			if strings.Contains(value, "supersecret") || strings.Contains(value, "vendor=") {
				t.Fatalf("debug header %s exposed cookie value/name: %q", name, value)
			}
		}
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
		`href="/odo?url=https%3A%2F%2Fwww.jstor.org%2Fstyle.css"`,
		`src="/odo?url=https%3A%2F%2Fwww.jstor.org%2Fapp.js"`,
		`src="/odo?url=https%3A%2F%2Fwww.jstor.org%2Fimage.png"`,
		`data-src="/odo?url=https%3A%2F%2Fwww.jstor.org%2Flazy.png"`,
		`src="/odo?url=https%3A%2F%2Fwww.jstor.org%2Fmovie.mp4"`,
		`src="/odo?url=https%3A%2F%2Fwww.jstor.org%2Fframe.html"`,
		`poster="/odo?url=https%3A%2F%2Fwww.jstor.org%2Fposter.jpg"`,
		`action="/odo?url=https%3A%2F%2Fwww.jstor.org%2Fsearch"`,
		`data-href="/odo?url=https%3A%2F%2Fwww.jstor.org%2Fdata-link"`,
		`href="/odo?url=https%3A%2F%2Fwww.jstor.org%2Farticle"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected rewritten HTML to contain %s, got %s", want, body)
		}
	}
	if headers.Get("Content-Length") != "" {
		t.Fatalf("transformed HTML copied stale Content-Length: %q", headers.Get("Content-Length"))
	}
}

func TestFetchHandlerRewritesRelativeAnchorURL(t *testing.T) {
	html := `<a href="../journal/article">Article</a>`
	body, _ := fetchBody(t, "text/html", html, allowedHostTargetCheck)

	if !strings.Contains(body, `href="/odo?url=https%3A%2F%2Fwww.jstor.org%2Fjournal%2Farticle"`) {
		t.Fatalf("expected relative anchor to resolve and rewrite through /odo, got %s", body)
	}
}

func TestFetchHandlerDoesNotCopyCSPForTransformedHTML(t *testing.T) {
	client := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type":                        []string{"text/html"},
				"Content-Security-Policy":             []string{"default-src 'self'"},
				"Content-Security-Policy-Report-Only": []string{"default-src 'self'"},
			},
			Body:    io.NopCloser(strings.NewReader(`<a href="/next">next</a>`)),
			Request: req,
		}, nil
	}).client()
	handler := FetchHandler(client, allowedHostTargetCheck)

	req := httptest.NewRequest(http.MethodGet, "/odo?url=https://www.jstor.org/path/page.html", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Content-Security-Policy") != "" || rec.Header().Get("Content-Security-Policy-Report-Only") != "" {
		t.Fatalf("transformed HTML copied CSP headers: %#v", rec.Header())
	}
}

func TestFetchHandlerRemovesIntegrityWhenURLIsRewritten(t *testing.T) {
	html := `<script src="/app.js" integrity="sha384-secret" crossorigin="anonymous"></script>`
	body, _ := fetchBody(t, "text/html", html, allowedHostTargetCheck)

	if strings.Contains(strings.ToLower(body), "integrity=") {
		t.Fatalf("expected integrity attribute removed after rewrite, got %s", body)
	}
	if !strings.Contains(body, `src="/odo?url=https%3A%2F%2Fwww.jstor.org%2Fapp.js"`) {
		t.Fatalf("expected script URL rewritten, got %s", body)
	}
}

func TestFetchHandlerRewritesSrcset(t *testing.T) {
	html := `<img srcset="/small.jpg 1x, /large.jpg 2x">`
	body, _ := fetchBody(t, "text/html", html, allowedHostTargetCheck)

	for _, want := range []string{
		`/odo?url=https%3A%2F%2Fwww.jstor.org%2Fsmall.jpg 1x`,
		`/odo?url=https%3A%2F%2Fwww.jstor.org%2Flarge.jpg 2x`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected rewritten srcset to contain %s, got %s", want, body)
		}
	}
}

func TestFetchHandlerRewritesInlineStyleURLs(t *testing.T) {
	html := `<div style="background: url('/asset.png')"></div>`
	body, _ := fetchBody(t, "text/html", html, allowedHostTargetCheck)

	if !strings.Contains(body, `url('/odo?url=https%3A%2F%2Fwww.jstor.org%2Fasset.png')`) {
		t.Fatalf("expected inline style URL rewrite, got %s", body)
	}
}

func TestFetchHandlerRewritesCSSURLs(t *testing.T) {
	css := `body{background:url(/asset.css)} @font-face{src:url("../font.woff2")} .data{background:url(data:image/png;base64,aaa)}`
	body, headers := fetchBody(t, "text/css", css, allowedHostTargetCheck)

	for _, want := range []string{
		`url(/odo?url=https%3A%2F%2Fwww.jstor.org%2Fasset.css)`,
		`url("/odo?url=https%3A%2F%2Fwww.jstor.org%2Ffont.woff2")`,
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

func TestFetchHandlerLeavesNonProxyableAssetURLUnchanged(t *testing.T) {
	html := `<img src="https://cdn.example.org/image.png"><img src="https://tracking.jstor.org/pixel.gif"><a href="https://external.example.org/page">external</a><img src="/allowed.png">`
	body, _ := fetchBody(t, "text/html", html, allowedHostTargetCheck)

	if !strings.Contains(body, `src="https://cdn.example.org/image.png"`) {
		t.Fatalf("expected non-allowlisted URL unchanged, got %s", body)
	}
	if !strings.Contains(body, `src="https://tracking.jstor.org/pixel.gif"`) {
		t.Fatalf("expected blocked URL unchanged, got %s", body)
	}
	if !strings.Contains(body, `href="https://external.example.org/page"`) {
		t.Fatalf("expected external/allow URL unchanged, got %s", body)
	}
	if !strings.Contains(body, `src="/odo?url=https%3A%2F%2Fwww.jstor.org%2Fallowed.png"`) {
		t.Fatalf("expected allowlisted relative URL rewritten, got %s", body)
	}
}

func TestFetchHandlerRecordsRewriteDiagnostics(t *testing.T) {
	html := `<a href="/article">article</a>` +
		`<form action="/search"></form>` +
		`<img src="/image.png" integrity="sha384-secret">` +
		`<img src="https://tracking.jstor.org/pixel.gif">` +
		`<a href="https://external.example.org/page">external</a>`
	store := NewDiagnosticsStore(10)
	_, _ = fetchBodyWithDiagnostics(t, "text/html", html, allowedHostTargetCheck, store)
	entries := store.Recent()
	if len(entries) != 1 {
		t.Fatalf("expected one diagnostics entry, got %#v", entries)
	}
	entry := entries[0]
	if entry.RewrittenNavigationCount == 0 || entry.RewrittenFormCount == 0 || entry.RewrittenAssetCount == 0 {
		t.Fatalf("expected rewritten navigation/form/asset counts, got %#v", entry)
	}
	if entry.BlockedURLCount == 0 || entry.NonProxyableAllowedCount == 0 || entry.RemovedIntegrityCount == 0 {
		t.Fatalf("expected blocked/non-proxyable/integrity counts, got %#v", entry)
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
	if target != nil && target.Hostname() == "external.example.org" {
		return target, resources.TestResult{
			Allowed:    true,
			ResourceID: "external",
			RuleHost:   "external.example.org",
			RuleMatch:  "exact",
			Role:       "external",
			Action:     "allow",
			Matched:    &resources.DomainRule{Host: "external.example.org", Match: "exact", Role: "external", Action: "allow"},
			Reason:     "matched",
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
	return fetchBodyWithDiagnostics(t, contentType, body, check, nil)
}

func fetchBodyWithDiagnostics(t *testing.T, contentType, body string, check TargetCheck, diagnostics *DiagnosticsStore) (string, http.Header) {
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
	handler := FetchHandlerWithOptions(FetchOptions{Client: client, Check: check, Diagnostics: diagnostics})

	req := httptest.NewRequest(http.MethodGet, "/odo?url=https://www.jstor.org/path/page.html", nil)
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

func okResponse(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("ok")),
		Request:    req,
	}, nil
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func (f roundTripFunc) client() *http.Client {
	return &http.Client{
		Transport: f,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
