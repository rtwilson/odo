package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"example.org/odo/internal/resources"
)

func TestResponsePolicyDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name, method, contentType, path string
		status                          int
		csp, reportOnly, challenge      bool
	}{
		{"html", "GET", "text/html; charset=utf-8", "/page", 200, true, true, false},
		{"json", "GET", "application/json", "/data", 200, true, false, false},
		{"head", "HEAD", "text/html", "/page", 200, true, false, false},
		{"challenge", "GET", "application/javascript", "/_fs-ch-private-path/script.js", 200, true, true, true},
		{"challenge without CSP", "GET", "font/woff2", "/_fs-ch-private-path/font.woff2", 200, false, false, true},
		{"cloudflare prefix", "GET", "text/javascript", "/cdn-cgi/challenge-platform/private-path", 200, false, true, true},
		{"ordinary asset", "GET", "text/css", "/style.css", 200, false, false, false},
		{"redirect", "GET", "text/html", "/redirect", 302, true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := NewDiagnosticsStore(20)
			client := roundTripFunc(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{"Content-Type": {tc.contentType}, "Cache-Control": {"max-age=60"}, "Location": {"https://www.jstor.org/next"}}
				if tc.csp {
					headers.Set("Content-Security-Policy", "script-src 'sha256-private-policy'; report-uri https://private-report.example/secret")
				}
				if tc.reportOnly {
					headers.Set("Content-Security-Policy-Report-Only", "default-src 'none'; report-uri /private-report")
				}
				headers.Set("Set-Cookie", "private-cookie=value")
				return &http.Response{StatusCode: tc.status, Header: headers, Body: io.NopCloser(strings.NewReader("private-body")), Request: req}, nil
			}).client()
			handler := FetchHandlerWithOptions(FetchOptions{Client: client, Diagnostics: store, Check: func(ctx context.Context, raw string) (*url.URL, resources.TestResult) {
				target, result := allowedHostTargetCheck(ctx, raw)
				result.ResourceID = "jstor"
				result.AnonymousRulePattern = "private-pattern"
				return target, result
			}})
			req := httptest.NewRequest(tc.method, "/odo?url="+url.QueryEscape("https://www.jstor.org"+tc.path+"?token=private-query"), nil)
			req.Header.Set("Authorization", "Bearer private-auth")
			req.Header.Set("Cookie", "private-cookie=value")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
			}
			for _, name := range []string{"Content-Security-Policy", "Content-Security-Policy-Report-Only"} {
				if rec.Header().Get(name) != "" {
					t.Fatalf("forwarded %s", name)
				}
			}
			entries := store.Recent()
			wantEvents := 0
			if tc.csp {
				wantEvents++
			}
			if tc.reportOnly {
				wantEvents++
			}
			if len(entries) != 1+wantEvents {
				t.Fatalf("unexpected diagnostics: %#v", entries)
			}
			aggregate := entries[0]
			if aggregate.UpstreamCSPPresent != tc.csp || aggregate.UpstreamCSPReportOnlyPresent != tc.reportOnly || aggregate.CSPRemoved != (wantEvents > 0) || aggregate.ChallengePathRequested != tc.challenge {
				t.Fatalf("wrong policy summary: %#v", aggregate)
			}
			for _, event := range entries[1:] {
				if event.Type != "response_header_modified" || event.Action != "removed_for_proxy_compatibility" || event.TargetHost != "www.jstor.org" || event.ResourceID != "jstor" || event.ContentType != diagnosticContentType(tc.contentType) {
					t.Fatalf("wrong event: %#v", event)
				}
				if event.Header != "Content-Security-Policy" && event.Header != "Content-Security-Policy-Report-Only" {
					t.Fatalf("unexpected header: %q", event.Header)
				}
				payload, err := json.Marshal(event)
				if err != nil {
					t.Fatal(err)
				}
				for _, forbidden := range []string{"private-", "https://", tc.path, "authorization", "cookie", "anonymous_rule_pattern"} {
					if strings.Contains(string(payload), forbidden) {
						t.Fatalf("event contains %q: %s", forbidden, payload)
					}
				}
			}
			if tc.status == 200 && rec.Header().Get("Cache-Control") != "max-age=60" {
				t.Fatal("unrelated response policy changed")
			}
		})
	}
}

func TestDiagnosticContentTypeDoesNotExposeArbitraryValues(t *testing.T) {
	for input, want := range map[string]string{"text/html; private=secret": "text/html", "TEXT/HTML": "text/html", "application/private-secret": "other", "text/html\r\nprivate-secret": "other", "": "missing"} {
		if got := diagnosticContentType(input); got != want {
			t.Errorf("%q: got %q, want %q", input, got, want)
		}
	}
}
