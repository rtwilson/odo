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

func TestJavaScriptCompatibility(t *testing.T) {
	t.Setenv("APP_PROXY_URL_MODE", ProxyURLModePath)
	for _, tc := range []struct {
		name, contentType, path, encoding string
		enabled, rewrite, corrected       bool
	}{
		{"standard", "application/javascript", "/private-script.js", "", true, true, false},
		{"text", "text/javascript; charset=utf-8", "/private-script.js", "", true, true, false},
		{"legacy", "application/x-javascript", "/private-script.js", "", true, true, false},
		{"disabled", "application/x-javascript", "/private-script.js", "", false, false, false},
		{"missing MIME", "", "/private-script.mjs", "", true, true, true},
		{"octet enabled", "application/octet-stream", "/private-script.js", "", true, true, true},
		{"octet disabled", "application/octet-stream", "/private-script.js", "", false, false, false},
		{"other binary", "application/octet-stream", "/private-data.bin", "", true, false, false},
		{"explicit binary MIME", "image/png", "/private-script.js", "", true, false, false},
		{"MIME substring", "application/javascript-binary", "/private-script.js", "", true, false, false},
		{"encoded", "application/javascript", "/private-script.js", "gzip", true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const body = `const u = "https://vendor.example/private-url";`
			store := NewDiagnosticsStore(10)
			handler := FetchHandlerWithOptions(FetchOptions{
				Diagnostics: store,
				Check: func(ctx context.Context, raw string) (*url.URL, resources.TestResult) {
					target, result := allowedTargetCheck(ctx, raw)
					result.JavaScriptTextRewriteEnabled = tc.enabled
					result.AnonymousRulePattern = "private-pattern"
					result.ContentRewriteRules = []resources.ContentRewriteRule{{
						ContentTypes: []string{"application/javascript", "text/javascript", "application/x-javascript"},
						Find:         "https://vendor.example/", Replace: "{proxy_url:https://vendor.example/}",
					}}
					return target, result
				},
				Client: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					headers := http.Header{"Content-Length": {"999"}, "Content-Security-Policy": {"private-policy"}}
					if tc.contentType != "" {
						headers.Set("Content-Type", tc.contentType)
					}
					if tc.encoding != "" {
						headers.Set("Content-Encoding", tc.encoding)
					}
					return &http.Response{StatusCode: 200, Header: headers, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
				}).client(),
			})
			req := httptest.NewRequest("GET", "/odo/https/www.jstor.org"+tc.path+"?private-query", nil)
			req.Header.Set("Sec-Fetch-Dest", "script")
			req.Header.Set("Authorization", "private-auth")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != 200 {
				t.Fatalf("status = %d", rec.Code)
			}
			if strings.Contains(rec.Body.String(), "/odo/https/vendor.example/") != tc.rewrite {
				t.Fatalf("unexpected body: %s", rec.Body.String())
			}
			if !tc.rewrite && rec.Body.String() != body {
				t.Fatal("non-rewritten bytes changed")
			}
			wantMIME := tc.contentType
			if tc.corrected {
				wantMIME = "application/javascript; charset=utf-8"
			}
			if rec.Header().Get("Content-Type") != wantMIME {
				t.Errorf("MIME = %q, want %q", rec.Header().Get("Content-Type"), wantMIME)
			}
			events := 0
			for _, event := range store.Recent() {
				if event.Type != "proxy_script_asset" {
					continue
				}
				events++
				if event.TargetHost != "www.jstor.org" || event.UpstreamStatus != 200 || event.ContentTypeCorrected != tc.corrected || event.ContentTypeMissing != (tc.contentType == "") || event.ContentEncodingPresent != (tc.encoding != "") || !event.CSPRemoved || !event.UpstreamCSPPresent || event.ReferringIntegrity != "unknown" {
					t.Errorf("unexpected script event: %#v", event)
				}
				if event.ContentLengthStripped != (isTransformable(wantMIME) && tc.encoding == "") {
					t.Errorf("wrong length stripping diagnostic: %#v", event)
				}
				encoded, err := json.Marshal(event)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(encoded), "private-") {
					t.Fatalf("private value leaked: %s", encoded)
				}
			}
			if events != 1 {
				t.Errorf("script events = %d", events)
			}
		})
	}
}

func TestScriptSourceRewriting(t *testing.T) {
	t.Setenv("APP_PROXY_URL_MODE", ProxyURLModePath)
	base, _ := url.Parse("https://www.jstor.org/viewer/index.html")
	for _, tc := range []struct{ source, want string }{
		{"/assets/jquery.js", "/odo/https/www.jstor.org/assets/jquery.js"},
		{"assets/jquery.js", "/odo/https/www.jstor.org/viewer/assets/jquery.js"},
		{"../jquery.js", "/odo/https/www.jstor.org/jquery.js"},
	} {
		t.Run(tc.source, func(t *testing.T) {
			ctx, diagnostic := WithDiagnostics(context.Background())
			got := RewriteHTML(ctx, `<script src="`+tc.source+`" integrity="private-hash"></script>`, base, allowedHostTargetCheck)
			if !strings.Contains(got, `src="`+tc.want+`"`) || strings.Contains(got, "integrity=") || diagnostic.RemovedIntegrityCount != 1 {
				t.Fatalf("script rewriting: %s; diagnostic: %#v", got, diagnostic)
			}
		})
	}
}
