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

func TestEmbeddedURLRewriting(t *testing.T) {
	t.Setenv("APP_PROXY_URL_MODE", ProxyURLModePath)
	base, _ := url.Parse("https://www.jstor.org/viewer/index.html")
	check := func(ctx context.Context, raw string) (*url.URL, resources.TestResult) {
		target, result := allowedTargetCheck(ctx, raw)
		result.Allowed = target.Hostname() == base.Hostname()
		return target, result
	}
	for _, element := range []struct{ tag, attr string }{{"iframe", "src"}, {"frame", "src"}, {"object", "data"}, {"embed", "src"}} {
		for _, source := range []struct{ value, want string }{
			{"/private-article.pdf", "/odo/https/www.jstor.org/private-article.pdf"},
			{"private-article.pdf", "/odo/https/www.jstor.org/viewer/private-article.pdf"},
			{"https://outside.example/viewer", "https://outside.example/viewer"},
			{"data:application/pdf;base64,AA==", "data:application/pdf;base64,AA=="},
		} {
			t.Run(element.tag+source.value, func(t *testing.T) {
				input := "<" + element.tag + " " + element.attr + `="` + source.value + `"></` + element.tag + ">"
				got := RewriteHTML(context.Background(), input, base, check)
				if !strings.Contains(got, element.attr+`="`+source.want+`"`) {
					t.Fatalf("unexpected embedded URL: %s", got)
				}
			})
		}
	}
	input := `<div data="/private-article.pdf"></div>`
	if got := RewriteHTML(context.Background(), input, base, check); got != input {
		t.Fatalf("non-object data changed: %s", got)
	}
}

func TestFrameContentDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		destination, csp string
		xfo, ancestors   bool
	}{
		{"iframe", "frame-ancestors 'none'; report-uri /private-report", true, true},
		{"frame", "default-src 'self'; FRAME-ANCESTORS 'none'", false, true},
		{"object", "default-src 'self'", true, false},
		{"embed", "", false, false},
		{"", "default-src 'none', frame-ancestors 'self'", true, true},
	} {
		t.Run(tc.destination+tc.csp, func(t *testing.T) {
			store := NewDiagnosticsStore(10)
			handler := FetchHandlerWithOptions(FetchOptions{Check: allowedTargetCheck, Diagnostics: store, Client: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				headers := http.Header{"Content-Type": {"application/pdf; title=private-title"}}
				if tc.xfo {
					headers.Set("X-Frame-Options", "DENY private-value")
				}
				if tc.csp != "" {
					headers.Set("Content-Security-Policy", tc.csp)
				}
				return &http.Response{StatusCode: 200, Header: headers, Body: io.NopCloser(strings.NewReader("%PDF-private-body")), Request: req}, nil
			}).client()})
			req := httptest.NewRequest("GET", "/odo/https/www.jstor.org/private-title.pdf?private-query", nil)
			req.Header.Set("Sec-Fetch-Dest", tc.destination)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Header().Get("X-Frame-Options") != "" || rec.Header().Get("Content-Security-Policy") != "" {
				t.Fatal("frame-blocking headers forwarded")
			}
			count := 0
			for _, event := range store.Recent() {
				if event.Type != "proxy_frame_content" {
					continue
				}
				count++
				if event.TargetHost != "www.jstor.org" || event.UpstreamStatus != 200 || event.ContentType != "application/pdf" || event.FrameDestination != tc.destination || event.UpstreamXFrameOptionsPresent != tc.xfo || event.XFrameOptionsRemoved != tc.xfo || event.UpstreamFrameAncestorsPresent != tc.ancestors || event.FrameAncestorsRemoved != tc.ancestors {
					t.Errorf("wrong frame diagnostic: %#v", event)
				}
				if (event.Action != "") != (tc.xfo || tc.ancestors) {
					t.Errorf("wrong suppression action: %#v", event)
				}
				payload, err := json.Marshal(event)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(payload), "private-") {
					t.Fatalf("private value leaked: %s", payload)
				}
			}
			if count != 1 {
				t.Errorf("frame event count = %d", count)
			}
		})
	}
}

func TestFrameAncestorsDetection(t *testing.T) {
	for _, tc := range []struct {
		policy string
		want   bool
	}{
		{"frame-ancestors 'none'", true},
		{"script-src https://example.org/frame-ancestors", false},
		{"report-uri /frame-ancestors", false},
		{"frame-ancestors-extra 'none'", false},
		{"default-src 'none', FRAME-ANCESTORS 'self'", true},
	} {
		for _, name := range []string{"Content-Security-Policy", "Content-Security-Policy-Report-Only"} {
			headers := http.Header{}
			headers.Add(name, "default-src 'none'")
			headers.Add(name, tc.policy)
			if got := hasFrameAncestors(headers); got != tc.want {
				t.Errorf("%s %q: got %t", name, tc.policy, got)
			}
		}
	}
}
