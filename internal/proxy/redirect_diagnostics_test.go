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

func TestBlockedRedirectDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name, category string
		denied         resources.TestResult
	}{
		{"unlisted", "no_matching_domain_rule", resources.TestResult{Reason: "no active resource domain rule matched"}},
		{"unclassified validation failure", "target_not_allowed", resources.TestResult{Reason: "private-validation-reason"}},
		{"blocked", "explicitly_blocked", resources.TestResult{Blocked: true, Action: "block", Reason: "private-rule-reason"}},
		{"nonproxyable", "not_proxyable", resources.TestResult{Reason: "not_proxyable"}},
		{"unsafe", "target_safety_check_failed", resources.TestResult{SafetyReason: SafetyReasonPrivateIP}},
		{"other", "target_not_allowed", resources.TestResult{Matched: &resources.DomainRule{Host: "files.example"}, Reason: "private-rule-reason"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := NewDiagnosticsStore(10)
			handler := FetchHandlerWithOptions(FetchOptions{
				Diagnostics: store,
				Check: func(ctx context.Context, raw string) (*url.URL, resources.TestResult) {
					parsed, _ := url.Parse(raw)
					if parsed.Hostname() == "files.example" {
						return nil, tc.denied
					}
					return allowedTargetCheck(ctx, raw)
				},
				Client: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: 307, Header: http.Header{"Location": {"https://files.example/private-title.pdf?signature=private-token"}}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
				}).client(),
			})
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest("GET", "/odo/https/www.jstor.org/preview", nil))
			if rec.Code != 502 || rec.Header().Get("Location") != "" {
				t.Fatalf("blocked redirect escaped: %d", rec.Code)
			}
			entries := store.Recent()
			if len(entries) != 1 {
				t.Fatalf("events: %#v", entries)
			}
			event := entries[0]
			if event.RedirectTargetHost != "files.example" || event.RedirectBlockReason != tc.category || event.Reason != "redirect_to_blocked_target" {
				t.Fatalf("wrong redirect diagnostic: %#v", event)
			}
			payload, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(payload), "private-") || strings.Contains(string(payload), "signature") {
				t.Fatalf("redirect details leaked: %s", payload)
			}
		})
	}
}
