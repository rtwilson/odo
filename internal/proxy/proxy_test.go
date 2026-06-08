package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"example.org/odo/internal/resources"
)

func TestStubHandlerAllowsMatchedURL(t *testing.T) {
	handler := StubHandler(func(rawURL string) resources.TestResult {
		if rawURL != "https://www.jstor.org/stable/example" {
			t.Fatalf("handler passed unexpected URL to matcher: %q", rawURL)
		}
		return resources.TestResult{
			Allowed:    true,
			ResourceID: "jstor",
			Matched:    &resources.DomainRule{Host: "www.jstor.org", Match: "exact"},
			Reason:     "matched active resource domain rule",
		}
	})

	req := httptest.NewRequest(http.MethodGet, "/p?url="+url.QueryEscape("https://www.jstor.org/stable/example"), nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d with body %s", rec.Code, rec.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response JSON: %v", err)
	}
	if body["allowed"] != true {
		t.Fatalf("expected allowed true, got %#v", body)
	}
	if body["resource_id"] != "jstor" {
		t.Fatalf("expected jstor resource id, got %#v", body)
	}
	message, ok := body["message"].(string)
	if !ok || message == "" {
		t.Fatalf("expected future-work message, got %#v", body)
	}
}

func TestStubHandlerDeniesUnmatchedURL(t *testing.T) {
	handler := StubHandler(func(rawURL string) resources.TestResult {
		if rawURL != "https://example.org/" {
			t.Fatalf("handler passed unexpected URL to matcher: %q", rawURL)
		}
		return resources.TestResult{
			Allowed: false,
			Reason:  "no active resource domain rule matched",
		}
	})

	req := httptest.NewRequest(http.MethodGet, "/p?url="+url.QueryEscape("https://example.org/"), nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d with body %s", rec.Code, rec.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response JSON: %v", err)
	}
	if body["allowed"] != false {
		t.Fatalf("expected allowed false, got %#v", body)
	}
	reason, ok := body["reason"].(string)
	if !ok || reason == "" {
		t.Fatalf("expected denial reason, got %#v", body)
	}
	if _, exists := body["resource_id"]; exists {
		t.Fatalf("did not expect resource_id on denial, got %#v", body)
	}
}
