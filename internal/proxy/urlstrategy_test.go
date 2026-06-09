package proxy

import (
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestBuildProxyURLDefaultsToPathMode(t *testing.T) {
	t.Setenv("APP_PROXY_URL_MODE", "")
	target, _ := url.Parse("https://example.com/path/to/page?q=science")

	got := BuildProxyURL(target)
	want := "/odo/https/example.com/path/to/page?q=science"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestBuildProxyURLUsesQueryMode(t *testing.T) {
	t.Setenv("APP_PROXY_URL_MODE", "query")
	target, _ := url.Parse("https://example.com/path")

	got := BuildProxyURL(target)
	want := "/odo?url=https%3A%2F%2Fexample.com%2Fpath"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestParseProxyRequestPathMode(t *testing.T) {
	req := httptest.NewRequest("GET", "/odo/https/example.com/path/to/page?q=science", nil)

	target, err := ParseProxyRequest(req)
	if err != nil {
		t.Fatalf("parse proxy request: %v", err)
	}
	if target.String() != "https://example.com/path/to/page?q=science" {
		t.Fatalf("unexpected target URL %q", target.String())
	}
}

func TestParseProxyRequestQueryMode(t *testing.T) {
	req := httptest.NewRequest("GET", "/odo?url=https%3A%2F%2Fexample.com%2Fpath", nil)

	target, err := ParseProxyRequest(req)
	if err != nil {
		t.Fatalf("parse proxy request: %v", err)
	}
	if target.String() != "https://example.com/path" {
		t.Fatalf("unexpected target URL %q", target.String())
	}
}
