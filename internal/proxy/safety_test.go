package proxy

import (
	"context"
	"net"
	"testing"
)

func TestNormalizeAndValidateTargetURLRejectsUnsafeSyntax(t *testing.T) {
	tests := []string{
		"http://example.com",
		"https://user:pass@example.com",
		"https://127.0.0.1/",
		"https://localhost/",
		"https://foo.local/",
		"https://foo.internal/",
		"https://example.com:8443/",
		"https://[",
	}

	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			if _, err := NormalizeAndValidateTargetURL(raw); err == nil {
				t.Fatal("expected target URL to be rejected")
			}
		})
	}
}

func TestNormalizeAndValidateTargetURLAllowsHTTPSHostname(t *testing.T) {
	parsed, err := NormalizeAndValidateTargetURL("https://WWW.JSTOR.ORG./stable/example")
	if err != nil {
		t.Fatalf("expected target URL to be valid: %v", err)
	}
	if parsed.Hostname() != "www.jstor.org" {
		t.Fatalf("expected normalized hostname, got %q", parsed.Hostname())
	}
}

func TestValidateTargetURLRejectsPrivateResolvedIPs(t *testing.T) {
	tests := []string{
		"127.0.0.1",
		"10.0.0.1",
		"192.168.1.5",
		"::1",
		"fc00::1",
	}

	for _, ip := range tests {
		t.Run(ip, func(t *testing.T) {
			lookup := func(ctx context.Context, host string) ([]net.IPAddr, error) {
				return []net.IPAddr{{IP: net.ParseIP(ip)}}, nil
			}
			if _, err := ValidateTargetURL(context.Background(), "https://www.jstor.org/stable/example", lookup); err == nil {
				t.Fatal("expected resolved private/internal IP to be rejected")
			}
		})
	}
}

func TestValidateTargetURLAllowsPublicResolvedIP(t *testing.T) {
	lookup := func(ctx context.Context, host string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
	}
	parsed, err := ValidateTargetURL(context.Background(), "https://www.jstor.org/stable/example", lookup)
	if err != nil {
		t.Fatalf("expected public resolved IP to be allowed: %v", err)
	}
	if parsed.Hostname() != "www.jstor.org" {
		t.Fatalf("expected normalized hostname, got %q", parsed.Hostname())
	}
}
