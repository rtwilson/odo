package proxy

import (
	"context"
	"net"
	"strings"
	"testing"
)

func TestNormalizeAndValidateTargetURLRejectsUnsafeSyntax(t *testing.T) {
	tests := []string{
		"http://example.com",
		"file:///etc/passwd",
		"gopher://example.com/",
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

func TestNormalizeAndValidateTargetURLAllowsLocalHTTPOnlyInDevelopment(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("APP_PROXY_ALLOW_LOCAL_HTTP", "true")
	parsed, err := NormalizeAndValidateTargetURL("http://127.0.0.1:9090/article/123")
	if err != nil {
		t.Fatalf("expected development local HTTP target to be valid: %v", err)
	}
	if parsed.String() != "http://127.0.0.1:9090/article/123" {
		t.Fatalf("expected target to be preserved, got %q", parsed.String())
	}
}

func TestNormalizeAndValidateTargetURLRejectsLocalHTTPWithoutDevelopmentAllowance(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("APP_PROXY_ALLOW_LOCAL_HTTP", "true")
	if _, err := NormalizeAndValidateTargetURL("http://127.0.0.1:9090/"); err == nil {
		t.Fatal("expected local HTTP target to be rejected outside development")
	}
}

func TestValidateTargetURLRejectsPrivateResolvedIPs(t *testing.T) {
	tests := []string{
		"0.0.0.1",
		"127.0.0.1",
		"10.0.0.1",
		"172.16.0.1",
		"172.31.255.255",
		"192.168.1.5",
		"169.254.1.1",
		"::1",
		"fe80::1",
		"fc00::1",
		"224.0.0.1",
		"192.0.2.1",
		"2001:db8::1",
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

func TestSafeDialContextUsesValidatedNumericAddress(t *testing.T) {
	lookup := func(ctx context.Context, host string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
	}
	var dialed string
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed = address
		return nil, nil
	}
	_, err := safeDialContext(lookup, dial)(context.Background(), "tcp", "vendor.example:443")
	if err != nil {
		t.Fatalf("expected validated public address to be dialed: %v", err)
	}
	if dialed != "93.184.216.34:443" {
		t.Fatalf("expected numeric validated address, got %q", dialed)
	}
}

func TestSafeDialContextBlocksDNSRebindingBeforeDial(t *testing.T) {
	lookups := 0
	lookup := func(ctx context.Context, host string) ([]net.IPAddr, error) {
		lookups++
		if lookups == 1 {
			return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
		}
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}
	if _, err := ValidateTargetURL(context.Background(), "https://vendor.example/", lookup); err != nil {
		t.Fatalf("initial validation should see a public address: %v", err)
	}
	dialCalled := false
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		dialCalled = true
		return nil, nil
	}
	_, err := safeDialContext(lookup, dial)(context.Background(), "tcp", "vendor.example:443")
	if err == nil || SafetyReason(err) != SafetyReasonLoopbackIP {
		t.Fatalf("expected loopback rebinding to be blocked, got %v", err)
	}
	if dialCalled {
		t.Fatal("unsafe rebound address must not be dialed")
	}
}

func TestSafeDialContextPreservesIPv6AddressFormatting(t *testing.T) {
	lookup := func(ctx context.Context, host string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("2606:4700:4700::1111")}}, nil
	}
	var dialed string
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed = address
		return nil, nil
	}
	_, err := safeDialContext(lookup, dial)(context.Background(), "tcp", "vendor.example:443")
	if err != nil {
		t.Fatalf("expected public IPv6 address to pass: %v", err)
	}
	if !strings.HasPrefix(dialed, "[") || !strings.HasSuffix(dialed, "]:443") {
		t.Fatalf("expected bracketed IPv6 dial address, got %q", dialed)
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
