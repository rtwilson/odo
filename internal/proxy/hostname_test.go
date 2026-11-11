package proxy

import (
	"strings"
	"testing"
)

func TestRegistryHostnameCanonicalIdentity(t *testing.T) {
	var canonical string
	for _, input := range []string{"BÜCHER.example", "xn--bcher-kva.example.", "xn--bcher-kva.example:443"} {
		host, label, err := RegistryHostname(input, "odo.access.example", "proxy.access.example")
		if err != nil || host != "xn--bcher-kva.example" || len(label) != 54 || !strings.HasPrefix(label, "h-") {
			t.Fatalf("%q: host=%q label=%q err=%v", input, host, label, err)
		}
		if canonical != "" && canonical != label {
			t.Fatal("equivalent hosts received different identities")
		}
		canonical = label
	}
	_, other, err := RegistryHostname("other.example", "odo.access.example", "proxy.access.example")
	if err != nil || other == canonical {
		t.Fatalf("distinct host identity: %q, %v", other, err)
	}
}

func TestRegistryHostnameRejectsUnsafeNames(t *testing.T) {
	for _, input := range []string{
		"", ".", "example..com", "example.com..", "-bad.example", "bad-.example",
		"bad_name.example", "*.example", "xn--.example", "127.0.0.1", "[::1]",
		"localhost", "x.localhost", "x.local", "x.internal", "example.com:80",
		"https://example.com", "user@example.com", "example.com/path", "example.com?q=x",
		"example.com#x", "example.com%00", "example.com\\x", "exam\nple.com",
		strings.Repeat("a", 64) + ".example",
		strings.Repeat(strings.Repeat("a", 63)+".", 4) + "example",
		"ODO.ACCESS.EXAMPLE.", "proxy.access.example", "h-test.proxy.access.example",
	} {
		t.Run(input, func(t *testing.T) {
			if _, _, err := RegistryHostname(input, "odo.access.example", "proxy.access.example"); err == nil {
				t.Fatalf("accepted %q", input)
			}
		})
	}
}

func TestRegistryHostnameValidatesDeploymentNames(t *testing.T) {
	for _, tc := range []struct{ central, base string }{
		{"", "proxy.example"}, {"odo.example", ""}, {"https://odo.example", "proxy.example"},
		{"odo.example", strings.Repeat(strings.Repeat("a", 60)+".", 3) + strings.Repeat("b", 30)},
	} {
		if _, _, err := RegistryHostname("vendor.example", tc.central, tc.base); err == nil {
			t.Fatalf("accepted central=%q base=%q", tc.central, tc.base)
		}
	}
}

// Regression: golang.org/x/net/idna with VerifyDNSLength rejects the empty
// root label, so a fully qualified name must have one dot removed first.
func TestNormalizeRegistryHostnameAcceptsOneRootDot(t *testing.T) {
	for _, input := range []string{"Vendor.Example.", "vendor.example.:443", "BÜCHER.example."} {
		host, err := NormalizeRegistryHostname(input)
		if err != nil || strings.HasSuffix(host, ".") || host != strings.ToLower(host) {
			t.Fatalf("%q: host=%q err=%v", input, host, err)
		}
	}
	for _, input := range []string{".", "..", "vendor.example..", "vendor.example..:443", ".vendor.example"} {
		if host, err := NormalizeRegistryHostname(input); err == nil {
			t.Fatalf("accepted %q as %q", input, host)
		}
	}
}
