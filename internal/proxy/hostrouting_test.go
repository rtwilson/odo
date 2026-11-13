package proxy

import (
	"strings"
	"testing"
)

func TestHostRoutingConfigNormalizesTrustedNames(t *testing.T) {
	config, err := NewHostRoutingConfig(" https://ODO.EXAMPLE.:443/ ", " PROXY.EXAMPLE. ")
	if err != nil || config.CentralHostname() != "odo.example" || config.ProxyBaseDomain() != "proxy.example" {
		t.Fatalf("configuration: %+v err=%v", config, err)
	}
	config, err = NewHostRoutingConfig("https://bücher.example", "proxy.example")
	if err != nil || config.CentralHostname() != "xn--bcher-kva.example" {
		t.Fatalf("IDNA configuration: %+v err=%v", config, err)
	}
}

func TestHostRoutingConfigRejectsInvalidDeploymentNames(t *testing.T) {
	for _, tc := range []struct{ public, base string }{
		{"", "proxy.example"}, {"https://odo.example", ""},
		{"http://odo.example", "proxy.example"}, {"https://u:p@odo.example", "proxy.example"},
		{"https://odo.example/admin", "proxy.example"}, {"https://odo.example/%2F", "proxy.example"},
		{"https://odo.example?", "proxy.example"}, {"https://odo.example?q=x", "proxy.example"},
		{"https://odo.example#", "proxy.example"}, {"https://odo.example#fragment", "proxy.example"},
		{"https://odo.example:8443", "proxy.example"}, {"https://127.0.0.1", "proxy.example"},
		{"https://localhost", "proxy.example"}, {"https://odo.example", "*.proxy.example"},
		{"https://odo.example", strings.Repeat(strings.Repeat("a", 60)+".", 3) + strings.Repeat("b", 30)},
	} {
		if _, err := NewHostRoutingConfig(tc.public, tc.base); err == nil {
			t.Fatalf("accepted public=%q base=%q", tc.public, tc.base)
		}
	}
}

func TestClassifyAuthoritySeparatesCentralAndCandidateHosts(t *testing.T) {
	config, err := NewHostRoutingConfig("https://admin.proxy.example", "proxy.example")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		authority string
		central   bool
		label     string
	}{
		{"admin.proxy.example", true, ""}, {"ADMIN.PROXY.EXAMPLE.:443", true, ""},
		{"h-abc.proxy.example", false, "h-abc"}, {"JSTOR.PROXY.EXAMPLE:443", false, "jstor"},
	} {
		central, label, err := config.ClassifyAuthority(tc.authority)
		if err != nil || central != tc.central || label != tc.label {
			t.Fatalf("%q: central=%v label=%q err=%v", tc.authority, central, label, err)
		}
	}
	for _, authority := range []string{
		"", "proxy.example", "unknown.example", "proxy.example.evil", "h-abc.proxy.example.evil",
		"a.b.proxy.example", "admin.proxy.example:80", "admin.proxy.example:",
		"admin.proxy.example..", "https://admin.proxy.example", "u@admin.proxy.example",
		"admin.proxy.example/path", "admin.proxy.example?x=1", "admin.proxy.example#x",
		"admin.proxy.example,evil.example", " admin.proxy.example", "admin.proxy.example ",
		"admin.proxy.example\t", "admin.proxy.example\r\n", "bücher.proxy.example",
		"admin%2eproxy.example", "*.proxy.example", "127.0.0.1", "[::1]",
	} {
		if central, label, err := config.ClassifyAuthority(authority); err == nil || central || label != "" {
			t.Fatalf("accepted %q: central=%v label=%q err=%v", authority, central, label, err)
		}
	}
	if _, _, err := (HostRoutingConfig{}).ClassifyAuthority("admin.proxy.example"); err == nil {
		t.Fatal("unconfigured classifier admitted an authority")
	}
}
