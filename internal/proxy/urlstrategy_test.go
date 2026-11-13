package proxy

import (
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
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

func TestURLRoutingContextIsIndependentOfEnvironment(t *testing.T) {
	target, err := url.Parse("https://example.com/a%2Fb?q=a%2Bb&next=https%3A%2F%2Fvendor.example%2F")
	if err != nil {
		t.Fatal(err)
	}
	original := *target
	for _, tc := range []struct {
		mode string
		want string
	}{
		{"", "/odo/https/example.com/a%2Fb?q=a%2Bb&next=https%3A%2F%2Fvendor.example%2F"},
		{ProxyURLModePath, "/odo/https/example.com/a%2Fb?q=a%2Bb&next=https%3A%2F%2Fvendor.example%2F"},
		{ProxyURLModeDual, "/odo/https/example.com/a%2Fb?q=a%2Bb&next=https%3A%2F%2Fvendor.example%2F"},
		{ProxyURLModeQuery, "/odo?url=" + url.QueryEscape(target.String())},
		{ProxyURLModeVirtualHost, "/odo/https/example.com/a%2Fb?q=a%2Bb&next=https%3A%2F%2Fvendor.example%2F"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			routing := URLRoutingContext{Mode: tc.mode}
			for _, envMode := range []string{ProxyURLModePath, ProxyURLModeQuery} {
				t.Setenv("APP_PROXY_URL_MODE", envMode)
				if got := routing.BuildProxyURL(target); got != tc.want {
					t.Fatalf("environment %q: got %q, want %q", envMode, got, tc.want)
				}
				parsed, _, ok, err := routing.ParseProxyRequest(httptest.NewRequest("GET", tc.want, nil))
				if err != nil || !ok || parsed.String() != target.String() {
					t.Fatalf("round trip changed target: %v, ok=%v, err=%v", parsed, ok, err)
				}
			}
			if *target != original {
				t.Fatal("URL builder changed the caller's target")
			}
		})
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

func TestBuildProxyURLDoesNotRepeatSameHostPrefix(t *testing.T) {
	for _, mode := range []string{ProxyURLModePath, ProxyURLModeQuery} {
		for _, path := range []string{
			"/odo/https/www.jstor.org/stable/3041316",
			"/odo/https/www.jstor.org/odo/https/www.jstor.org/stable/3041316",
		} {
			t.Run(mode+path, func(t *testing.T) {
				target, _ := url.Parse("https://www.jstor.org" + path + "?seq=1")
				original := target.String()
				clean, _ := url.Parse("https://www.jstor.org/stable/3041316?seq=1")
				if got, want := BuildProxyURLWithMode(target, mode), BuildProxyURLWithMode(clean, mode); got != want {
					t.Fatalf("got %q, want %q", got, want)
				}
				if target.String() != original {
					t.Fatal("URL builder changed the caller's target")
				}
			})
		}
	}
}

func TestBuildProxyURLPrefixBoundariesAndEscaping(t *testing.T) {
	for _, tc := range []struct{ target, clean string }{
		{"https://www.jstor.org/odo/https/www.jstor.org", "https://www.jstor.org/"},
		{"https://www.jstor.org/odo/https/www.jstor.org/a%2Fb?q=a%2Bb", "https://www.jstor.org/a%2Fb?q=a%2Bb"},
		{"https://www.jstor.org/odo/https/other.example/article", "https://www.jstor.org/odo/https/other.example/article"},
		{"https://www.jstor.org/odo/https/www.jstor.org.example/article", "https://www.jstor.org/odo/https/www.jstor.org.example/article"},
	} {
		for _, mode := range []string{ProxyURLModePath, ProxyURLModeQuery} {
			target, _ := url.Parse(tc.target)
			clean, _ := url.Parse(tc.clean)
			if got, want := BuildProxyURLWithMode(target, mode), BuildProxyURLWithMode(clean, mode); got != want {
				t.Errorf("%s %s: got %q, want %q", mode, tc.target, got, want)
			}
		}
	}
}

func TestBuildProxyURLDualModeBuildsPathMode(t *testing.T) {
	t.Setenv("APP_PROXY_URL_MODE", "dual")
	target, _ := url.Parse("https://example.com/path?q=science")

	got := BuildProxyURL(target)
	want := "/odo/https/example.com/path?q=science"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestParseProxyRequestPathMode(t *testing.T) {
	req := httptest.NewRequest("GET", "/odo/https/example.com/path/to/page?q=science", nil)

	target, mode, ok, err := ParseProxyRequest(req)
	if err != nil {
		t.Fatalf("parse proxy request: %v", err)
	}
	if !ok || mode != ProxyURLModePath {
		t.Fatalf("expected path mode ok parse, got mode=%q ok=%v", mode, ok)
	}
	if target.String() != "https://example.com/path/to/page?q=science" {
		t.Fatalf("unexpected target URL %q", target.String())
	}
}

func TestParseProxyRequestQueryMode(t *testing.T) {
	req := httptest.NewRequest("GET", "/odo?url=https%3A%2F%2Fexample.com%2Fpath", nil)

	target, mode, ok, err := ParseProxyRequest(req)
	if err != nil {
		t.Fatalf("parse proxy request: %v", err)
	}
	if !ok || mode != ProxyURLModeQuery {
		t.Fatalf("expected query mode ok parse, got mode=%q ok=%v", mode, ok)
	}
	if target.String() != "https://example.com/path" {
		t.Fatalf("unexpected target URL %q", target.String())
	}
}

func TestProxyURLRoundTripPreservesVendorQuery(t *testing.T) {
	for _, raw := range []string{
		"https://vendor.example/search?url=https%3A%2F%2Fother.example%2F&term=a%2Bb",
		"https://vendor.example/search?url=not-a-url&url=another-value",
		"https://vendor.example/a%2Fb?",
	} {
		for _, mode := range []string{ProxyURLModePath, ProxyURLModeQuery, ProxyURLModeDual} {
			t.Run(mode+raw, func(t *testing.T) {
				target, err := url.Parse(raw)
				if err != nil {
					t.Fatal(err)
				}
				built := BuildProxyURLWithMode(target, mode)
				got, _, ok, err := ParseProxyRequest(httptest.NewRequest("GET", built, nil))
				if err != nil || !ok || got.String() != target.String() {
					t.Fatalf("round trip %q: got %v ok=%v err=%v", built, got, ok, err)
				}
			})
		}
	}
}

func TestQueryProxyEntryPointsRemainCompatible(t *testing.T) {
	for _, path := range []string{PublicProxyPath, PublicProxyPath + "/", "/p"} {
		target, mode, ok, err := ParseProxyRequest(httptest.NewRequest("GET", path+"?url=https%3A%2F%2Fvendor.example%2F", nil))
		if err != nil || !ok || mode != ProxyURLModeQuery || target.String() != "https://vendor.example/" {
			t.Fatalf("query entry %q: got %v mode=%q ok=%v err=%v", path, target, mode, ok, err)
		}
	}
}

func TestParseProxyRequestDualModeAcceptsPathAndQueryForms(t *testing.T) {
	t.Setenv("APP_PROXY_URL_MODE", "dual")
	for _, raw := range []string{
		"/odo/https/example.com/path",
		"/odo?url=https%3A%2F%2Fexample.com%2Fpath",
	} {
		req := httptest.NewRequest("GET", raw, nil)
		target, _, ok, err := ParseProxyRequest(req)
		if err != nil || !ok {
			t.Fatalf("expected dual mode to parse %q, ok=%v err=%v", raw, ok, err)
		}
		if target.String() != "https://example.com/path" {
			t.Fatalf("unexpected target for %q: %q", raw, target.String())
		}
	}
}

// virtual_host is served by the API's virtual-host runtime. The URL strategy
// keeps producing path-form URLs, which that runtime redirects to launch.
func TestVirtualHostModeKeepsPathURLShape(t *testing.T) {
	if got := NormalizeProxyURLMode("virtual_host"); got != ProxyURLModePath {
		t.Fatalf("expected virtual_host URL output to use the path shape, got %q", got)
	}
	if warning := ProxyURLModeWarning("virtual_host"); warning != "" {
		t.Fatalf("virtual_host is implemented; unexpected warning %q", warning)
	}
}

// The setup guide must cover what an operator needs before enabling the mode.
func TestVirtualHostProxyingDocExists(t *testing.T) {
	body, err := os.ReadFile("../../docs/virtual-host-proxying.md")
	if err != nil {
		t.Fatalf("expected docs/virtual-host-proxying.md to exist: %v", err)
	}
	for _, want := range []string{"APP_PROXY_URL_MODE=virtual_host", "APP_PROXY_BASE_DOMAIN", "Wildcard DNS", "Wildcard TLS", "DNS-01", "Single instance", "Rollback"} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("expected virtual-host doc to contain %q", want)
		}
	}
}

func TestObviousHelpersDoNotHardcodePathProxyURLConstruction(t *testing.T) {
	for _, path := range []string{"jsshim.go", "../ui/admin.go"} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, forbidden := range []string{`"/odo/https/" +`, `'/odo/https/' +`} {
			if strings.Contains(string(body), forbidden) {
				t.Fatalf("%s should not hand-build path proxy URLs with %q", path, forbidden)
			}
		}
	}
}

func TestParseProxyRequestCollapsesRepeatedPrefix(t *testing.T) {
	for _, raw := range []string{
		"/odo/https/www.jstor.org/odo/https/www.jstor.org/stable/3041316?seq=1",
		"/odo/https/www.jstor.org/odo/https/www.jstor.org/odo/https/www.jstor.org/stable/3041316?seq=1",
		"/odo?url=https%3A%2F%2Fwww.jstor.org%2Fodo%2Fhttps%2Fwww.jstor.org%2Fstable%2F3041316%3Fseq%3D1",
	} {
		target, _, ok, err := ParseProxyRequest(httptest.NewRequest("GET", raw, nil))
		if err != nil || !ok {
			t.Fatalf("parse failed: %v", err)
		}
		if target.String() != "https://www.jstor.org/stable/3041316?seq=1" {
			t.Fatalf("nested vendor target: %s", target)
		}
	}
	for _, raw := range []string{
		"/odo/https/www.jstor.org/a%2Fb?q=a%2Bb",
		"/odo/https/www.jstor.org/odo/https/www.jstor.org/a%2Fb?q=a%2Bb",
	} {
		target, _, _, err := ParseProxyRequest(httptest.NewRequest("GET", raw, nil))
		if err != nil || target.String() != "https://www.jstor.org/a%2Fb?q=a%2Bb" {
			t.Fatalf("escaped target changed: %v %v", target, err)
		}
	}
	target, _, _, err := ParseProxyRequest(httptest.NewRequest("GET", "/odo/https/www.jstor.org/odo/https/other.example/file", nil))
	if err != nil || target.Host != "www.jstor.org" || target.Path != "/odo/https/other.example/file" {
		t.Fatalf("another host's prefix was unwrapped: %v %v", target, err)
	}
}
