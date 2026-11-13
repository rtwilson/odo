package proxy

import (
	"net/url"
	"strings"
	"testing"
)

func TestParseLaunchQueryPreservesTargetData(t *testing.T) {
	for _, target := range []string{
		"https://vendor.example/",
		"https://vendor.example/a%2fb%2Fc?q=a%2Bb&space=a+b&literal=a%20b",
		"https://vendor.example/search?a=1&b=2&url=https%3A%2F%2Fother.example%2Fa%3Fx%3D1%26y%3D2",
		"https://vendor.example/search?next=https://other.example/?q=x+y&x==?&empty=",
		"https://vendor.example/search?value=100%25&twice=%252F&semi=a;b",
		"https://vendor.example/a%23b?hash=%23&unicode=%E2%9C%93",
		"https://vendor.example/日本語?q=日本語",
		"https://vendor.example/path?",
	} {
		for _, envelope := range []string{"url=" + url.QueryEscape(target), "url=" + target} {
			t.Run(envelope, func(t *testing.T) {
				got, err := ParseLaunchQuery(envelope)
				if err != nil {
					t.Fatal(err)
				}
				want, err := url.Parse(target)
				if err != nil {
					t.Fatal(err)
				}
				if got.String() != want.String() || got.EscapedPath() != want.EscapedPath() || got.RawQuery != want.RawQuery || got.ForceQuery != want.ForceQuery {
					t.Fatalf("target data changed: got %q want %q", got, want)
				}
			})
		}
	}
}

func TestParseLaunchQueryRejectsInvalidEnvelope(t *testing.T) {
	for _, query := range []string{
		"", "url=", "url", "URL=https%3A%2F%2Fvendor.example", "other=x&url=https%3A%2F%2Fvendor.example",
		"url=https%3A%2F%2Fvendor.example&url=https%3A%2F%2Fother.example",
		"url=https%3A%2F%2Fvendor.example&extra=x", "url=https%3A%2F%2Fvendor.example&",
		"url=https%3A%2F%2Fvendor.example;extra=x", "url=%zz",
		"url=" + url.QueryEscape(url.QueryEscape("https://vendor.example/")),
	} {
		t.Run(query, func(t *testing.T) {
			if got, err := ParseLaunchQuery(query); err == nil || got != nil {
				t.Fatalf("accepted %q: %v err=%v", query, got, err)
			}
		})
	}
}

func TestParseLaunchQueryRejectsUnsafeSyntax(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("APP_PROXY_ALLOW_LOCAL_HTTP", "true")
	for _, target := range []string{
		"http://localhost/", "javascript:alert(1)", "//vendor.example/", "/relative",
		"https://user:password@vendor.example/", "https://127.0.0.1/", "https://[::1]/",
		"https://localhost/", "https://vendor.local/", "https://vendor.internal/",
		"https://vendor.example:8443/", "https://vendor.example/%zz", "https://vendor.example/?q=%zz",
		"https://vendor.example/#fragment", "https://vendor.example/#", " https://vendor.example/",
		"https://vendor.example/?q=unescaped space", "https://vendor.example/?q=\r\nvalue",
	} {
		for _, envelope := range []string{"url=" + url.QueryEscape(target), "url=" + target} {
			t.Run(envelope, func(t *testing.T) {
				if got, err := ParseLaunchQuery(envelope); err == nil || got != nil {
					t.Fatalf("accepted unsafe target %q: %v err=%v", target, got, err)
				}
			})
		}
	}
}

func TestParseLaunchQueryLengthBound(t *testing.T) {
	prefix := "url=https://vendor.example/?q="
	query := prefix + strings.Repeat("x", MaxLaunchQueryBytes-len(prefix))
	if _, err := ParseLaunchQuery(query); err != nil {
		t.Fatalf("rejected query at limit: %v", err)
	}
	if got, err := ParseLaunchQuery(query + "x"); err == nil || got != nil {
		t.Fatal("accepted query over limit")
	}
}
