package proxy

import (
	"bytes"
	"strings"
	"testing"
)

const (
	testUpstream = "vendor.example"
	testProxy    = "h-test.proxy.example"
)

func TestRewriteSameHostURLRules(t *testing.T) {
	for raw, want := range map[string]string{
		"https://vendor.example/a%2Fb?q=x%20y&z=1#frag": "https://" + testProxy + "/a%2Fb?q=x%20y&z=1#frag",
		"HTTPS://VENDOR.EXAMPLE:443/p":                  "https://" + testProxy + "/p",
		"http://vendor.example/p":                       "https://" + testProxy + "/p",
		"http://vendor.example:80":                      "https://" + testProxy,
		"//vendor.example/p?x":                          "https://" + testProxy + "/p?x",
		"  https://vendor.example/p \n":                 "https://" + testProxy + "/p",
		"https://vendor.example?q":                      "https://" + testProxy + "?q",
		"https://vendor.example#top":                    "https://" + testProxy + "#top",
	} {
		if got, ok := rewriteSameHostURL(raw, testUpstream, testProxy); !ok || got != want {
			t.Fatalf("%q: got %q %v want %q", raw, got, ok, want)
		}
	}
	for _, raw := range []string{
		"/root", "relative/page", "../up", "?q=1", "#frag", "",
		"https://other.example/p", "https://vendor.example.evil/p", "https://evil.vendor.example/p",
		"https://vendor.example:8443/p", "http://vendor.example:443/p", "https://user@vendor.example/p",
		"https://vendor.example%2eevil/p", "https:\\\\vendor.example\\p", "javascript:https://vendor.example/",
		"data:text/html,https://vendor.example/", "mailto:x@vendor.example", "ftp://vendor.example/",
		"https://vendor.example./p",
	} {
		if got, ok := rewriteSameHostURL(raw, testUpstream, testProxy); ok {
			t.Fatalf("%q was rewritten to %q", raw, got)
		}
	}
}

func TestRewriteSameHostHTMLOnlyRecognizedAttributes(t *testing.T) {
	input := `<!DOCTYPE html><HTML><head><base href="https://vendor.example/articles/">` +
		`<link rel=stylesheet href='https://vendor.example/s.css'><script src="//vendor.example/a.js" async></script>` +
		`<script>location = "https://vendor.example/js";</script><style>a{background:url(https://vendor.example/c.png)}</style></head>` +
		`<body><!-- https://vendor.example/comment --><a href="https://vendor.example/p?a=1&amp;b=2#f" title="Caf&eacute; &quot;x&quot;">https://vendor.example/text</a>` +
		`<img srcset="https://vendor.example/1x.png 1x, /2x.png 2x,https://other.example/3x.png 3x" alt=ok>` +
		`<form action="https://vendor.example/search"><button formaction="https://vendor.example/b">b</button></form>` +
		`<video poster="https://vendor.example/v.jpg"></video><object data="https://vendor.example/o"></object>` +
		`<div data-src="https://vendor.example/lazy" style="background:url(https://vendor.example/s.png)"></div>` +
		`<meta http-equiv="refresh" content="0; url=https://vendor.example/r"><br/></body></HTML>`
	want := `<!DOCTYPE html><HTML><head><base href="https://h-test.proxy.example/articles/">` +
		`<link rel="stylesheet" href="https://h-test.proxy.example/s.css"><script src="https://h-test.proxy.example/a.js" async=""></script>` +
		`<script>location = "https://vendor.example/js";</script><style>a{background:url(https://vendor.example/c.png)}</style></head>` +
		`<body><!-- https://vendor.example/comment --><a href="https://h-test.proxy.example/p?a=1&amp;b=2#f" title="Caf&#233; &quot;x&quot;">https://vendor.example/text</a>` +
		`<img srcset="https://h-test.proxy.example/1x.png 1x, /2x.png 2x,https://other.example/3x.png 3x" alt="ok">` +
		`<form action="https://h-test.proxy.example/search"><button formaction="https://h-test.proxy.example/b">b</button></form>` +
		`<video poster="https://h-test.proxy.example/v.jpg"></video><object data="https://h-test.proxy.example/o"></object>` +
		`<div data-src="https://vendor.example/lazy" style="background:url(https://vendor.example/s.png)"></div>` +
		`<meta http-equiv="refresh" content="0; url=https://vendor.example/r"><br/></body></HTML>`
	got, changed := RewriteSameHostHTML([]byte(input), testUpstream, testProxy)
	if !changed || string(got) != want {
		t.Fatalf("rewrite mismatch:\n got %s\nwant %s", got, want)
	}
}

func TestRewriteSameHostHTMLPreservesUnchangedDocuments(t *testing.T) {
	for _, input := range []string{
		`<!doctype html><a href="/p">x</a><img src="relative.png"><a href="https://other.example/">o</a>`,
		`<HTML><BODY CLASS=x><A HREF='/p' Title=T>x</A><svg viewBox="0 0 1 1"></svg></BODY></HTML>`,
		"<p>\xe9t\xe9 (windows-1252 bytes)</p><a href=\"page.html\">x</a>",
		`<a href="https://vendor.example/unterminated`,
		"",
	} {
		got, changed := RewriteSameHostHTML([]byte(input), testUpstream, testProxy)
		if changed || !bytes.Equal(got, []byte(input)) {
			t.Fatalf("unchanged document was modified: %q -> %q", input, got)
		}
	}
}

// Changed tags keep legacy-encoded bytes intact and encode decoded entities as
// numeric references, so the result is valid in the document's own charset.
func TestRewriteSameHostHTMLKeepsLegacyEncodingBytes(t *testing.T) {
	input := "<p>\xe9t\xe9</p><a href=\"https://vendor.example/p\" title=\"\xe9t\xe9 &copy;\">x</a>"
	want := "<p>\xe9t\xe9</p><a href=\"https://h-test.proxy.example/p\" title=\"\xe9t\xe9 &#169;\">x</a>"
	if got, changed := RewriteSameHostHTML([]byte(input), testUpstream, testProxy); !changed || string(got) != want {
		t.Fatalf("got %q", got)
	}
}

// Re-serializing a rewritten tag must keep case-sensitive SVG names, which
// browsers ignore when lower-cased.
func TestRewriteSameHostHTMLKeepsSVGNameCase(t *testing.T) {
	body := []byte(`<svg viewBox="0 0 10 10"><image href="https://vendor.example/a.png" preserveAspectRatio="none" data-x=1 /><linearGradient xlink:href="https://vendor.example/g"></linearGradient></svg>`)
	out, changed := RewriteSameHostHTML(body, "vendor.example", "h-label.proxy.example")
	if !changed {
		t.Fatal("same-host href not rewritten")
	}
	want := `<svg viewBox="0 0 10 10"><image href="https://h-label.proxy.example/a.png" preserveAspectRatio="none" data-x="1" /><linearGradient xlink:href="https://vendor.example/g"></linearGradient></svg>`
	if string(out) != want {
		t.Fatalf("got  %s\nwant %s", out, want)
	}
}

func TestScanTagNamesFallsBackOnMismatch(t *testing.T) {
	for raw, want := range map[string]string{
		`<IMG SRC='x' Alt = "a b" data-q=1>`: "IMG SRC Alt data-q",
		`<a =odd href=x>`:                    "a =odd href",
		`<a href="unterminated>`:             "",
	} {
		tag, attrs, ok := scanTagNames([]byte(raw))
		got := ""
		if ok {
			got = strings.Join(append([]string{tag}, attrs...), " ")
		}
		if got != want {
			t.Fatalf("%s: got %q want %q", raw, got, want)
		}
	}
}

func TestRewriteHostsHTMLMapsEachRegisteredHost(t *testing.T) {
	body := []byte(`<a href="https://WWW.vendor.example/a">a</a><img src="//cdn.vendor.example/i.png" srcset="https://cdn.vendor.example/i2.png 2x, https://other.example/x.png 3x"><script src="https://other.example/t.js"></script>`)
	out, changed := RewriteHostsHTML(body, map[string]string{"www.vendor.example": "h-www.proxy.example", "cdn.vendor.example": "h-cdn.proxy.example"})
	want := `<a href="https://h-www.proxy.example/a">a</a><img src="https://h-cdn.proxy.example/i.png" srcset="https://h-cdn.proxy.example/i2.png 2x, https://other.example/x.png 3x"><script src="https://other.example/t.js"></script>`
	if !changed || string(out) != want {
		t.Fatalf("got  %s\nwant %s", out, want)
	}
}
