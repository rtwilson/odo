package proxy

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"example.org/odo/internal/resources"
)

func TestResourceRewriteDoesNotChangeInjectedShim(t *testing.T) {
	t.Setenv("APP_PROXY_INJECT_JS_SHIM", "true")
	base, _ := url.Parse("https://www.economist.com/")
	for _, mode := range []string{"path", "query"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("APP_PROXY_URL_MODE", mode)
			ctx, diagnostic := WithDiagnostics(context.Background())
			result := resources.TestResult{ContentRewriteRules: []resources.ContentRewriteRule{{
				ContentTypes: []string{"text/html"}, Find: "https://www.economist.com/", Replace: "{proxy_url:https://www.economist.com/}",
			}}}
			input := `<html><head></head><body><script>const vendorURL = "https://www.economist.com/";</script></body></html>`
			got := transformBody(ctx, input, "text/html", base, allowedHostTargetCheck, result)
			if !strings.Contains(got, BuildJSShim("https://www.economist.com", base.String())) {
				t.Fatalf("resource rule modified Odo shim: %s", got)
			}
			if !strings.Contains(got, `const vendorURL = "`+BuildProxyURL(base)+`";`) {
				t.Fatalf("vendor rule stopped working: %s", got)
			}
			if diagnostic.ContentRewriteRulesApplied != 1 || !diagnostic.JSShimInjected {
				t.Fatalf("unexpected diagnostics: %#v", diagnostic)
			}
		})
	}
}

func TestRewriteHTMLPreservesInlineScriptSource(t *testing.T) {
	base, _ := url.Parse("https://www.jstor.org/")
	script := `
function loadScript(src) {
 const script = document.createElement('script');
 script.src = src;
 script.src='/dynamic.js';
 const markup = '<img src="/inside-script.png" integrity="keep">';
 document.body.appendChild(script);
}
loadScript('/challenge.js');
`
	for _, tag := range []string{"script", "SCRIPT"} {
		input := `<html><head><` + tag + `>` + script + `</` + tag + `></head><body><img src="/real.png"></body></html>`
		got := RewriteHTML(context.Background(), input, base, allowedHostTargetCheck)
		if !strings.Contains(got, "<"+tag+">"+script+"</"+tag+">") {
			t.Fatalf("script source changed: %s", got)
		}
		if !strings.Contains(got, `src="/odo/https/www.jstor.org/real.png"`) {
			t.Fatalf("real attribute not rewritten: %s", got)
		}
	}
}

func TestRewriteHTMLPreservesNonAttributeContent(t *testing.T) {
	base, _ := url.Parse("https://www.jstor.org/")
	for _, input := range []string{
		`<!-- <img src="/comment.png"> -->`,
		`<textarea><img src="/text.png"></textarea>`,
		`<style>/* src="/text.png" */</style>`,
		`<script type="application/json">{"html":"<img src='/json.png'>"}</script>`,
		`<div title="src='/not-an-attribute.png'">src=/plain-text</div>`,
		`<script>script.src = src;`,
	} {
		if got := RewriteHTML(context.Background(), input, base, allowedHostTargetCheck); got != input {
			t.Errorf("changed non-attribute content:\nwant %s\ngot %s", input, got)
		}
	}
}

func TestRewriteHTMLHandlesAttributesAndEntities(t *testing.T) {
	base, _ := url.Parse("https://www.jstor.org/")
	input := `<img title="a > b" src='/image?a=1&amp;b=2'><form ACTION = '/search'></form><script src="/app.js" integrity="old"></script>`
	got := RewriteHTML(context.Background(), input, base, allowedHostTargetCheck)
	for _, want := range []string{`src="/odo/https/www.jstor.org/image?a=1&amp;b=2"`, `action="/odo/https/www.jstor.org/search"`, `src="/odo/https/www.jstor.org/app.js"`} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in %s", want, got)
		}
	}
	if strings.Contains(got, "integrity=") || strings.Count(got, "action=") != 1 {
		t.Fatalf("incorrect attributes: %s", got)
	}
}

func TestRewriteHTMLRemovesOnlyCSPMetaTags(t *testing.T) {
	base, _ := url.Parse("https://www.jstor.org/")
	for _, meta := range []string{
		`<meta http-equiv="Content-Security-Policy" content="script-src 'none'">`,
		`<META content="private-policy" HTTP-EQUIV='content-security-policy' />`,
		"<meta\nhttp-equiv=Content-Security-Policy content=private-policy>",
		`<meta http-equiv="Content&#45;Security&#45;Policy" content="private-policy">`,
		`<meta http-equiv=" Content-Security-Policy-Report-Only " content="private-policy">`,
	} {
		ctx, diagnostic := WithDiagnostics(context.Background())
		keep := `<meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta http-equiv="refresh" content="30"><script>script.src = src;</script>`
		got := RewriteHTML(ctx, "<head>"+meta+meta+keep+"</head>", base, allowedHostTargetCheck)
		if got != "<head>"+keep+"</head>" {
			t.Fatalf("unexpected HTML: %s", got)
		}
		if diagnostic.RemovedCSPMetaCount != 2 || !diagnostic.CSPRemoved {
			t.Fatalf("missing meta diagnostic: %#v", diagnostic)
		}
	}
	for _, input := range []string{
		`<!-- <meta http-equiv="Content-Security-Policy"> -->`,
		`<script>const text = '<meta http-equiv="Content-Security-Policy">';</script>`,
		`<textarea><meta http-equiv="Content-Security-Policy"></textarea>`,
		`<meta name="Content-Security-Policy" content="not-a-policy">`,
	} {
		ctx, diagnostic := WithDiagnostics(context.Background())
		if got := RewriteHTML(ctx, input, base, allowedHostTargetCheck); got != input || diagnostic.RemovedCSPMetaCount != 0 {
			t.Fatalf("changed non-policy markup: %s", got)
		}
	}
}
