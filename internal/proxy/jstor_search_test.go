package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"example.org/odo/internal/resources"
)

// Minimal route selection from the captured search-results bundle. Its error
// handler reports missing components remotely, so the console can stay quiet.
const jstorSearchRouter = `var component = [{path:"/action/doBasicSearch",component:"results"},{path:"/site/collection-list",component:"collections"}].find((e=>window.location.pathname.startsWith(e.path))).component;`

func jstorSearchRewriteResult(t *testing.T) resources.TestResult {
	t.Helper()
	data, err := os.ReadFile("../../config/resources/jstor.json")
	if err != nil {
		t.Fatal(err)
	}
	resource, err := resources.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if resource.Compatibility.JavaScriptTextRewriting == nil || !*resource.Compatibility.JavaScriptTextRewriting {
		t.Fatal("JSTOR search route compatibility must enable JavaScript rewriting")
	}
	return resources.TestResult{JavaScriptTextRewriteEnabled: true, ContentRewriteRules: resource.ContentRewriteRules}
}

func TestJSTORSearchRouteRewriteIsNarrowAndOptIn(t *testing.T) {
	result := jstorSearchRewriteResult(t)
	base, _ := url.Parse("https://www.jstor.org/assets/search-results.js")
	const unrelated = `console.log(window.location.pathname);`
	source := jstorSearchRouter + unrelated
	for _, contentType := range []string{"text/javascript", "application/javascript", "application/x-javascript"} {
		ctx, diagnostic := WithDiagnostics(context.Background())
		rewritten := ApplyContentRewriteRules(ctx, source, contentType, base, result)
		if strings.Contains(rewritten, "window.location.pathname.startsWith(e.path)") || !strings.HasSuffix(rewritten, unrelated) || diagnostic.ContentRewriteRulesApplied != 1 {
			t.Fatalf("unexpected route rewrite: %s", rewritten)
		}
	}
	result.JavaScriptTextRewriteEnabled = false
	if got := ApplyContentRewriteRules(context.Background(), source, "text/javascript", base, result); got != source {
		t.Fatal("search rule bypassed JavaScript compatibility flag")
	}
	result.JavaScriptTextRewriteEnabled = true
	if got := ApplyContentRewriteRules(context.Background(), source, "text/html", base, result); got != source {
		t.Fatal("JavaScript rule applied to HTML")
	}
}

func TestBrowserJSTORSearchRoute(t *testing.T) {
	browser := os.Getenv("ODO_TEST_BROWSER")
	if browser == "" {
		t.Skip("set ODO_TEST_BROWSER to a Chromium executable to check the search router")
	}
	result := jstorSearchRewriteResult(t)
	base, _ := url.Parse("https://www.jstor.org/assets/search-results.js")
	source := ApplyContentRewriteRules(context.Background(), jstorSearchRouter, "text/javascript", base, result)
	for _, tc := range []struct{ name, path, component string }{
		{"path", "/odo/https/www.jstor.org/action/doBasicSearch?Query=fixture-value", "results"},
		{"query", "/odo?url=" + url.QueryEscape("https://www.jstor.org/action/doBasicSearch?Query=fixture-value"), "results"},
		{"native", "/action/doBasicSearch?Query=fixture-value", "results"},
		{"collection", "/odo/https/www.jstor.org/site/collection-list", "collections"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			page := `<!doctype html><pre id="route">PENDING</pre><script>try {` + source + `document.getElementById("route").textContent=component;} catch(error) {document.getElementById("route").textContent="FAIL";}</script>`
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = w.Write([]byte(page))
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			output, err := exec.CommandContext(ctx, browser, "--headless", "--disable-gpu", "--disable-background-networking", "--no-first-run", "--user-data-dir="+t.TempDir(), "--dump-dom", server.URL+tc.path).CombinedOutput()
			if err != nil {
				t.Fatalf("browser failed: %v\n%s", err, output)
			}
			if !strings.Contains(string(output), `<pre id="route">`+tc.component+`</pre>`) {
				t.Fatalf("search route selection failed:\n%s", output)
			}
		})
	}
}
