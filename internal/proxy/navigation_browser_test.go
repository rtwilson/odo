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
)

// Opt in with ODO_TEST_BROWSER=chromium-browser. Normal Go tests do not require
// an installed browser; this check exercises real history and shadow DOM APIs.
func TestBrowserNavigation(t *testing.T) {
	browser := os.Getenv("ODO_TEST_BROWSER")
	if browser == "" {
		t.Skip("set ODO_TEST_BROWSER to a Chromium executable to check browser navigation")
	}
	fixture, err := os.ReadFile("testdata/navigation.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{ProxyURLModePath, ProxyURLModeQuery} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("APP_PROXY_URL_MODE", mode)
			page := strings.ReplaceAll(string(fixture), "TEST_MODE", mode)
			page = strings.Replace(page, "<!-- ODO_SHIM -->", BuildJSShim("https://www.jstor.org", "https://www.jstor.org/stable/3041316?seq=1"), 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = w.Write([]byte(page))
			}))
			defer server.Close()
			target, _ := url.Parse("https://www.jstor.org/stable/3041316?seq=1")
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, browser, "--headless", "--disable-gpu", "--disable-background-networking", "--no-first-run", "--user-data-dir="+t.TempDir(), "--virtual-time-budget=2000", "--dump-dom", server.URL+BuildProxyURL(target))
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("browser failed: %v\n%s", err, output)
			}
			if !strings.Contains(string(output), `<pre id="results">PASS `) {
				t.Fatalf("navigation checks failed:\n%s", output)
			}
		})
	}
}
