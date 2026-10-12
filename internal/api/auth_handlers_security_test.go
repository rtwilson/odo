package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

func TestLoginPageEscapesNextAttribute(t *testing.T) {
	server := newTestServer(t, "secret")
	handler := server.Routes()
	for _, payload := range []string{
		`/resources?q=" autofocus onfocus="alert(1)`,
		`/resources?q="><script>alert(1)</script><input name="injected`,
		`/resources?q=&quot;><img src=x onerror=alert(1)>`,
		`/resources?q='><svg onload=alert(1)>&x=1`,
	} {
		t.Run(payload, func(t *testing.T) {
			// Require an accepted next path so rejection cannot hide missing escaping.
			want, ok := safeNextPath(payload)
			if !ok {
				t.Fatal("test payload must reach the HTML rendering path")
			}
			req := httptest.NewRequest(http.MethodGet, "/login?next="+url.QueryEscape(payload), nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "text/html; charset=utf-8" {
				t.Fatalf("unexpected response: %d %v", rec.Code, rec.Header())
			}
			doc, err := html.Parse(strings.NewReader(rec.Body.String()))
			if err != nil {
				t.Fatal(err)
			}
			inputs, nextInputs := 0, 0
			var visit func(*html.Node)
			visit = func(node *html.Node) {
				if node.Type == html.ElementNode {
					switch node.Data {
					case "script", "img", "svg":
						t.Errorf("payload created a %s element", node.Data)
					case "input":
						inputs++
					}
					attrs := map[string]string{}
					for _, attr := range node.Attr {
						attrs[attr.Key] = attr.Val
						if strings.HasPrefix(attr.Key, "on") || attr.Key == "autofocus" {
							t.Errorf("payload created attribute %s", attr.Key)
						}
					}
					if node.Data == "input" && attrs["name"] == "next" {
						nextInputs++
						if len(node.Attr) != 3 || attrs["type"] != "hidden" || attrs["value"] != want {
							t.Errorf("hidden next input changed: %v; want value %q", node.Attr, want)
						}
					}
				}
				for child := node.FirstChild; child != nil; child = child.NextSibling {
					visit(child)
				}
			}
			visit(doc)
			if inputs != 3 || nextInputs != 1 {
				t.Fatalf("expected three inputs with one hidden next input, got inputs=%d next=%d", inputs, nextInputs)
			}
		})
	}
}
