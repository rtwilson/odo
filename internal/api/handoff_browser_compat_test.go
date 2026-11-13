package api

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/html"
)

// fakeVendorGzipHTML contains a same-host link that must not be rewritten
// because the body is compressed.
var fakeVendorGzipHTML = func() []byte {
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	_, _ = io.WriteString(z, `<a href="https://vendor.example/x">x</a>`)
	_ = z.Close()
	return b.Bytes()
}()

// fakeVendorPDF is binary content with bytes that must survive unmodified,
// including ones that look like HTML/URL text.
var fakeVendorPDF = func() []byte {
	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n<a href=\"https://vendor.example/x\">\n")
	for i := range 4096 {
		b.WriteByte(byte(i * 7))
	}
	b.WriteString("\n%%EOF\n")
	return b.Bytes()
}()

const fakeVendorIndex = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Fake Vendor &amp; Co</title>
<link rel="stylesheet" href="/static/site.css">
<script src="/static/app.js"></script>
</head><body>
<h1>Fake Vendor</h1>
<img id="logo" src="/static/logo.png" alt="Logo &quot;mark&quot;">
<a id="relative" href="articles/page2.html?q=a%20b&amp;n=1#sec">Relative page</a>
<a id="absolute" href="https://vendor.example/articles/page3.html?x=%2F&amp;y=1#top">Absolute same-host page</a>
<a id="absolute-http" href="http://VENDOR.example/articles/page3.html">Absolute same-host http page</a>
<a id="scheme-relative" href="//vendor.example/articles/page3.html">Scheme-relative page</a>
<a id="redirect" href="/go/page2">Redirecting link</a>
<a id="escaped" href="/docs/a%2Fb%20c?v=%E2%9C%93">Escaped path</a>
<a id="pdf" href="/files/report.pdf">Report</a>
<a id="fragment" href="#section">Fragment</a>
<a id="other-host" href="https://other.example/page">Other host</a>
<img id="external" src="https://cdn.external.example/pixel.png" alt="">
<script>var url = "https://vendor.example/should-stay-in-script";</script>
</body></html>
`

func fakeVendorSite() http.Handler {
	mux := http.NewServeMux()
	page := func(w http.ResponseWriter, body string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, body)
	}
	requireSession := func(w http.ResponseWriter, r *http.Request) bool {
		if cookie, err := r.Cookie("vendor_session"); err != nil || cookie.Value != "s3cret" {
			http.Error(w, "vendor session required", http.StatusForbidden)
			return false
		}
		return true
	}
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "vendor_session", Value: "s3cret", Path: "/", Secure: true, HttpOnly: true})
		w.Header().Set("ETag", `"index-v1"`)
		w.Header().Set("Content-Length", strconv.Itoa(len(fakeVendorIndex)))
		page(w, fakeVendorIndex)
	})
	mux.HandleFunc("HEAD /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("ETag", `"index-v1"`)
		w.Header().Set("Content-Length", strconv.Itoa(len(fakeVendorIndex)))
	})
	// A <base> naming the vendor host would send every relative URL off-proxy.
	mux.HandleFunc("GET /based.html", func(w http.ResponseWriter, r *http.Request) {
		page(w, `<!doctype html><head><base href="https://vendor.example/articles/"></head><a id="next" href="page3.html">Next</a>`)
	})
	mux.HandleFunc("GET /plain.html", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"plain-v1"`)
		page(w, `<!doctype html><a href="/static/site.css">relative only</a>`)
	})
	mux.HandleFunc("GET /compressed.html", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(fakeVendorGzipHTML)
	})
	mux.HandleFunc("GET /static/site.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		_, _ = io.WriteString(w, `body{background:url("/static/logo.png")}`)
	})
	mux.HandleFunc("GET /static/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript")
		_, _ = io.WriteString(w, `document.title += " ready";`)
	})
	mux.HandleFunc("GET /static/logo.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("\x89PNG\r\n\x1a\nfake"))
	})
	mux.HandleFunc("GET /articles/page2.html", func(w http.ResponseWriter, r *http.Request) {
		if !requireSession(w, r) {
			return
		}
		if r.URL.Query().Get("q") != "a b" || r.URL.Query().Get("n") != "1" {
			http.Error(w, "query lost", http.StatusBadRequest)
			return
		}
		page(w, `<!doctype html><title>Page 2</title><a id="up" href="../">Home</a> <a id="next" href="page3.html">Next</a>`)
	})
	mux.HandleFunc("GET /articles/page3.html", func(w http.ResponseWriter, r *http.Request) {
		if requireSession(w, r) {
			page(w, `<!doctype html><title>Page 3</title><p>page3-body</p>`)
		}
	})
	mux.HandleFunc("GET /go/page2", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://vendor.example/articles/page2.html?q=a%20b&n=1", http.StatusFound)
	})
	mux.HandleFunc("GET /docs/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/docs/a%2Fb%20c" || r.URL.Query().Get("v") != "✓" {
			http.Error(w, "escaping lost", http.StatusBadRequest)
			return
		}
		page(w, `<!doctype html><title>Escaped</title>escaped-ok`)
	})
	mux.HandleFunc("GET /files/report.pdf", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("ETag", `"report-v1"`)
		http.ServeContent(w, r, "report.pdf", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), bytes.NewReader(fakeVendorPDF))
	})
	return mux
}

// browse issues one browser request, as a document navigation or a
// subresource fetch, and returns the response with its full body.
func (d *deliveryHarness) browse(t *testing.T, method, target, dest string, header http.Header) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, values := range header {
		req.Header[name] = values
	}
	req.Header.Set("Sec-Fetch-Dest", dest)
	if dest == "document" {
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Accept", "text/html")
	} else {
		req.Header.Set("Sec-Fetch-Mode", "no-cors")
		req.Header.Set("Accept", "*/*")
	}
	response, err := d.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response, body
}

// pageURLs returns each URL-bearing attribute value by element id (or by tag
// name for elements without an id), as the browser would see it.
func pageURLs(t *testing.T, body []byte) map[string]string {
	t.Helper()
	urls := map[string]string{}
	tokenizer := html.NewTokenizer(bytes.NewReader(body))
	for {
		kind := tokenizer.Next()
		if kind == html.ErrorToken {
			return urls
		}
		if kind != html.StartTagToken && kind != html.SelfClosingTagToken {
			continue
		}
		token := tokenizer.Token()
		id := token.Data
		for _, attr := range token.Attr {
			if attr.Key == "id" {
				id = attr.Val
			}
		}
		for _, attr := range token.Attr {
			if attr.Key == "href" || attr.Key == "src" {
				urls[id] = attr.Val
			}
		}
	}
}

func resolve(t *testing.T, base, ref string) string {
	t.Helper()
	b, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	r, err := url.Parse(ref)
	if err != nil {
		t.Fatal(err)
	}
	return b.ResolveReference(r).String()
}

// The complete browser path through one registered vendor host: central
// login session, launch, confirmation, grant, then a multi-page vendor site.
func TestVendorBrowserCompatibilitySameHostSite(t *testing.T) {
	d := newDeliveryHarnessWithSite(t, fakeVendorSite())
	proxyBase := "https://" + d.authority

	// Entry: no grant yet, so the navigation restarts the handoff; the patron
	// confirms at central and redemption returns to the index.
	d.target = "https://vendor.example/"
	if response, _ := d.browse(t, "GET", proxyBase+"/", "document", nil); response.StatusCode != 303 {
		t.Fatalf("entry did not start the handoff: %d", response.StatusCode)
	}
	d.finish(t, d.ticket(t))
	index, body := d.browse(t, "GET", proxyBase+"/", "document", nil)
	if index.StatusCode != 200 || !bytes.Contains(body, []byte("<h1>Fake Vendor</h1>")) {
		t.Fatalf("index: %d", index.StatusCode)
	}
	for _, cookie := range index.Cookies() {
		if cookie.Name != handoffAttemptCookie || cookie.MaxAge >= 0 {
			t.Fatal("upstream Set-Cookie reached the browser")
		}
	}
	urls := pageURLs(t, body)
	pageURL := proxyBase + "/"

	t.Run("root-relative assets", func(t *testing.T) {
		for id, want := range map[string]string{"link": "text/css", "script": "text/javascript", "logo": "image/png"} {
			dest := map[string]string{"link": "style", "script": "script", "logo": "image"}[id]
			response, _ := d.browse(t, "GET", resolve(t, pageURL, urls[id]), dest, nil)
			if response.StatusCode != 200 || response.Header.Get("Content-Type") != want {
				t.Fatalf("%s asset: %d %q", id, response.StatusCode, response.Header.Get("Content-Type"))
			}
		}
	})
	t.Run("relative navigation keeps query and session cookie", func(t *testing.T) {
		target := resolve(t, pageURL, urls["relative"])
		response, page2 := d.browse(t, "GET", target, "document", nil)
		if response.StatusCode != 200 || !bytes.Contains(page2, []byte("Page 2")) {
			t.Fatalf("page2: %d %s", response.StatusCode, page2)
		}
		links := pageURLs(t, page2)
		if response, _ := d.browse(t, "GET", resolve(t, target, links["next"]), "document", nil); response.StatusCode != 200 {
			t.Fatalf("relative link from page2: %d", response.StatusCode)
		}
		if response, home := d.browse(t, "GET", resolve(t, target, links["up"]), "document", nil); response.StatusCode != 200 || !bytes.Contains(home, []byte("Fake Vendor")) {
			t.Fatalf("parent-relative link: %d", response.StatusCode)
		}
	})
	t.Run("absolute same-host links stay on the proxy host", func(t *testing.T) {
		for _, id := range []string{"absolute", "absolute-http", "scheme-relative"} {
			target, _ := url.Parse(resolve(t, pageURL, urls[id]))
			if target.Host != d.authority || target.Scheme != "https" {
				t.Fatalf("%s link leaves the proxy host: %s", id, target.Redacted())
			}
			response, page3 := d.browse(t, "GET", target.String(), "document", nil)
			if response.StatusCode != 200 || !bytes.Contains(page3, []byte("page3-body")) {
				t.Fatalf("%s page: %d", id, response.StatusCode)
			}
		}
		if got := urls["absolute"]; got != proxyBase+"/articles/page3.html?x=%2F&y=1#top" {
			t.Fatalf("absolute link lost its path, query or fragment: %q", got)
		}
	})
	t.Run("same-host redirect", func(t *testing.T) {
		response, _ := d.browse(t, "GET", resolve(t, pageURL, urls["redirect"]), "document", nil)
		location := response.Header.Get("Location")
		if response.StatusCode != 302 || location != proxyBase+"/articles/page2.html?q=a%20b&n=1" {
			t.Fatalf("redirect: %d %q", response.StatusCode, location)
		}
		if response, _ := d.browse(t, "GET", location, "document", nil); response.StatusCode != 200 {
			t.Fatalf("redirect target: %d", response.StatusCode)
		}
	})
	t.Run("escaped path and query", func(t *testing.T) {
		response, page := d.browse(t, "GET", resolve(t, pageURL, urls["escaped"]), "document", nil)
		if response.StatusCode != 200 || !bytes.Contains(page, []byte("escaped-ok")) {
			t.Fatalf("escaped: %d %s", response.StatusCode, page)
		}
	})
	t.Run("unchanged markup", func(t *testing.T) {
		for id, want := range map[string]string{
			"fragment": "#section", "other-host": "https://other.example/page",
			"external": "https://cdn.external.example/pixel.png", "relative": "articles/page2.html?q=a%20b&n=1#sec",
		} {
			if urls[id] != want {
				t.Fatalf("%s was rewritten to %q", id, urls[id])
			}
		}
		for _, kept := range []string{
			`<title>Fake Vendor &amp; Co</title>`, `alt="Logo &quot;mark&quot;"`,
			`<script>var url = "https://vendor.example/should-stay-in-script";</script>`,
			`<link rel="stylesheet" href="/static/site.css">`,
		} {
			if !bytes.Contains(body, []byte(kept)) {
				t.Fatalf("document changed outside URL attributes: missing %s", kept)
			}
		}
	})
	t.Run("pdf ranges and integrity", func(t *testing.T) {
		pdf := resolve(t, pageURL, urls["pdf"])
		response, full := d.browse(t, "GET", pdf, "document", nil)
		if response.StatusCode != 200 || !bytes.Equal(full, fakeVendorPDF) || response.Header.Get("Accept-Ranges") != "bytes" ||
			response.Header.Get("Content-Type") != "application/pdf" || response.Header.Get("ETag") != `"report-v1"` {
			t.Fatalf("pdf: %d len=%d", response.StatusCode, len(full))
		}
		for _, tc := range []struct{ header, contentRange string }{
			{"bytes=0-99", "bytes 0-99/"}, {"bytes=100-", "bytes 100-"}, {"bytes=-50", "bytes "},
		} {
			response, part := d.browse(t, "GET", pdf, "empty", http.Header{"Range": {tc.header}})
			start, end := 0, len(fakeVendorPDF)
			switch tc.header {
			case "bytes=0-99":
				end = 100
			case "bytes=100-":
				start = 100
			case "bytes=-50":
				start = len(fakeVendorPDF) - 50
			}
			if response.StatusCode != 206 || !strings.HasPrefix(response.Header.Get("Content-Range"), tc.contentRange) ||
				!bytes.Equal(part, fakeVendorPDF[start:end]) || response.ContentLength != int64(len(part)) || response.Header.Get("Accept-Ranges") != "bytes" {
				t.Fatalf("range %s: %d %q len=%d", tc.header, response.StatusCode, response.Header.Get("Content-Range"), len(part))
			}
		}
		if response, part := d.browse(t, "GET", pdf, "empty", http.Header{"Range": {"bytes=0-9"}, "If-Range": {`"report-v1"`}}); response.StatusCode != 206 || !bytes.Equal(part, fakeVendorPDF[:10]) {
			t.Fatalf("If-Range: %d", response.StatusCode)
		}
		if response, part := d.browse(t, "HEAD", pdf, "empty", nil); response.StatusCode != 200 || len(part) != 0 || response.ContentLength != int64(len(fakeVendorPDF)) {
			t.Fatalf("pdf HEAD: %d", response.StatusCode)
		}
	})
	t.Run("base element stays on the proxy host", func(t *testing.T) {
		based := proxyBase + "/based.html"
		response, page := d.browse(t, "GET", based, "document", nil)
		links := pageURLs(t, page)
		if response.StatusCode != 200 || links["base"] != proxyBase+"/articles/" {
			t.Fatalf("base: %d %q", response.StatusCode, links["base"])
		}
		// Native resolution against the rewritten <base>.
		next := resolve(t, links["base"], links["next"])
		if response, body := d.browse(t, "GET", next, "document", nil); response.StatusCode != 200 || !bytes.Contains(body, []byte("page3-body")) {
			t.Fatalf("relative link under base: %d %s", response.StatusCode, next)
		}
	})
	t.Run("response metadata stays consistent", func(t *testing.T) {
		// Rewritten: exact length, no validators or ranges for the old bytes.
		if index.ContentLength != int64(len(body)) || index.Header.Get("ETag") != "" || index.Header.Get("Accept-Ranges") != "" {
			t.Fatalf("rewritten index metadata: len=%d etag=%q", index.ContentLength, index.Header.Get("ETag"))
		}
		head, headBody := d.browse(t, "HEAD", proxyBase+"/", "document", nil)
		if head.StatusCode != 200 || len(headBody) != 0 || head.Header.Get("ETag") != "" || head.Header.Get("Content-Length") != "" {
			t.Fatal("HEAD advertised metadata that a rewritten GET would not match")
		}
		// Unchanged HTML keeps its upstream bytes and validators.
		response, plain := d.browse(t, "GET", proxyBase+"/plain.html", "document", nil)
		if response.StatusCode != 200 || response.Header.Get("ETag") != `"plain-v1"` || response.ContentLength != int64(len(plain)) {
			t.Fatal("unchanged HTML lost its validators")
		}
		// Compressed HTML is never modified.
		request, _ := http.NewRequest("GET", proxyBase+"/compressed.html", nil)
		request.Header.Set("Accept-Encoding", "gzip")
		// An explicit Accept-Encoding stops the client decompressing.
		raw, err := d.client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		compressed, _ := io.ReadAll(raw.Body)
		raw.Body.Close()
		if raw.StatusCode != 200 || raw.Header.Get("Content-Encoding") != "gzip" || !bytes.Equal(compressed, fakeVendorGzipHTML) {
			t.Fatal("compressed HTML was modified")
		}
	})
	t.Run("vendor HTML gets no central application policy", func(t *testing.T) {
		for _, name := range []string{"Content-Security-Policy", "X-Frame-Options", "Permissions-Policy"} {
			if index.Header.Get(name) != "" {
				t.Fatalf("central %s applied to vendor HTML", name)
			}
		}
		if index.Header.Get("Cache-Control") != "no-store" || index.Header.Get("Referrer-Policy") != "strict-origin" || index.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatal("vendor delivery headers missing")
		}
	})
	t.Run("logs omit patron targets and credentials", func(t *testing.T) {
		for _, secret := range []string{"articles/page2", "q=a", "a%2Fb", "report.pdf", "s3cret", "vendor_session", d.central, "vendor.example/articles"} {
			if strings.Contains(d.logs.String(), secret) {
				t.Fatalf("logs disclosed %q", secret)
			}
		}
	})
	t.Run("vendor cookie stays upstream", func(t *testing.T) {
		vendorURL, _ := url.Parse(proxyBase)
		for _, cookie := range d.client.Jar.Cookies(vendorURL) {
			if cookie.Name == "vendor_session" {
				t.Fatal("vendor application cookie reached the browser jar")
			}
		}
	})
}
