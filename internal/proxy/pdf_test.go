package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestPDFStreaming(t *testing.T) {
	for _, tc := range []struct {
		name, method, contentType, disposition, requestRange, encoding string
		status                                                         int
	}{
		{"inline", "GET", "application/pdf", `inline; filename="article.pdf"`, "", "", 200},
		{"attachment", "GET", "application/pdf", `attachment; filename="article.pdf"`, "", "", 200},
		{"range", "GET", "application/pdf", "inline", "bytes=0-15", "", 206},
		{"range ignored upstream", "GET", "application/pdf", "inline", "bytes=0-15", "", 200},
		{"missing MIME", "GET", "", "inline", "", "", 200},
		{"encoded bytes", "GET", "application/pdf", "inline", "", "gzip", 200},
		{"head", "HEAD", "application/pdf", "inline", "", "", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Include invalid UTF-8 and URL-like text that rewriting must leave alone.
			const body = "%PDF-1.7\x00\xff https://www.jstor.org/test"
			responseBody := body
			headers := http.Header{
				"Content-Disposition": {tc.disposition}, "Accept-Ranges": {"bytes"},
				"Etag": {`"pdf-version"`}, "Last-Modified": {"Wed, 21 Oct 2015 07:28:00 GMT"},
				"Cache-Control": {"private, max-age=60"},
			}
			if tc.contentType != "" {
				headers.Set("Content-Type", tc.contentType)
			}
			if tc.encoding != "" {
				headers.Set("Content-Encoding", tc.encoding)
			}
			if tc.status == 206 {
				responseBody = body[:16]
				headers.Set("Content-Range", "bytes 0-15/"+strconv.Itoa(len(body)))
			}
			headers.Set("Content-Length", strconv.Itoa(len(responseBody)))
			store := NewDiagnosticsStore(10)
			handler := FetchHandlerWithOptions(FetchOptions{Diagnostics: store, Check: allowedTargetCheck, Client: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.Header.Get("Range") != tc.requestRange {
					t.Errorf("Range = %q", req.Header.Get("Range"))
				}
				wantIfRange := ""
				if tc.requestRange != "" {
					wantIfRange = `"pdf-version"`
				}
				if req.Header.Get("If-Range") != wantIfRange {
					t.Errorf("If-Range = %q", req.Header.Get("If-Range"))
				}
				if req.Header.Get("Accept-Encoding") != "identity" {
					t.Error("transport could implicitly decompress PDF")
				}
				return &http.Response{StatusCode: tc.status, Header: headers, Body: io.NopCloser(strings.NewReader(responseBody)), Request: req}, nil
			}).client()})
			req := httptest.NewRequest(tc.method, "/odo/https/www.jstor.org/article.pdf", nil)
			req.Header.Set("Sec-Fetch-Dest", "iframe")
			if tc.requestRange != "" {
				req.Header.Set("Range", tc.requestRange)
				req.Header.Set("If-Range", `"pdf-version"`)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d", rec.Code, tc.status)
			}
			wantBody := responseBody
			if tc.method == "HEAD" {
				wantBody = ""
			}
			if rec.Body.String() != wantBody {
				t.Fatal("PDF bytes changed")
			}
			if rec.Header().Get("Content-Type") != "application/pdf" {
				t.Errorf("Content-Type = %q", rec.Header().Get("Content-Type"))
			}
			for name, values := range headers {
				if rec.Header().Get(name) != values[0] {
					t.Errorf("%s = %q, want %q", name, rec.Header().Get(name), values[0])
				}
			}
			var pdfEvents int
			for _, event := range store.Recent() {
				if event.Type != "proxy_pdf_response" {
					continue
				}
				pdfEvents++
				if event.TargetHost != "www.jstor.org" || event.UpstreamStatus != tc.status || event.ContentType != "application/pdf" ||
					event.RangeRequested != (tc.requestRange != "") || event.PartialContent != (tc.status == 206) ||
					event.ContentRangePresent != (tc.status == 206) || !event.DeliveryHeadersPreserved ||
					event.ContentTypeMissing != (tc.contentType == "") || event.ContentTypeCorrected != (tc.contentType == "") {
					t.Errorf("unexpected PDF diagnostic: %#v", event)
				}
			}
			if pdfEvents != 1 {
				t.Fatalf("PDF event count = %d, want 1", pdfEvents)
			}
		})
	}
}

func TestPDFDiagnosticsExcludePrivateValues(t *testing.T) {
	for _, disposition := range []struct{ raw, want string }{
		{`inline; filename="private-article.pdf"`, "inline"},
		{`attachment; filename*=UTF-8''private-title.pdf`, "attachment"},
		{"private-disposition", "other"},
		{"", "missing"},
	} {
		t.Run(disposition.want, func(t *testing.T) {
			store := NewDiagnosticsStore(10)
			request := httptest.NewRequest("GET", "https://odo.example/private-search?q=private-term", nil)
			request.Header.Set("Range", "private-range")
			request.Header.Set("Cookie", "private-cookie")
			request.Header.Set("Authorization", "private-authorization")
			headers := http.Header{
				"Content-Type":        {"application/pdf; private-parameter=private-value"},
				"Content-Disposition": {disposition.raw},
				"Accept-Ranges":       {"private-accept-ranges"}, "Content-Range": {"private-content-range"},
			}
			recordPDFResponse(store, &Diagnostics{TargetHost: "vendor.example", UpstreamStatus: 206, AnonymousRulePattern: "private-rule"}, request, headers, headers.Clone())
			event := store.Recent()[0]
			if event.ContentDisposition != disposition.want || event.AcceptRanges != "other" || !event.ContentRangePresent {
				t.Fatalf("unexpected categories: %#v", event)
			}
			encoded, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(encoded), "private") {
				t.Fatalf("private value in PDF event: %s", encoded)
			}
		})
	}
}
