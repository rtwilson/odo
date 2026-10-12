package api

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPublicBaseURLRestrictsForwardedScheme(t *testing.T) {
	t.Setenv("APP_PUBLIC_URL", "")
	t.Setenv("APP_TRUST_PROXY_HEADERS", "true")
	for _, tc := range []struct {
		proto string
		want  string
	}{
		{"http", "http"},
		{"https", "https"},
		{" HTTPS , http", "https"},
		{"https, javascript", "https"},
		{"javascript, https", ""},
		{"javascript", ""},
		{"https://evil.example", ""},
		{`https"><script>alert(1)</script>`, ""},
		{"", ""},
	} {
		for _, connection := range []string{"http", "https"} {
			t.Run(connection+"/"+tc.proto, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodGet, connection+"://internal.example/auth/saml/metadata", nil)
				req.Header.Set("X-Forwarded-Proto", tc.proto)
				req.Header.Set("X-Forwarded-Host", "access.example.edu")
				want := tc.want
				if want == "" {
					want = connection
				}
				if got := publicBaseURL(req); got != want+"://access.example.edu" {
					t.Fatalf("unexpected public base URL: %q", got)
				}
			})
		}
	}
	// Configured URLs remain authoritative even when forwarding is enabled.
	t.Setenv("APP_PUBLIC_URL", "https://configured.example/")
	req := httptest.NewRequest(http.MethodGet, "http://internal.example/", nil)
	req.Header.Set("X-Forwarded-Proto", "http")
	req.Header.Set("X-Forwarded-Host", "forwarded.example")
	if got := publicBaseURL(req); got != "https://configured.example" {
		t.Fatalf("configured public URL lost priority: %q", got)
	}
}

func TestSAMLMetadataEscapesHostileForwardedHeaders(t *testing.T) {
	t.Setenv("APP_PUBLIC_URL", "")
	t.Setenv("APP_TRUST_PROXY_HEADERS", "true")
	server := newTestServer(t, "secret")
	handler := server.Routes()
	for _, proto := range []string{"https", `https"><script>alert(1)</script>`} {
		t.Run(proto, func(t *testing.T) {
			host := `access.example.edu"><script>alert(1)</script><x injected="yes&'`
			req := httptest.NewRequest(http.MethodGet, "http://internal.example/auth/saml/metadata", nil)
			req.Header.Set("X-Forwarded-Proto", proto)
			req.Header.Set("X-Forwarded-Host", host)

			// Create through the API so forwarded headers supply the default URLs.
			createReq := httptest.NewRequest(http.MethodPost, "http://internal.example/api/v1/auth/saml/providers", strings.NewReader(`{"id":"campus","name":"Campus","status":"active"}`))
			createReq.Header.Set("Authorization", "Bearer secret")
			createReq.Header.Set("Content-Type", "application/json")
			createReq.Header.Set("X-Forwarded-Proto", proto)
			createReq.Header.Set("X-Forwarded-Host", host)
			createRec := httptest.NewRecorder()
			handler.ServeHTTP(createRec, createReq)
			if createRec.Code != http.StatusOK {
				t.Fatalf("create provider: %d %s", createRec.Code, createRec.Body.String())
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/samlmetadata+xml; charset=utf-8" {
				t.Fatalf("unexpected metadata response: %d %s", rec.Code, rec.Body.String())
			}
			scheme := "http"
			if proto == "https" {
				scheme = "https"
			}
			decoder := xml.NewDecoder(strings.NewReader(rec.Body.String()))
			var elements []string
			for {
				token, err := decoder.Token()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("metadata is not valid XML: %v", err)
				}
				if element, ok := token.(xml.StartElement); ok {
					elements = append(elements, element.Name.Local)
					attrs := map[string]string{}
					for _, attr := range element.Attr {
						attrs[attr.Name.Local] = attr.Value
						if attr.Name.Local == "injected" || strings.HasPrefix(attr.Name.Local, "on") {
							t.Errorf("injected attribute: %v", attr)
						}
					}
					switch element.Name.Local {
					case "EntityDescriptor":
						if attrs["entityID"] != scheme+"://"+host+"/auth/saml/metadata" || len(element.Attr) != 2 {
							t.Errorf("entity attributes changed: %v", element.Attr)
						}
					case "AssertionConsumerService":
						if attrs["Location"] != scheme+"://"+host+"/auth/saml/acs" || len(element.Attr) != 4 {
							t.Errorf("ACS attributes changed: %v", element.Attr)
						}
					}
				}
			}
			if got := strings.Join(elements, ","); got != "EntityDescriptor,SPSSODescriptor,NameIDFormat,AssertionConsumerService" {
				t.Fatalf("unexpected XML structure: %s", got)
			}
		})
	}
}
