package api

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// navigate issues a GET with the fetch metadata a browser sends for a
// top-level navigation from a page whose relation to the target is site.
func (b handoffBrowser) navigate(t *testing.T, target, site string) *http.Response {
	t.Helper()
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	if site != "" {
		req.Header.Set("Sec-Fetch-Site", site)
	}
	response, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	return response
}

func (b handoffBrowser) confirmationFor(t *testing.T, site string) *http.Response {
	t.Helper()
	launched := b.navigate(t, "https://odo.example/launch?"+url.Values{"url": {b.target}}.Encode(), site)
	if launched.StatusCode != http.StatusSeeOther {
		t.Fatalf("launch status: %d", launched.StatusCode)
	}
	prepared := b.navigate(t, launched.Header.Get("Location"), "same-site")
	if prepared.StatusCode != http.StatusSeeOther {
		t.Fatalf("preflight status: %d", prepared.StatusCode)
	}
	return b.navigate(t, prepared.Header.Get("Location"), "same-site")
}

func TestSameOriginLaunchSkipsConfirmationForm(t *testing.T) {
	b := newHandoffBrowser(t, true, true)
	confirmed := b.confirmationFor(t, "same-origin")
	location := confirmed.Header.Get("Location")
	if confirmed.StatusCode != http.StatusSeeOther || !strings.HasPrefix(location, "https://"+b.authority+handoffVendorPath+"?ticket=") {
		t.Fatalf("same-origin launch was not confirmed directly: %d %q", confirmed.StatusCode, location)
	}
	b.finish(t, location)
}

func TestOtherLaunchOriginsKeepConfirmationForm(t *testing.T) {
	// Proxy hosts are same-site with central, so "same-site" covers vendor
	// pages and vendor scripts; they must not skip the central action.
	for _, site := range []string{"cross-site", "same-site", "none", ""} {
		t.Run(site, func(t *testing.T) {
			b := newHandoffBrowser(t, true, true)
			page := b.confirmationFor(t, site)
			if page.StatusCode != http.StatusOK || page.Header.Get("Location") != "" {
				t.Fatalf("launch from %q skipped confirmation: %d", site, page.StatusCode)
			}
		})
	}
}
