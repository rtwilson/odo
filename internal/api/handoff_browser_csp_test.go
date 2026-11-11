package api

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// formAction returns the CSP form-action source list of a response.
func formAction(t *testing.T, response *http.Response) string {
	t.Helper()
	for _, directive := range strings.Split(response.Header.Get("Content-Security-Policy"), ";") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(directive), "form-action "); ok {
			return value
		}
	}
	t.Fatal("response has no CSP form-action")
	return ""
}

// Real browsers enforce form-action on every redirect of a form submission.
// The confirmation POST redirects to the vendor proxy host, so the page must
// allow exactly that one registered origin (verified with headless Chromium).
func TestHandoffConfirmationPageAllowsOnlyItsVendorRedirect(t *testing.T) {
	b := newHandoffBrowser(t, true, true)
	response, _ := b.launch(t)
	prepared, _ := b.request(t, "GET", response.Header.Get("Location"), nil)
	page, _ := b.request(t, "GET", prepared.Header.Get("Location"), nil)
	if page.StatusCode != 200 {
		t.Fatalf("confirmation page: %d", page.StatusCode)
	}
	if got, want := formAction(t, page), "'self' https://"+b.authority; got != want {
		t.Fatalf("form-action = %q, want %q", got, want)
	}
	for _, directive := range []string{"default-src 'none'", "script-src 'none'", "frame-ancestors 'none'", "base-uri 'none'"} {
		if !strings.Contains(page.Header.Get("Content-Security-Policy"), directive) {
			t.Fatalf("confirmation CSP lost %q", directive)
		}
	}
	// Error responses on the same endpoint do not gain the vendor origin.
	broken, _ := b.request(t, "GET", "https://odo.example"+handoffConfirmPath+"?handoff="+b.nonce+"&proof="+b.vendor, nil)
	if broken.StatusCode == 200 || formAction(t, broken) != "'self'" {
		t.Fatal("non-rendered confirmation response widened form-action")
	}
}

// A login that continues a launch redirects (within the same form submission)
// to the vendor proxy host. Only for this browser's live continuation does the
// login page allow that one registered origin.
func TestLoginPageAllowsOnlyItsContinuationVendorRedirect(t *testing.T) {
	b := newHandoffBrowser(t, true, false)
	response, _ := b.launch(t)
	loginURL := "https://odo.example" + response.Header.Get("Location")
	page, _ := b.request(t, "GET", loginURL, nil)
	if got, want := formAction(t, page), "'self' https://"+b.authority; page.StatusCode != 200 || got != want {
		t.Fatalf("continuation login form-action = %q, want %q", got, want)
	}
	// Plain login, a malformed or unknown continuation, and another browser
	// (no matching nonce cookie) keep form-action 'self'.
	parsed, _ := url.Parse(loginURL)
	next := parsed.Query().Get("next")
	other := newHandoffBrowser(t, true, false)
	get := func(client *http.Client, target string) *http.Response {
		t.Helper()
		response, err := client.Get(target)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		return response
	}
	for name, response := range map[string]*http.Response{
		"plain":         get(b.client, "https://odo.example/login"),
		"unknown":       get(b.client, "https://odo.example/login?next="+url.QueryEscape(launchContinuePath+"?token="+b.vendor)),
		"malformed":     get(b.client, "https://odo.example/login?next="+url.QueryEscape(next+"&x=1")),
		"other browser": get(other.client, loginURL),
	} {
		if got := formAction(t, response); response.StatusCode != 200 || got != "'self'" {
			t.Fatalf("%s login page widened form-action to %q (%d)", name, got, response.StatusCode)
		}
	}
	// The continuation was only peeked: it still completes.
	login, _ := b.request(t, "POST", "https://odo.example/login", url.Values{"username": {"alice"}, "password": {"correct horse battery"}, "next": {next}})
	continued, _ := b.request(t, "GET", "https://odo.example"+login.Header.Get("Location"), nil)
	if continued.StatusCode != 303 || !strings.Contains(continued.Header.Get("Location"), handoffVendorPath+"?handoff=") {
		t.Fatal("peeked continuation no longer completes")
	}
}

func TestLaunchContinuationPeekDoesNotConsume(t *testing.T) {
	s := newLaunchContinuations()
	now := time.Now()
	token, err := s.create("https://vendor.example/a", strings.Repeat("A", 43), now)
	if err != nil {
		t.Fatal(err)
	}
	if target, ok := s.peek(token, strings.Repeat("B", 43), now); ok || target != "" {
		t.Fatal("peek ignored the browser nonce")
	}
	if target, ok := s.peek(token, strings.Repeat("A", 43), now.Add(launchContinuationTTL)); ok || target != "" {
		t.Fatal("peek returned an expired continuation")
	}
	for range 2 {
		if target, ok := s.peek(token, strings.Repeat("A", 43), now); !ok || target != "https://vendor.example/a" {
			t.Fatal("peek failed")
		}
	}
	if target, ok := s.consume(token, strings.Repeat("A", 43), now); !ok || target != "https://vendor.example/a" {
		t.Fatal("peek consumed the continuation")
	}
}
