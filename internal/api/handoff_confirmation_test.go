package api

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"example.org/odo/internal/accesslog"
	"example.org/odo/internal/auth/local"
	"example.org/odo/internal/resources"
)

type confirmationFixture struct {
	securityFixture
	token, proof string
	logs         *bytes.Buffer
	handler      http.Handler
}

func newConfirmationFixture(t *testing.T) confirmationFixture {
	t.Helper()
	f := newSecurityFixture(t)
	token, err := f.h.begin(context.Background(), f.central, f.authority, f.target, f.nonce, f.now)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := f.h.preflight(token, f.authority, f.vendor, f.now)
	if err != nil {
		t.Fatal(err)
	}
	logs := new(bytes.Buffer)
	f.h.server.logger = slog.New(slog.NewJSONHandler(logs, nil))
	f.h.server.accessLog, _ = accesslog.New(accesslog.FormatPrivacy, logs)
	f.h.server.httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("confirmation fetched upstream content")
		return nil, io.ErrUnexpectedEOF
	})}
	return confirmationFixture{securityFixture: f, token: token, proof: proof, logs: logs, handler: f.h.centralConfirmationHandler()}
}

func (f confirmationFixture) request(method string) *http.Request {
	fields := url.Values{"handoff": {f.token}, "proof": {f.proof}}
	target := handoffConfirmPath
	var body io.Reader
	if method == "POST" {
		fields.Set("csrf", csrfTokenForSessionToken(f.central))
		body = strings.NewReader(fields.Encode())
	} else {
		target += "?" + fields.Encode()
	}
	req := httptest.NewRequest(method, target, body)
	req.Host = "odo.example"
	req.AddCookie(&http.Cookie{Name: "__Host-odo_session", Value: f.central})
	req.AddCookie(&http.Cookie{Name: handoffNonceCookie, Value: f.nonce})
	if method == "POST" {
		req.Header.Set("Origin", "https://odo.example")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("X-Request-ID", "confirmation-test-123")
	return req
}

func (f confirmationFixture) respond(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

func assertConfirmationHeaders(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Referrer-Policy") != "no-referrer" || rec.Header().Get("X-Frame-Options") != "DENY" || rec.Header().Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "script-src 'none'") || len(rec.Result().Cookies()) != 0 {
		t.Fatal("missing control security headers or unexpected cookie issuance")
	}
}

func TestHandoffConfirmationGETThenPOST(t *testing.T) {
	f := newConfirmationFixture(t)
	before := f.h.state.entries[local.HashToken(f.token)]
	if _, err := f.control.Exec(`CREATE TRIGGER prevent_confirmation_touch BEFORE UPDATE OF last_seen_at ON sessions BEGIN SELECT RAISE(ABORT,'unexpected session touch'); END`); err != nil {
		t.Fatal(err)
	}
	rec := f.respond(f.request("GET"))
	assertConfirmationHeaders(t, rec)
	if rec.Code != 200 || rec.Header().Get("Location") != "" || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatal("GET did not render confirmation")
	}
	for _, expected := range []string{`<h1>Continue to vendor.example</h1>`, `method="post" action="/launch/handoff/confirm"`, `name="csrf" value="` + csrfTokenForSessionToken(f.central) + `"`, `name="proof" value="` + f.proof + `"`, `<button type="submit">Continue</button>`} {
		if !strings.Contains(rec.Body.String(), expected) {
			t.Fatal("confirmation form missing expected browser binding")
		}
	}
	for _, private := range []string{f.central, f.nonce, f.vendor, f.target, "private-search", "<script"} {
		if strings.Contains(rec.Body.String(), private) {
			t.Fatal("page disclosed private data or included script")
		}
	}
	if f.h.state.entries[local.HashToken(f.token)] != before || len(f.h.state.tickets) != 0 {
		t.Fatal("GET consumed or renewed live state")
	}
	post := f.request("POST")
	post.Header.Set("X-Forwarded-Host", "evil.example")
	rec = f.respond(post)
	assertConfirmationHeaders(t, rec)
	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || rec.Code != 303 || location.Scheme != "https" || location.Host != f.authority || location.Path != "/.well-known/odo/redeem" || len(location.Query()) != 1 || !validLaunchToken(location.Query().Get("ticket")) {
		t.Fatal("POST did not redirect to the bound vendor redemption endpoint")
	}
	if len(f.h.state.entries) != 0 || len(f.h.state.tickets) != 1 || len(f.h.state.grants) != 0 {
		t.Fatal("POST state transition incorrect")
	}
	for _, private := range []string{f.central, f.nonce, f.vendor, f.target, f.proof, csrfTokenForSessionToken(f.central)} {
		if strings.Contains(location.String(), private) {
			t.Fatal("redirect disclosed private browser data")
		}
	}
	if replay := f.respond(f.request("POST")); replay.Code != 404 || replay.Header().Get("Location") != "" {
		t.Fatal("POST replay succeeded")
	}
}

func TestHandoffConfirmationRejectsOriginAndCSRF(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*http.Request)
	}{
		{"missing origin", func(r *http.Request) { r.Header.Del("Origin") }},
		{"sibling origin", func(r *http.Request) { r.Header.Set("Origin", "https://sibling.proxy.example") }},
		{"null origin", func(r *http.Request) { r.Header.Set("Origin", "null") }},
		{"duplicate origin", func(r *http.Request) { r.Header.Add("Origin", "https://odo.example") }},
		{"missing origin with bearer", func(r *http.Request) { r.Header.Del("Origin"); r.Header.Set("Authorization", "Bearer secret") }},
		{"missing csrf", nil},
		{"wrong csrf", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newConfirmationFixture(t)
			req := f.request("POST")
			if tc.name == "missing csrf" || tc.name == "wrong csrf" {
				fields := url.Values{"handoff": {f.token}, "proof": {f.proof}}
				if tc.name == "wrong csrf" {
					fields.Set("csrf", "wrong-csrf")
				}
				req.Body = io.NopCloser(strings.NewReader(fields.Encode()))
				req.Header.Set("X-Odo-CSRF", csrfTokenForSessionToken(f.central))
			} else {
				tc.change(req)
			}
			before := f.h.state.entries[local.HashToken(f.token)]
			rec := f.respond(req)
			assertConfirmationHeaders(t, rec)
			if rec.Code != 403 || rec.Header().Get("Location") != "" || len(f.h.state.tickets) != 0 || f.h.state.entries[local.HashToken(f.token)] != before {
				t.Fatal("Origin/CSRF failure changed state or redirected")
			}
		})
	}
}

func TestHandoffConfirmationStrictInputs(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		change func(*http.Request)
	}{
		{"HEAD", 405, func(r *http.Request) { r.Method = "HEAD" }},
		{"PUT", 405, func(r *http.Request) { r.Method = "PUT" }},
		{"wrong host", 421, func(r *http.Request) { r.Host = "evil.example"; r.Header.Set("X-Forwarded-Host", "odo.example") }},
		{"vendor host", 421, func(r *http.Request) { r.Host = "h-abc.proxy.example" }},
		{"absolute authority conflict", 421, func(r *http.Request) { r.URL.Host = "evil.example"; r.URL.Scheme = "https" }},
		{"encoded path", 404, func(r *http.Request) { r.URL.RawPath = "/launch/handoff/%63onfirm" }},
		{"wrong path", 404, func(r *http.Request) { r.URL.Path = "/admin" }},
		{"query on POST", 400, func(r *http.Request) { r.URL.RawQuery = "next=https://evil.example/" }},
		{"empty query on POST", 400, func(r *http.Request) { r.URL.ForceQuery = true }},
		{"duplicate handoff", 400, func(r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(strings.NewReader(string(body) + "&handoff=duplicate"))
		}},
		{"unknown field", 400, func(r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(strings.NewReader(string(body) + "&return_to=https://evil.example/"))
		}},
		{"bad encoding", 400, func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("handoff=%ZZ")) }},
		{"oversized body", 413, func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", maxConfirmationBody+1)))
		}},
		{"JSON", 415, func(r *http.Request) { r.Header.Set("Content-Type", "application/json") }},
		{"duplicate content type", 415, func(r *http.Request) { r.Header.Add("Content-Type", "application/x-www-form-urlencoded") }},
		{"compressed", 415, func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }},
		{"missing session", 401, func(r *http.Request) { r.Header.Del("Cookie") }},
		{"legacy session", 401, func(r *http.Request) {
			r.Header.Set("Cookie", strings.ReplaceAll(r.Header.Get("Cookie"), "__Host-odo_session", "odo_session"))
		}},
		{"duplicate session", 401, func(r *http.Request) { r.Header.Add("Cookie", "__Host-odo_session=duplicate") }},
		{"legacy nonce", 404, func(r *http.Request) {
			r.Header.Set("Cookie", strings.ReplaceAll(r.Header.Get("Cookie"), handoffNonceCookie, "odo_handoff_nonce"))
		}},
		{"duplicate nonce", 404, func(r *http.Request) { r.Header.Add("Cookie", handoffNonceCookie+"=duplicate") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newConfirmationFixture(t)
			req := f.request("POST")
			tc.change(req)
			before := f.h.state.entries[local.HashToken(f.token)]
			rec := f.respond(req)
			assertConfirmationHeaders(t, rec)
			if rec.Code != tc.status || rec.Header().Get("Location") != "" || len(f.h.state.tickets) != 0 || f.h.state.entries[local.HashToken(f.token)] != before {
				t.Fatalf("unsafe input response: got %d want %d", rec.Code, tc.status)
			}
		})
	}
}

func TestHandoffConfirmationLiveFailures(t *testing.T) {
	for _, kind := range []string{"database", "resource", "revocation", "expiry", "capacity"} {
		t.Run(kind, func(t *testing.T) {
			f := newConfirmationFixture(t)
			if page := f.respond(f.request("GET")); page.Code != 200 {
				t.Fatal("initial confirmation page failed")
			}
			want := 404
			switch kind {
			case "database":
				want = 500
				if _, err := f.control.Exec(`ALTER TABLE sessions RENAME TO unavailable_sessions`); err != nil {
					t.Fatal(err)
				}
			case "resource":
				want = 403
				if err := f.h.server.store.UpsertResource(resources.Resource{ID: "vendor", Name: "Vendor", Status: "disabled", Domains: []resources.DomainRule{{Host: "vendor.example"}}}); err != nil {
					t.Fatal(err)
				}
			case "revocation":
				if err := f.h.server.store.RevokeSession(local.SessionIDFromToken(f.central)); err != nil {
					t.Fatal(err)
				}
			case "expiry":
				p := f.h.state.entries[local.HashToken(f.token)]
				p.returnProofExpires = time.Now().Add(-time.Second)
				f.h.state.entries[local.HashToken(f.token)] = p
			case "capacity":
				want = 503
				for i := 0; i < maxHandoffTickets; i++ {
					grantTicketFixture(t, f.h.state, "other", f.now, f.now.Add(time.Hour))
				}
			}
			before := f.h.state.entries[local.HashToken(f.token)]
			rec := f.respond(f.request("POST"))
			assertConfirmationHeaders(t, rec)
			if rec.Code != want || rec.Header().Get("Location") != "" || len(f.h.state.grants) != 0 {
				t.Fatalf("failure response: got %d want %d", rec.Code, want)
			}
			if (kind == "database" || kind == "resource" || kind == "capacity") && f.h.state.entries[local.HashToken(f.token)] != before {
				t.Fatal("retryable failure changed pending state")
			}
			for _, secret := range []string{f.central, f.nonce, f.proof, f.target, "private-search", "unavailable_sessions"} {
				if strings.Contains(rec.Body.String(), secret) {
					t.Fatal("failure disclosed sensitive details")
				}
			}
		})
	}
}

func TestHandoffConfirmationPrivacyAndRuntimeIsolation(t *testing.T) {
	f := newConfirmationFixture(t)
	req := f.request("GET")
	req.URL.RawQuery += "&search=private-search"
	f.respond(req)
	if _, err := f.control.Exec(`ALTER TABLE sessions RENAME TO unavailable_sessions`); err != nil {
		t.Fatal(err)
	}
	if failed := f.respond(f.request("POST")); failed.Code != 500 {
		t.Fatal("database failure did not reach safe error helper")
	}
	if _, err := f.control.Exec(`ALTER TABLE unavailable_sessions RENAME TO sessions`); err != nil {
		t.Fatal(err)
	}
	rec := f.respond(f.request("POST"))
	ticketURL := rec.Header().Get("Location")
	ticket, _ := url.Parse(ticketURL)
	for _, secret := range []string{f.token, f.proof, f.central, f.nonce, f.vendor, csrfTokenForSessionToken(f.central), f.target, "private-search", ticketURL, ticket.Query().Get("ticket")} {
		if secret != "" && strings.Contains(f.logs.String(), secret) {
			t.Fatal("confirmation logs disclosed sensitive data")
		}
	}
	if !strings.Contains(f.logs.String(), "confirmation-test-123") || !strings.Contains(f.logs.String(), "handoff_confirmation") {
		t.Fatal("missing privacy-safe request correlation")
	}
	// A fresh fixture proves the running server has no confirmation registration.
	live := newConfirmationFixture(t)
	req = live.request("POST")
	out := httptest.NewRecorder()
	live.h.server.Routes().ServeHTTP(out, req)
	if out.Code == 303 || len(live.h.state.tickets) != 0 {
		t.Fatal("runtime exposed unfinished confirmation flow")
	}
}

func TestHandoffConfirmationConcurrentPOST(t *testing.T) {
	f := newConfirmationFixture(t)
	f.h.server.accessLog, _ = accesslog.New(accesslog.FormatPrivacy, io.Discard)
	f.h.server.logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if f.respond(f.request("POST")).Code == 303 {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 || len(f.h.state.tickets) != 1 || len(f.h.state.grants) != 0 {
		t.Fatal("concurrent POST created multiple tickets or grant state")
	}
}

func TestHandoffConfirmationGETRejectsSwappedBindings(t *testing.T) {
	for _, kind := range []string{"proof", "handoff", "session", "nonce", "duplicate query", "oversized query"} {
		t.Run(kind, func(t *testing.T) {
			f := newConfirmationFixture(t)
			req := f.request("GET")
			want := 404
			fields := req.URL.Query()
			switch kind {
			case "proof":
				fields.Set("proof", f.vendor)
				req.URL.RawQuery = fields.Encode()
			case "handoff":
				fields.Set("handoff", f.vendor)
				req.URL.RawQuery = fields.Encode()
			case "session":
				req.Header.Set("Cookie", strings.ReplaceAll(req.Header.Get("Cookie"), f.central, f.central[:len(f.central)-2]+"xx"))
			case "nonce":
				req.Header.Set("Cookie", strings.ReplaceAll(req.Header.Get("Cookie"), f.nonce, f.vendor))
			case "duplicate query":
				want = 400
				req.URL.RawQuery += "&handoff=" + f.token
			case "oversized query":
				want = 400
				req.URL.RawQuery = strings.Repeat("x", 1025)
			}
			before := f.h.state.entries[local.HashToken(f.token)]
			rec := f.respond(req)
			assertConfirmationHeaders(t, rec)
			if rec.Code != want || f.h.state.entries[local.HashToken(f.token)] != before || len(f.h.state.tickets) != 0 {
				t.Fatalf("GET binding response: got %d want %d", rec.Code, want)
			}
		})
	}
}
