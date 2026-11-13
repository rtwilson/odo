package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"example.org/odo/internal/auth/local"
	"golang.org/x/net/html"
)

// Follow the protocol exactly as the central script does (including its JSON
// POST), with a hard hop limit. Actual JavaScript execution is tested separately.
func followAutomaticHandoff(t *testing.T, b handoffBrowser, start string) (*http.Response, string) {
	t.Helper()
	next := start
	for hops := 0; hops < 20; hops++ {
		response, body := b.request(t, "GET", next, nil)
		if response.StatusCode >= 300 && response.StatusCode < 400 {
			next = resolve(t, next, response.Header.Get("Location"))
			continue
		}
		if response.StatusCode != 200 || !strings.Contains(body, `<form id="handoff"`) {
			return response, body
		}
		if strings.Contains(body, "<button") || !strings.Contains(body, handoffContinueScript) {
			t.Fatal("handoff requires manual interaction")
		}
		sum := sha256.Sum256([]byte(handoffContinueScript))
		if !strings.Contains(response.Header.Get("Content-Security-Policy"), "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'") {
			t.Fatal("automatic script not authorized by CSP")
		}
		fields := url.Values{}
		z := html.NewTokenizer(strings.NewReader(body))
		for z.Next() != html.ErrorToken {
			token := z.Token()
			if token.Data != "input" {
				continue
			}
			name, value := "", ""
			for _, attr := range token.Attr {
				if attr.Key == "name" {
					name = attr.Val
				}
				if attr.Key == "value" {
					value = attr.Val
				}
			}
			fields.Set(name, value)
		}
		req, _ := http.NewRequest("POST", "https://odo.example"+handoffConfirmPath, strings.NewReader(fields.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Origin", "https://odo.example")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		post, err := b.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var result struct {
			Next string `json:"next"`
		}
		err = json.NewDecoder(post.Body).Decode(&result)
		post.Body.Close()
		if err != nil || post.StatusCode != 200 || result.Next == "" {
			t.Fatalf("automatic POST failed: %d", post.StatusCode)
		}
		next = result.Next
	}
	t.Fatal("automatic handoff exceeded its hop bound")
	return nil, ""
}

func TestAutomaticNavigationAndRepeatedLaunches(t *testing.T) {
	d := newDeliveryHarness(t)
	start := "https://odo.example/launch?" + url.Values{"url": {d.target}}.Encode()
	for i := 0; i < 3; i++ {
		response, body := followAutomaticHandoff(t, d.handoffBrowser, start)
		if response.StatusCode != 200 || !strings.Contains(body, vendorBodyMarker) {
			t.Fatalf("launch %d failed: %d", i, response.StatusCode)
		}
		if len(d.h.state.entries) != 0 || len(d.h.state.tickets) != 0 {
			t.Fatal("successful launch retained pending proof or ticket")
		}
	}
	// Valid host grants deliver directly; no handoff Location or new grant.
	response, _ := d.request(t, "GET", "https://"+d.authority+"/private", nil)
	if response.StatusCode != 200 || response.Header.Get("Location") != "" {
		t.Fatal("valid grant restarted handoff")
	}
	d.h.state.mu.Lock()
	for key, g := range d.h.state.grants {
		g.expires = time.Now().Add(-time.Second)
		d.h.state.grants[key] = g
	}
	d.h.state.mu.Unlock()
	response, body := followAutomaticHandoff(t, d.handoffBrowser, "https://"+d.authority+"/private?x=%2F&y=a%20b")
	if response.StatusCode != 200 || !strings.Contains(body, vendorBodyMarker) || d.vendor.lastRequest().URL.RequestURI() != "/private?x=%2F&y=a%20b" {
		t.Fatal("expired grant failed automatic re-handoff or changed query")
	}
}

func TestAutomaticNavigationAfterLogin(t *testing.T) {
	d := newDeliveryHarness(t)
	central, _ := url.Parse("https://odo.example")
	d.client.Jar.SetCookies(central, []*http.Cookie{{Name: "__Host-odo_session", Path: "/", MaxAge: -1}})
	response, _ := d.launch(t)
	loginURL, _ := url.Parse(response.Header.Get("Location"))
	login, _ := d.request(t, "POST", "https://odo.example/login", url.Values{"username": {"alice"}, "password": {"correct horse battery"}, "next": {loginURL.Query().Get("next")}})
	response, body := followAutomaticHandoff(t, d.handoffBrowser, resolve(t, "https://odo.example", login.Header.Get("Location")))
	if response.StatusCode != 200 || !strings.Contains(body, vendorBodyMarker) {
		t.Fatal("login did not continue automatically")
	}
}

func TestAutomaticNavigationOpaqueRestartAndReplay(t *testing.T) {
	d := newDeliveryHarness(t)
	target := "https://" + d.authority + "/a%2Fb?q=private-search&x=%2F"
	response, _ := d.request(t, "GET", target, nil)
	start := response.Header.Get("Location")
	u, _ := url.Parse(start)
	if response.StatusCode != 303 || u.Path != handoffStartPath || len(u.Query()) != 1 || !validLaunchToken(u.Query().Get("token")) || strings.Contains(start, "private-search") {
		t.Fatal("restart exposed target")
	}
	response, _ = d.request(t, "GET", start, nil)
	if response.StatusCode != 303 {
		t.Fatal("opaque restart failed")
	}
	if replay, body := d.request(t, "GET", start, nil); replay.StatusCode != 404 || !strings.Contains(body, "start again") {
		t.Fatal("repeated navigation was not stopped clearly")
	}
	// The stored target preserves the original escaped path and query.
	var found bool
	for _, pending := range d.h.state.entries {
		if pending.target == "https://vendor.example/a%2Fb?q=private-search&x=%2F" {
			found = true
		}
	}
	if !found {
		t.Fatal("opaque restart lost destination bytes")
	}
}

func TestAutomaticNavigationMissingCookiesAndLoopBound(t *testing.T) {
	for _, kind := range []string{"all", "grant", "nonce", "central", "central nonce"} {
		t.Run(kind, func(t *testing.T) {
			d := newDeliveryHarness(t)
			if kind == "all" {
				d.client.Jar = nil
				response, _ := d.launch(t)
				loginURL, _ := url.Parse(response.Header.Get("Location"))
				login, _ := d.request(t, "POST", "https://odo.example/login", url.Values{"username": {"alice"}, "password": {"correct horse battery"}, "next": {loginURL.Query().Get("next")}})
				response, _ = d.request(t, "GET", resolve(t, "https://odo.example", login.Header.Get("Location")), nil)
				if response.StatusCode < 400 || response.Header.Get("Location") != "" {
					t.Fatal("blocked cookies restarted login")
				}
				return
			}
			ticket := d.ticket(t)
			vendor, _ := url.Parse("https://" + d.authority)
			if kind == "nonce" {
				d.client.Jar.SetCookies(vendor, []*http.Cookie{{Name: vendorNonceCookie, Path: "/", MaxAge: -1}})
				response, body := d.request(t, "GET", ticket, nil)
				if response.StatusCode != 404 || !strings.Contains(body, "Allow cookies") {
					t.Fatal("missing vendor nonce not explained")
				}
				return
			}
			if kind == "central" || kind == "central nonce" {
				// A new launch followed by preflight still cannot confirm without the
				// original central browser state.
				launched, _ := d.launch(t)
				prepared, _ := d.request(t, "GET", launched.Header.Get("Location"), nil)
				central, _ := url.Parse("https://odo.example")
				name := "__Host-odo_session"
				if kind == "central nonce" {
					name = handoffNonceCookie
				}
				d.client.Jar.SetCookies(central, []*http.Cookie{{Name: name, Path: "/", MaxAge: -1}})
				response, _ := d.request(t, "GET", prepared.Header.Get("Location"), nil)
				if response.StatusCode < 400 || response.Header.Get("Location") != "" {
					t.Fatal("missing central cookie accepted")
				}
				return
			}
			redeemed, _ := d.request(t, "GET", ticket, nil)
			d.client.Jar.SetCookies(vendor, []*http.Cookie{{Name: vendorGrantCookie, Path: "/", MaxAge: -1}})
			response, body := d.request(t, "GET", redeemed.Header.Get("Location"), nil)
			if response.StatusCode != 401 || response.Header.Get("Location") != "" || !strings.Contains(body, "Allow cookies") || d.vendor.hits.Load() != 0 {
				t.Fatal("dropped grant did not stop navigation")
			}
		})
	}
	d := newDeliveryHarness(t)
	for i := 0; i < 3; i++ {
		response, _ := d.request(t, "GET", "https://"+d.authority+"/private", nil)
		want := 303
		if i == 2 {
			want = 508
		}
		if response.StatusCode != want {
			t.Fatalf("loop attempt %d: %d", i, response.StatusCode)
		}
	}
}

func TestAutomaticNavigationRevocationAndFinishReplay(t *testing.T) {
	d := newDeliveryHarness(t)
	ticket := d.ticket(t)
	response, _ := d.request(t, "GET", ticket, nil)
	finish := response.Header.Get("Location")
	verified, _ := d.request(t, "GET", finish, nil)
	if verified.StatusCode != 303 {
		t.Fatal("cookie verification failed")
	}
	replay, _ := d.request(t, "GET", finish, nil)
	if replay.StatusCode != 404 {
		t.Fatal("verification replay accepted")
	}
	// A revoked central session must not be rescued by an existing vendor grant.
	if err := d.h.server.store.RevokeSession(local.SessionIDFromToken(d.central)); err != nil {
		t.Fatal(err)
	}
	response, body := followAutomaticHandoff(t, d.handoffBrowser, "https://"+d.authority+"/private")
	if response.StatusCode != 200 || !strings.Contains(body, `name="password"`) || d.vendor.hits.Load() != 0 {
		t.Fatal("revoked parent did not require a fresh login")
	}
}

func TestAutomaticJSONConfirmationRejectsOriginAndCSRF(t *testing.T) {
	for _, kind := range []string{"csrf", "origin", "null sibling"} {
		t.Run(kind, func(t *testing.T) {
			f := newConfirmationFixture(t)
			req := f.request("POST")
			req.Header.Set("Accept", "application/json")
			switch kind {
			case "csrf":
				req.Body = io.NopCloser(strings.NewReader(url.Values{"handoff": {f.token}, "proof": {f.proof}, "csrf": {"wrong"}}.Encode()))
			case "origin":
				req.Header.Set("Origin", "https://evil.example")
				req.Header.Set("Sec-Fetch-Site", "same-origin")
			case "null sibling":
				req.Header.Set("Origin", "null")
				req.Header.Set("Sec-Fetch-Site", "same-site")
			}
			if response := f.respond(req); response.Code != 403 || len(f.h.state.tickets) != 0 {
				t.Fatal("automatic POST bypassed origin/CSRF checks")
			}
		})
	}
}

func TestAutomaticSkipRequiresSameParentSession(t *testing.T) {
	d := newDeliveryHarness(t)
	d.finish(t, d.ticket(t))
	centralToken, _ := d.grantFor(t, d.parentUserID(t))
	centralURL, _ := url.Parse("https://odo.example")
	d.client.Jar.SetCookies(centralURL, []*http.Cookie{handoffCookie("__Host-odo_session", centralToken, time.Now().Add(time.Hour))})
	response, _ := d.launch(t)
	preflight, _ := d.request(t, "GET", response.Header.Get("Location"), nil)
	if preflight.StatusCode != 303 || !strings.HasPrefix(preflight.Header.Get("Location"), "https://odo.example"+handoffConfirmPath+"?") {
		t.Fatal("another central session reused the previous parent's grant")
	}
}

func TestAutomaticContinuationTypesCannotBeSwapped(t *testing.T) {
	b := newHandoffBrowser(t, true, true)
	token, err := b.h.server.launchContinuations.create(b.target, b.nonce, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	response, _ := b.request(t, "GET", "https://odo.example"+handoffStartPath+"?token="+token, nil)
	if response.StatusCode != 404 {
		t.Fatal("browser-bound login token was accepted as an unbound restart")
	}
	if _, found := b.h.server.launchContinuations.peek(token, b.nonce, time.Now()); !found {
		t.Fatal("wrong endpoint consumed login continuation")
	}
}
