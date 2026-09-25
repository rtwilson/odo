package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func recordLoginFailure(t *testing.T, limiter *loginThrottle, account, source string, now time.Time) bool {
	t.Helper()
	attempt, reason, _ := limiter.begin(account, source, now)
	if attempt == nil {
		t.Fatalf("unexpected throttle: %s", reason)
	}
	return limiter.finish(attempt, true, false, now)
}

func TestLoginThrottleAccountWindowAndCooldown(t *testing.T) {
	limiter := newLoginThrottle()
	now := time.Unix(1700000000, 0)
	for i := 0; i < loginAccountLimit; i++ {
		excessive := recordLoginFailure(t, limiter, " Alice ", fmt.Sprint(i), now)
		if excessive != (i == loginAccountLimit-1) {
			t.Fatalf("threshold event on failure %d: %v", i+1, excessive)
		}
	}
	for _, offset := range []time.Duration{0, 30 * time.Second, 59 * time.Second} {
		attempt, reason, audit := limiter.begin("ALICE", "another-source", now.Add(offset))
		if attempt != nil || reason != "account" || audit != (offset == 0) {
			t.Fatalf("unexpected throttle result at %v: %v %s %v", offset, attempt, reason, audit)
		}
	}
	// Rejected requests did not extend the original one-minute cooldown.
	probe, _, _ := limiter.begin("alice", "another-source", now.Add(loginLockout))
	if probe == nil {
		t.Fatal("expected a probe when cooldown ends")
	}
	if attempt, _, _ := limiter.begin("alice", "different-source", now.Add(loginLockout)); attempt != nil {
		t.Fatal("allowed concurrent post-cooldown probe")
	}
	if limiter.finish(probe, true, false, now.Add(loginLockout)) {
		t.Fatal("repeated failure emitted another threshold-crossing event")
	}
	if attempt, _, _ := limiter.begin("alice", "different-source", now.Add(loginLockout+time.Second)); attempt != nil {
		t.Fatal("failed probe did not start a new bounded cooldown")
	}
	// The fixed window is not extended by repeated failures or rejected attempts.
	for i := 0; i < loginAccountLimit; i++ {
		recordLoginFailure(t, limiter, "alice", fmt.Sprint(i), now.Add(loginFailureWindow))
	}
}

func TestLoginThrottleSourceAndSuccessReset(t *testing.T) {
	limiter := newLoginThrottle()
	now := time.Unix(1700000000, 0)
	for i := 0; i < 4; i++ {
		recordLoginFailure(t, limiter, "alice", "shared-source", now)
	}
	attempt, _, _ := limiter.begin("ALICE", "shared-source", now)
	if attempt == nil {
		t.Fatal("success attempt was unexpectedly blocked")
	}
	limiter.finish(attempt, false, true, now)
	// Four new failures are allowed because success cleared the account state.
	for i := 0; i < 4; i++ {
		recordLoginFailure(t, limiter, "alice", "shared-source", now)
	}
	// Success did not clear the source's original four failures.
	for i := 8; i < loginSourceLimit; i++ {
		recordLoginFailure(t, limiter, fmt.Sprint(i), "shared-source", now)
	}
	if attempt, reason, _ := limiter.begin("new-account", "shared-source", now); attempt != nil || reason != "source" {
		t.Fatalf("expected source throttle, got %v %s", attempt, reason)
	}
	other, _, _ := limiter.begin("new-account", "other-source", now)
	if other == nil {
		t.Fatal("independent source was blocked")
	}
	limiter.finish(other, false, false, now)
	for i := 0; i < loginSourceLimit; i++ {
		recordLoginFailure(t, limiter, fmt.Sprint(i), "shared-source", now.Add(loginFailureWindow))
	}
}

func TestLoginThrottleCapacityAndExpiry(t *testing.T) {
	limiter := newLoginThrottle()
	now := time.Unix(1700000000, 0)
	for i := 0; i < loginAccountLimit; i++ {
		recordLoginFailure(t, limiter, "protected", "protected-source", now)
	}
	for i := 1; i < loginMaxKeys/2; i++ {
		recordLoginFailure(t, limiter, fmt.Sprint(i), fmt.Sprint(i), now)
	}
	if len(limiter.entries) != loginMaxKeys {
		t.Fatalf("expected %d entries, got %d", loginMaxKeys, len(limiter.entries))
	}
	for i := 0; i < 10; i++ {
		attempt, reason, audit := limiter.begin("new", "new", now)
		if attempt != nil || reason != "capacity" || audit != (i == 0) {
			t.Fatalf("unexpected capacity response: %v %s %v", attempt, reason, audit)
		}
	}
	if attempt, reason, _ := limiter.begin("protected", "protected-source", now); attempt != nil || reason != "account" {
		t.Fatal("capacity pressure evicted an active account lockout")
	}
	attempt, _, _ := limiter.begin("new", "new", now.Add(loginFailureWindow))
	if attempt == nil || len(limiter.entries) != 2 {
		t.Fatalf("expired entries not pruned: %d entries", len(limiter.entries))
	}
	limiter.finish(attempt, false, false, now.Add(loginFailureWindow))
	if len(limiter.entries) != 0 {
		t.Fatal("internal-error outcome leaked reservations or unused keys")
	}
}

func TestLoginThrottleConcurrentReservations(t *testing.T) {
	for _, dimension := range []string{"account", "source"} {
		t.Run(dimension, func(t *testing.T) {
			limiter := newLoginThrottle()
			now := time.Unix(1700000000, 0)
			attempts := make(chan *loginAttempt, 100)
			var wg sync.WaitGroup
			for i := 0; i < 100; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					account, source := "shared", fmt.Sprint(i)
					if dimension == "source" {
						account, source = source, account
					}
					if attempt, _, _ := limiter.begin(account, source, now); attempt != nil {
						attempts <- attempt
					}
				}(i)
			}
			wg.Wait()
			close(attempts)
			want := loginAccountLimit
			if dimension == "source" {
				want = loginSourceLimit
			}
			if len(attempts) != want {
				t.Fatalf("expected %d admitted attempts, got %d", want, len(attempts))
			}
			for attempt := range attempts {
				wg.Add(1)
				go func(a *loginAttempt) {
					defer wg.Done()
					limiter.finish(a, true, false, now)
				}(attempt)
			}
			wg.Wait()
			if attempt, reason, _ := limiter.begin("shared", "shared", now); attempt != nil || reason != dimension {
				t.Fatalf("expected %s throttle after concurrent failures, got %s", dimension, reason)
			}
		})
	}
}

func TestLoginSourceKey(t *testing.T) {
	for remote, want := range map[string]string{
		"192.0.2.1:1234":          "192.0.2.1",
		"192.0.2.1:5678":          "192.0.2.1",
		"[::ffff:192.0.2.1]:1234": "192.0.2.1",
		"[2001:0db8::1]:1234":     "2001:db8::1",
		"invalid":                 "unknown", "": "unknown",
	} {
		if got := loginSourceKey(remote); got != want {
			t.Errorf("source %q: got %q, want %q", remote, got, want)
		}
	}
}

func postThrottledLogin(handler http.Handler, username, password, remote, forwarded string) *httptest.ResponseRecorder {
	form := url.Values{"username": {username}, "password": {password}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.RemoteAddr = remote
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-For", forwarded)
	req.Header.Set("User-Agent", "private-user-agent")
	req.Header.Set("Cookie", "private-cookie=secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestLoginThrottleGenericResponsesAndAuditPrivacy(t *testing.T) {
	for _, status := range []string{"active", "disabled", "locked", "nonexistent"} {
		t.Run(status, func(t *testing.T) {
			server := newTestServer(t, "secret")
			if status != "nonexistent" {
				user := createLocalTestUser(t, server, "private-account", "private-password")
				if _, found, err := server.store.SetUserStatus(user.ID, status); err != nil || !found {
					t.Fatalf("set status: %v", err)
				}
			}
			handler := server.Routes()
			for i := 0; i < loginAccountLimit+2; i++ {
				password := "wrong-password"
				if status == "disabled" || status == "locked" || i >= loginAccountLimit {
					password = "private-password"
				}
				rec := postThrottledLogin(handler, "private-account", password, "192.0.2.42:1234", "203.0.113.42")
				want := http.StatusUnauthorized
				if i >= loginAccountLimit {
					want = http.StatusTooManyRequests
				}
				if rec.Code != want || rec.Body.String() != "{\"error\":\"invalid username or password\"}\n" || len(rec.Result().Cookies()) != 0 {
					t.Fatalf("attempt %d: status %d, body %s, cookies %v", i, rec.Code, rec.Body.String(), rec.Result().Cookies())
				}
			}
			events, err := server.store.ListAuditEvents(100)
			if err != nil {
				t.Fatal(err)
			}
			counts := map[string]int{}
			for _, event := range events {
				counts[event.Event]++
				if !strings.HasPrefix(event.Event, "login_") {
					continue
				}
				for _, secret := range []string{"private-account", "private-password", "wrong-password", "192.0.2.42", "203.0.113.42", "private-user-agent", "private-cookie"} {
					if strings.Contains(event.Detail, secret) {
						t.Errorf("audit %s contains %q", event.Event, secret)
					}
				}
			}
			if counts["login_failed"] != 5 || counts["login_failures_excessive"] != 1 || counts["login_throttled"] != 1 {
				t.Fatalf("unexpected audit events: %v", counts)
			}
		})
	}
}

func TestLoginThrottleIgnoresForwardedSource(t *testing.T) {
	for _, trusted := range []string{"false", "true"} {
		t.Run(trusted, func(t *testing.T) {
			t.Setenv("APP_TRUST_PROXY_HEADERS", trusted)
			server := newTestServer(t, "secret")
			handler := server.Routes()
			for i := 0; i < loginSourceLimit+1; i++ {
				rec := postThrottledLogin(handler, fmt.Sprint(i), "bad", fmt.Sprintf("192.0.2.1:%d", 1000+i), fmt.Sprintf("203.0.113.%d", i+1))
				want := http.StatusUnauthorized
				if i == loginSourceLimit {
					want = http.StatusTooManyRequests
				}
				if rec.Code != want {
					t.Fatalf("attempt %d returned %d, want %d", i, rec.Code, want)
				}
			}
			rec := postThrottledLogin(handler, "new", "bad", "192.0.2.2:1234", "203.0.113.1")
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("different connection peer blocked: %d", rec.Code)
			}
		})
	}
}

func TestLoginSuccessClearsAccountFailures(t *testing.T) {
	server := newTestServer(t, "secret")
	createLocalTestUser(t, server, "alice", "correct-password")
	handler := server.Routes()
	for i := 0; i < 4; i++ {
		rec := postThrottledLogin(handler, " Alice ", "bad", "192.0.2.1:1234", "")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d returned %d", i, rec.Code)
		}
	}
	rec := postThrottledLogin(handler, "alice", "correct-password", "192.0.2.1:1234", "")
	if rec.Code != http.StatusFound || findCookie(rec.Result().Cookies(), browserSessionCookieName) == nil {
		t.Fatalf("successful login failed: %d %s", rec.Code, rec.Body.String())
	}
	for i := 0; i < loginAccountLimit; i++ {
		rec = postThrottledLogin(handler, "ALICE", "bad", "192.0.2.1:1234", "")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("account state not cleared: failure %d returned %d", i, rec.Code)
		}
	}
	rec = postThrottledLogin(handler, "alice", "correct-password", "192.0.2.2:1234", "")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("normalization or account throttle failed: %d", rec.Code)
	}
}
