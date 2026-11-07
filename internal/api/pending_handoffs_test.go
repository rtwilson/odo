package api

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"example.org/odo/internal/auth/local"
	"example.org/odo/internal/proxy"
)

func pendingHandoffFixture(t *testing.T) (handoffBinding, string, string, time.Time) {
	t.Helper()
	nonce, err := local.NewToken("", 32)
	if err != nil {
		t.Fatal(err)
	}
	host, label, err := proxy.RegistryHostname("vendor.example", "login.library.example", "proxy.library.example")
	if err != nil {
		t.Fatal(err)
	}
	return handoffBinding{parentSessionID: "sess_parent", parentSessionHash: local.HashToken("parent-token"), hostname: host, label: label, proxyAuthority: label + ".proxy.library.example"},
		"https://vendor.example/private?ticket=vendor-ticket&url=vendor-value&search=private-search", nonce, time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
}

func TestPendingHandoffBindingsAndPrivateStorage(t *testing.T) {
	binding, target, nonce, now := pendingHandoffFixture(t)
	s := newPendingHandoffs()
	token, err := s.create(binding, target, nonce, now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if !validLaunchToken(token) {
		t.Fatal("invalid token format")
	}
	if _, found := s.entries[token]; found {
		t.Fatal("plaintext handoff ID stored as key")
	}
	stored := s.entries[local.HashToken(token)]
	if stored.centralNonceHash != local.HashToken(nonce) || stored.centralNonceHash == nonce {
		t.Fatal("raw browser nonce stored")
	}
	for _, alter := range []func(*handoffBinding){
		func(b *handoffBinding) { b.parentSessionID = "other-session" },
		func(b *handoffBinding) { b.parentSessionHash = local.HashToken("other-session-token") },
		func(b *handoffBinding) { b.hostname = "other.example" },
		func(b *handoffBinding) { b.label = "other-label" },
		func(b *handoffBinding) { b.proxyAuthority = b.label + ".other-proxy.example" },
	} {
		wrong := binding
		alter(&wrong)
		if got, ok := s.inspect(token, wrong, nonce, now); ok || got != (pendingHandoff{}) {
			t.Fatal("wrong binding exposed state")
		}
	}
	otherNonce, err := local.NewToken("", 32)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{"", "malformed", otherNonce} {
		if got, ok := s.inspect(token, binding, candidate, now); ok || got != (pendingHandoff{}) {
			t.Fatal("wrong nonce exposed state")
		}
		if got, ok := s.inspect(candidate, binding, nonce, now); ok || got != (pendingHandoff{}) {
			t.Fatal("wrong token exposed state")
		}
	}
	got, ok := s.inspect(token, binding, nonce, now)
	if !ok || got.target != target || got.expires != now.Add(pendingHandoffTTL) {
		t.Fatal("legitimate state lost after mismatches")
	}
	got.target = "changed copy"
	if again, ok := s.inspect(token, binding, nonce, now); !ok || again.target != target {
		t.Fatal("inspection consumed or exposed mutable state")
	}
	if _, ok := newPendingHandoffs().inspect(token, binding, nonce, now); ok {
		t.Fatal("new process store recovered old state")
	}
}

func TestPendingHandoffExactExpiryAndParentLimit(t *testing.T) {
	for _, ttl := range []time.Duration{pendingHandoffTTL, time.Minute} {
		t.Run(ttl.String(), func(t *testing.T) {
			binding, target, nonce, now := pendingHandoffFixture(t)
			s := newPendingHandoffs()
			token, err := s.create(binding, target, nonce, now.Add(ttl), now)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := s.inspect(token, binding, nonce, now.Add(ttl-time.Nanosecond)); !ok {
				t.Fatal("expired early")
			}
			if got, ok := s.inspect(token, binding, nonce, now.Add(ttl)); ok || got != (pendingHandoff{}) {
				t.Fatal("accepted exact expiry")
			}
			if len(s.entries) != 0 {
				t.Fatal("expired target retained")
			}
		})
	}
}

func TestPendingHandoffCapacityAndCleanup(t *testing.T) {
	binding, target, nonce, now := pendingHandoffFixture(t)
	s := newPendingHandoffs()
	var first string
	for i := 0; i < maxPendingHandoffs; i++ {
		token, err := s.create(binding, target, nonce, now.Add(time.Hour), now)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = token
		}
	}
	if token, err := s.create(binding, target, nonce, now.Add(time.Hour), now); token != "" || !errors.Is(err, errPendingHandoffsFull) {
		t.Fatal("capacity not enforced")
	}
	if _, ok := s.inspect(first, binding, nonce, now); !ok {
		t.Fatal("full store evicted live state")
	}
	if _, err := s.create(binding, target, nonce, now.Add(time.Hour), now.Add(pendingHandoffTTL)); err != nil {
		t.Fatal("expired entries did not free capacity")
	}
	if len(s.entries) != 1 {
		t.Fatal("create did not clean expired targets")
	}
	// Even a malformed inspection cleans expired unrelated records.
	s.inspect("invalid", binding, nonce, now.Add(2*pendingHandoffTTL))
	if len(s.entries) != 0 {
		t.Fatal("inspect did not clean unrelated expired state")
	}
	if _, err := s.create(binding, target, nonce, now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	s.cleanup(now.Add(pendingHandoffTTL))
	if len(s.entries) != 0 {
		t.Fatal("explicit cleanup retained expired state")
	}
}

func TestPendingHandoffParentRemoval(t *testing.T) {
	binding, target, nonce, now := pendingHandoffFixture(t)
	s := newPendingHandoffs()
	first, err := s.create(binding, target, nonce, now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	changedHash := binding
	changedHash.parentSessionHash = local.HashToken("replacement-parent-token")
	second, err := s.create(changedHash, target, nonce, now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	other := binding
	other.parentSessionID = "other-parent"
	third, err := s.create(other, target, nonce, now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	s.removeParent(binding.parentSessionID, now)
	if _, ok := s.inspect(first, binding, nonce, now); ok {
		t.Fatal("parent state retained")
	}
	if _, ok := s.inspect(second, changedHash, nonce, now); ok {
		t.Fatal("older hash binding retained")
	}
	if _, ok := s.inspect(third, other, nonce, now); !ok {
		t.Fatal("unrelated parent's state removed")
	}
	s.removeParent(binding.parentSessionID, now)
	if len(s.entries) != 1 {
		t.Fatal("parent cleanup not idempotent")
	}
}

func TestPendingHandoffRejectsInvalidOrUnboundedState(t *testing.T) {
	binding, target, nonce, now := pendingHandoffFixture(t)
	for _, invalid := range []struct {
		name   string
		change func(*handoffBinding, *string, *string, *time.Time)
	}{
		{"missing session", func(b *handoffBinding, _ *string, _ *string, _ *time.Time) { b.parentSessionID = "" }},
		{"oversized session", func(b *handoffBinding, _ *string, _ *string, _ *time.Time) {
			b.parentSessionID = strings.Repeat("x", maxHandoffSessionFieldBytes+1)
		}},
		{"missing session hash", func(b *handoffBinding, _ *string, _ *string, _ *time.Time) { b.parentSessionHash = "" }},
		{"oversized session hash", func(b *handoffBinding, _ *string, _ *string, _ *time.Time) {
			b.parentSessionHash = strings.Repeat("x", maxHandoffSessionFieldBytes+1)
		}},
		{"missing label", func(b *handoffBinding, _ *string, _ *string, _ *time.Time) { b.label = "" }},
		{"oversized label", func(b *handoffBinding, _ *string, _ *string, _ *time.Time) { b.label = strings.Repeat("x", 64) }},
		{"missing authority", func(b *handoffBinding, _ *string, _ *string, _ *time.Time) { b.proxyAuthority = "" }},
		{"oversized authority", func(b *handoffBinding, _ *string, _ *string, _ *time.Time) {
			b.proxyAuthority = strings.Repeat("x", 254)
		}},
		{"missing hostname", func(b *handoffBinding, _ *string, _ *string, _ *time.Time) { b.hostname = "" }},
		{"oversized hostname", func(b *handoffBinding, _ *string, _ *string, _ *time.Time) { b.hostname = strings.Repeat("x", 254) }},
		{"wrong target host", func(_ *handoffBinding, u *string, _ *string, _ *time.Time) { *u = "https://other.example/" }},
		{"bad target", func(_ *handoffBinding, u *string, _ *string, _ *time.Time) { *u = "http://vendor.example/" }},
		{"oversized target", func(_ *handoffBinding, u *string, _ *string, _ *time.Time) {
			*u = "https://vendor.example/" + strings.Repeat("x", proxy.MaxLaunchQueryBytes)
		}},
		{"bad nonce", func(_ *handoffBinding, _ *string, n *string, _ *time.Time) { *n = "invalid" }},
		{"expired parent", func(_ *handoffBinding, _ *string, _ *string, e *time.Time) { *e = now }},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			s := newPendingHandoffs()
			b, u, n, e := binding, target, nonce, now.Add(time.Hour)
			invalid.change(&b, &u, &n, &e)
			if token, err := s.create(b, u, n, e, now); token != "" || !errors.Is(err, errInvalidPendingHandoff) || len(s.entries) != 0 {
				t.Fatal("invalid state was retained")
			}
		})
	}
}

func TestPendingHandoffConcurrentCapacity(t *testing.T) {
	binding, target, nonce, now := pendingHandoffFixture(t)
	s := newPendingHandoffs()
	var successes, full, unexpected atomic.Int32
	var wg sync.WaitGroup
	for range maxPendingHandoffs + 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.create(binding, target, nonce, now.Add(time.Hour), now)
			if err == nil {
				successes.Add(1)
			} else if errors.Is(err, errPendingHandoffsFull) {
				full.Add(1)
			} else {
				unexpected.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != maxPendingHandoffs || full.Load() != 16 || unexpected.Load() != 0 || len(s.entries) != maxPendingHandoffs {
		t.Fatal("concurrent allocations exceeded capacity or lost state")
	}
}

func TestPendingHandoffConcurrentInspectionAndCleanup(t *testing.T) {
	binding, target, nonce, now := pendingHandoffFixture(t)
	s := newPendingHandoffs()
	token, err := s.create(binding, target, nonce, now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	var invalid atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 32 {
				if record, ok := s.inspect(token, binding, nonce, now); ok && record.target != target {
					invalid.Add(1)
				}
				s.cleanup(now)
			}
		}()
	}
	wg.Add(1)
	go func() { defer wg.Done(); s.removeParent(binding.parentSessionID, now) }()
	wg.Wait()
	if invalid.Load() != 0 {
		t.Fatal("concurrent inspection returned corrupted state")
	}
	if _, ok := s.inspect(token, binding, nonce, now); ok || len(s.entries) != 0 {
		t.Fatal("parent cleanup failed during inspection")
	}
}
