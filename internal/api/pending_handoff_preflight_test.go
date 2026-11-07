package api

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"example.org/odo/internal/auth/local"
	"example.org/odo/internal/db"
)

func TestPendingHandoffVendorNonceSingleAssignment(t *testing.T) {
	binding, target, centralNonce, now := pendingHandoffFixture(t)
	s := newPendingHandoffs()
	token, err := s.create(binding, target, centralNonce, now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	mapping := db.ProxyHostname{Hostname: binding.hostname, Label: binding.label}
	nonce, err := local.NewToken("", 32)
	if err != nil {
		t.Fatal(err)
	}
	before := s.entries[local.HashToken(token)]
	if before.vendorNonceHash != "" {
		t.Fatal("new handoff already prepared")
	}
	if !s.bindVendorNonce(token, mapping, binding.proxyAuthority, nonce, now) {
		t.Fatal("first binding rejected")
	}
	prepared := s.entries[local.HashToken(token)]
	expected := before
	expected.vendorNonceHash = local.HashToken(nonce)
	if prepared != expected || prepared.vendorNonceHash == nonce {
		t.Fatal("binding retained plaintext nonce or changed unrelated state")
	}
	if !s.bindVendorNonce(token, mapping, binding.proxyAuthority, nonce, now.Add(time.Minute)) {
		t.Fatal("idempotent preparation rejected")
	}
	otherNonce, err := local.NewToken("", 32)
	if err != nil {
		t.Fatal(err)
	}
	if s.bindVendorNonce(token, mapping, binding.proxyAuthority, otherNonce, now.Add(time.Minute)) {
		t.Fatal("replaced original vendor nonce")
	}
	if s.entries[local.HashToken(token)] != prepared {
		t.Fatal("retry/replacement changed pending state or expiry")
	}
	if got, ok := s.inspect(token, binding, centralNonce, now); !ok || got.vendorNonceHash != local.HashToken(nonce) || got.target != target {
		t.Fatal("central inspection lost prepared state")
	}
	if _, ok := s.inspect(token, binding, nonce, now); ok {
		t.Fatal("vendor nonce substituted for central browser nonce")
	}
}

func TestPendingHandoffVendorNonceMismatchDoesNotBind(t *testing.T) {
	binding, target, centralNonce, now := pendingHandoffFixture(t)
	s := newPendingHandoffs()
	token, err := s.create(binding, target, centralNonce, now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	mapping := db.ProxyHostname{Hostname: binding.hostname, Label: binding.label}
	nonce, err := local.NewToken("", 32)
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := local.NewToken("", 32)
	if err != nil {
		t.Fatal(err)
	}
	before := s.entries[local.HashToken(token)]
	for _, tc := range []struct {
		name, token, authority, nonce string
		mapping                       db.ProxyHostname
	}{
		{"wrong hostname", token, binding.proxyAuthority, nonce, db.ProxyHostname{Hostname: "other.example", Label: mapping.Label}},
		{"wrong label", token, binding.proxyAuthority, nonce, db.ProxyHostname{Hostname: mapping.Hostname, Label: "other-label"}},
		{"wrong deployment", token, mapping.Label + ".other.example", nonce, mapping},
		{"empty mapping", token, binding.proxyAuthority, nonce, db.ProxyHostname{}},
		{"missing nonce", token, binding.proxyAuthority, "", mapping},
		{"malformed nonce", token, binding.proxyAuthority, "malformed", mapping},
		{"malformed token", "malformed", binding.proxyAuthority, nonce, mapping},
		{"unknown token", unknown, binding.proxyAuthority, nonce, mapping},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if s.bindVendorNonce(tc.token, tc.mapping, tc.authority, tc.nonce, now) {
				t.Fatal("invalid preparation succeeded")
			}
			if len(s.entries) != 1 || s.entries[local.HashToken(token)] != before {
				t.Fatal("mismatch modified pending state")
			}
		})
	}
	if !s.bindVendorNonce(token, mapping, binding.proxyAuthority, nonce, now) {
		t.Fatal("mismatches consumed valid handoff")
	}
}

func TestPendingHandoffVendorNonceExpiryAndRemoval(t *testing.T) {
	for _, ttl := range []time.Duration{pendingHandoffTTL, time.Minute} {
		t.Run(ttl.String(), func(t *testing.T) {
			binding, target, centralNonce, now := pendingHandoffFixture(t)
			s := newPendingHandoffs()
			token, err := s.create(binding, target, centralNonce, now.Add(ttl), now)
			if err != nil {
				t.Fatal(err)
			}
			mapping := db.ProxyHostname{Hostname: binding.hostname, Label: binding.label}
			nonce, err := local.NewToken("", 32)
			if err != nil {
				t.Fatal(err)
			}
			if !s.bindVendorNonce(token, mapping, binding.proxyAuthority, nonce, now.Add(ttl-time.Nanosecond)) {
				t.Fatal("expired early")
			}
			if s.bindVendorNonce(token, mapping, binding.proxyAuthority, nonce, now.Add(ttl)) || len(s.entries) != 0 {
				t.Fatal("preparation extended expiry or retained expired state")
			}
			token, err = s.create(binding, target, centralNonce, now.Add(time.Hour), now)
			if err != nil {
				t.Fatal(err)
			}
			s.removeParent(binding.parentSessionID, now)
			if s.bindVendorNonce(token, mapping, binding.proxyAuthority, nonce, now) || len(s.entries) != 0 {
				t.Fatal("preparation resurrected removed parent state")
			}
		})
	}
}

func TestPendingHandoffVendorNonceConcurrentBinding(t *testing.T) {
	for _, sameNonce := range []bool{false, true} {
		t.Run(map[bool]string{false: "competing browsers", true: "same browser retries"}[sameNonce], func(t *testing.T) {
			binding, target, centralNonce, now := pendingHandoffFixture(t)
			s := newPendingHandoffs()
			token, err := s.create(binding, target, centralNonce, now.Add(time.Hour), now)
			if err != nil {
				t.Fatal(err)
			}
			mapping := db.ProxyHostname{Hostname: binding.hostname, Label: binding.label}
			const attempts = 16
			var nonces [attempts]string
			for i := range nonces {
				if sameNonce && i > 0 {
					nonces[i] = nonces[0]
					continue
				}
				nonces[i], err = local.NewToken("", 32)
				if err != nil {
					t.Fatal(err)
				}
			}
			start := make(chan struct{})
			var successes atomic.Int32
			var wg sync.WaitGroup
			for _, nonce := range nonces {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					if s.bindVendorNonce(token, mapping, binding.proxyAuthority, nonce, now) {
						successes.Add(1)
					}
				}()
			}
			close(start)
			wg.Wait()
			want := int32(1)
			if sameNonce {
				want = attempts
			}
			if successes.Load() != want {
				t.Fatalf("successful bindings: got %d want %d", successes.Load(), want)
			}
			prepared := s.entries[local.HashToken(token)]
			matches := 0
			for _, nonce := range nonces {
				if prepared.vendorNonceHash == local.HashToken(nonce) {
					matches++
				}
			}
			if int32(matches) != want {
				t.Fatal("stored nonce does not match successful browser")
			}
		})
	}
}

func TestPendingHandoffVendorNonceWorksAtCapacity(t *testing.T) {
	binding, target, centralNonce, now := pendingHandoffFixture(t)
	s := newPendingHandoffs()
	var token string
	for range maxPendingHandoffs {
		var err error
		token, err = s.create(binding, target, centralNonce, now.Add(time.Hour), now)
		if err != nil {
			t.Fatal(err)
		}
	}
	nonce, err := local.NewToken("", 32)
	if err != nil {
		t.Fatal(err)
	}
	mapping := db.ProxyHostname{Hostname: binding.hostname, Label: binding.label}
	if !s.bindVendorNonce(token, mapping, binding.proxyAuthority, nonce, now) || len(s.entries) != maxPendingHandoffs {
		t.Fatal("binding consumed capacity or evicted live state")
	}
}
