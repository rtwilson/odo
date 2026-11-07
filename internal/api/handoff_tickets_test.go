package api

import (
	"errors"
	"sync"
	"testing"
	"time"

	"example.org/odo/internal/auth/local"
	"example.org/odo/internal/db"
)

func preparedTicketFixture(t *testing.T, s *pendingHandoffs, parentID string, parentTTL time.Duration) (pendingHandoff, string, string, string, time.Time) {
	t.Helper()
	binding, target, centralNonce, now := pendingHandoffFixture(t)
	binding.parentSessionID = parentID
	token, err := s.create(binding, target, "vendor", centralNonce, now.Add(parentTTL), now)
	if err != nil {
		t.Fatal(err)
	}
	vendorNonce, err := local.NewToken("", 32)
	if err != nil {
		t.Fatal(err)
	}
	if !s.bindVendorNonce(token, db.ProxyHostname{Hostname: binding.hostname, Label: binding.label}, binding.proxyAuthority, vendorNonce, now) {
		t.Fatal("preflight failed")
	}
	return s.entries[local.HashToken(token)], token, centralNonce, vendorNonce, now
}

func TestHandoffTicketAtomicConfirmationAndInspection(t *testing.T) {
	s := newPendingHandoffs()
	pending, handoff, centralNonce, vendorNonce, now := preparedTicketFixture(t, s, "parent", time.Hour)
	token, err := s.confirm(handoff, pending.binding, centralNonce, now)
	if err != nil {
		t.Fatal(err)
	}
	if !validLaunchToken(token) || token == handoff {
		t.Fatal("invalid/distinct ticket token not generated")
	}
	if len(s.entries) != 0 || len(s.tickets) != 1 {
		t.Fatal("confirmation did not replace pending state")
	}
	if _, found := s.tickets[token]; found {
		t.Fatal("plaintext ticket token stored")
	}
	stored := s.tickets[local.HashToken(token)]
	if stored.binding != pending.binding || stored.centralNonceHash != local.HashToken(centralNonce) || stored.vendorNonceHash != local.HashToken(vendorNonce) || stored.target != pending.target || stored.expires != now.Add(handoffTicketTTL) {
		t.Fatal("ticket lost trusted bindings, target or expiry")
	}
	if again, err := s.confirm(handoff, pending.binding, centralNonce, now); again != "" || !errors.Is(err, errInvalidPendingHandoff) {
		t.Fatal("replayed confirmation minted another ticket")
	}
	mapping := db.ProxyHostname{Hostname: pending.binding.hostname, Label: pending.binding.label}
	if s.bindVendorNonce(handoff, mapping, pending.binding.proxyAuthority, vendorNonce, now) {
		t.Fatal("consumed handoff accepted preparation")
	}
	for _, tc := range []struct {
		token, authority, nonce string
		mapping                 db.ProxyHostname
	}{
		{token, pending.binding.proxyAuthority, vendorNonce, db.ProxyHostname{Hostname: "wrong.example", Label: mapping.Label}},
		{token, pending.binding.proxyAuthority, vendorNonce, db.ProxyHostname{Hostname: mapping.Hostname, Label: "wrong-label"}},
		{token, mapping.Label + ".other.example", vendorNonce, mapping},
		{token, pending.binding.proxyAuthority, centralNonce, mapping},
		{handoff, pending.binding.proxyAuthority, vendorNonce, mapping},
		{"malformed", pending.binding.proxyAuthority, vendorNonce, mapping},
		{token, pending.binding.proxyAuthority, "malformed", mapping},
	} {
		if got, ok := s.inspectTicket(tc.token, tc.mapping, tc.authority, tc.nonce, now); ok || got != (handoffTicket{}) {
			t.Fatal("invalid inspection exposed ticket")
		}
	}
	got, ok := s.inspectTicket(token, mapping, pending.binding.proxyAuthority, vendorNonce, now)
	if !ok || got != stored {
		t.Fatal("mismatches consumed legitimate ticket")
	}
	got.target = "edited copy"
	if again, ok := s.inspectTicket(token, mapping, pending.binding.proxyAuthority, vendorNonce, now); !ok || again != stored {
		t.Fatal("inspection consumed or exposed mutable ticket")
	}
	if _, ok := newPendingHandoffs().inspectTicket(token, mapping, pending.binding.proxyAuthority, vendorNonce, now); ok {
		t.Fatal("new store recovered previous ticket")
	}
}

func TestHandoffTicketConfirmationRequiresOriginalPreparedBinding(t *testing.T) {
	binding, target, nonce, now := pendingHandoffFixture(t)
	s := newPendingHandoffs()
	token, err := s.create(binding, target, "vendor", nonce, now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	before := s.entries[local.HashToken(token)]
	if ticket, err := s.confirm(token, binding, nonce, now); ticket != "" || !errors.Is(err, errInvalidPendingHandoff) {
		t.Fatal("unprepared handoff confirmed")
	}
	if s.entries[local.HashToken(token)] != before || len(s.tickets) != 0 {
		t.Fatal("failed confirmation consumed handoff")
	}
	vendor, err := local.NewToken("", 32)
	if err != nil {
		t.Fatal(err)
	}
	if !s.bindVendorNonce(token, db.ProxyHostname{Hostname: binding.hostname, Label: binding.label}, binding.proxyAuthority, vendor, now) {
		t.Fatal("preparation failed")
	}
	before = s.entries[local.HashToken(token)]
	for _, change := range []func(*handoffBinding){
		func(b *handoffBinding) { b.parentSessionID = "wrong-parent" }, func(b *handoffBinding) { b.parentSessionHash = local.HashToken("wrong-hash") },
		func(b *handoffBinding) { b.hostname = "other.example" }, func(b *handoffBinding) { b.label = "wrong-label" }, func(b *handoffBinding) { b.proxyAuthority = "other-proxy.example" },
	} {
		wrong := binding
		change(&wrong)
		if ticket, err := s.confirm(token, wrong, nonce, now); ticket != "" || !errors.Is(err, errInvalidPendingHandoff) {
			t.Fatal("swapped binding confirmed")
		}
	}
	for _, input := range []struct{ token, nonce string }{{token, vendor}, {token, "malformed"}, {"malformed", nonce}, {vendor, nonce}} {
		if ticket, err := s.confirm(input.token, binding, input.nonce, now); ticket != "" || !errors.Is(err, errInvalidPendingHandoff) {
			t.Fatal("swapped token/nonce confirmed")
		}
	}
	if s.entries[local.HashToken(token)] != before || len(s.tickets) != 0 {
		t.Fatal("invalid confirmations changed state")
	}
	if _, err := s.confirm(token, binding, nonce, now); err != nil {
		t.Fatal("valid confirmation lost after mismatches")
	}
}

func TestHandoffTicketExpiryAndParentCap(t *testing.T) {
	for _, parentTTL := range []time.Duration{30 * time.Second, time.Hour} {
		t.Run(parentTTL.String(), func(t *testing.T) {
			s := newPendingHandoffs()
			pending, handoff, central, vendor, now := preparedTicketFixture(t, s, "parent", parentTTL)
			token, err := s.confirm(handoff, pending.binding, central, now)
			if err != nil {
				t.Fatal(err)
			}
			ttl := handoffTicketTTL
			if parentTTL < ttl {
				ttl = parentTTL
			}
			mapping := db.ProxyHostname{Hostname: pending.binding.hostname, Label: pending.binding.label}
			if got, ok := s.inspectTicket(token, mapping, pending.binding.proxyAuthority, vendor, now.Add(ttl-time.Nanosecond)); !ok || got.expires != now.Add(ttl) {
				t.Fatal("ticket expired early or exceeded parent expiry")
			}
			if got, ok := s.inspectTicket(token, mapping, pending.binding.proxyAuthority, vendor, now.Add(ttl)); ok || got != (handoffTicket{}) || len(s.tickets) != 0 {
				t.Fatal("ticket survived exact expiry")
			}
		})
	}
	s := newPendingHandoffs()
	pending, handoff, central, vendor, now := preparedTicketFixture(t, s, "parent", time.Hour)
	confirmedAt := now.Add(pendingHandoffTTL - time.Nanosecond)
	ticket, err := s.confirm(handoff, pending.binding, central, confirmedAt)
	if err != nil {
		t.Fatal(err)
	}
	mapping := db.ProxyHostname{Hostname: pending.binding.hostname, Label: pending.binding.label}
	if got, ok := s.inspectTicket(ticket, mapping, pending.binding.proxyAuthority, vendor, now.Add(pendingHandoffTTL)); !ok || got.expires != confirmedAt.Add(handoffTicketTTL) {
		t.Fatal("ticket TTL incorrectly capped by consumed handoff deadline")
	}
	s = newPendingHandoffs()
	pending, handoff, central, _, now = preparedTicketFixture(t, s, "parent", time.Hour)
	if ticket, err := s.confirm(handoff, pending.binding, central, now.Add(pendingHandoffTTL)); ticket != "" || !errors.Is(err, errInvalidPendingHandoff) || len(s.entries) != 0 {
		t.Fatal("expired handoff confirmed")
	}
}

func TestHandoffTicketCapacityPreservesPendingForRetry(t *testing.T) {
	s := newPendingHandoffs()
	var firstTicket, firstVendor string
	var firstPending pendingHandoff
	for i := 0; i < maxHandoffTickets; i++ {
		pending, handoff, central, vendor, now := preparedTicketFixture(t, s, "parent", time.Hour)
		ticket, err := s.confirm(handoff, pending.binding, central, now)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			firstTicket, firstVendor, firstPending = ticket, vendor, pending
		}
	}
	pending, handoff, central, _, now := preparedTicketFixture(t, s, "parent", time.Hour)
	if ticket, err := s.confirm(handoff, pending.binding, central, now); ticket != "" || !errors.Is(err, errHandoffTicketsFull) {
		t.Fatal("ticket capacity not enforced")
	}
	if len(s.tickets) != maxHandoffTickets || len(s.entries) != 1 || s.entries[local.HashToken(handoff)] != pending {
		t.Fatal("capacity failure consumed pending state or evicted live tickets")
	}
	mapping := db.ProxyHostname{Hostname: firstPending.binding.hostname, Label: firstPending.binding.label}
	if _, ok := s.inspectTicket(firstTicket, mapping, firstPending.binding.proxyAuthority, firstVendor, now); !ok {
		t.Fatal("capacity failure evicted live ticket")
	}
	if _, err := s.confirm("malformed", pending.binding, central, now); !errors.Is(err, errInvalidPendingHandoff) {
		t.Fatal("full store changed invalid-state response")
	}
	if _, err := s.confirm(handoff, pending.binding, central, now.Add(handoffTicketTTL)); err != nil {
		t.Fatal("could not retry after expired tickets freed capacity")
	}
	if len(s.entries) != 0 || len(s.tickets) != 1 {
		t.Fatal("retry did not clean expired tickets and consume pending state")
	}
}

func TestHandoffTicketParentCleanup(t *testing.T) {
	s := newPendingHandoffs()
	pending, handoff, central, _, now := preparedTicketFixture(t, s, "parent", time.Hour)
	if _, err := s.confirm(handoff, pending.binding, central, now); err != nil {
		t.Fatal(err)
	}
	preparedTicketFixture(t, s, "parent", time.Hour)
	other, otherHandoff, otherCentral, otherVendor, _ := preparedTicketFixture(t, s, "other-parent", time.Hour)
	otherTicket, err := s.confirm(otherHandoff, other.binding, otherCentral, now)
	if err != nil {
		t.Fatal(err)
	}
	s.removeParent("parent", now)
	if len(s.entries) != 0 || len(s.tickets) != 1 {
		t.Fatal("parent cleanup did not remove pending and ticket state")
	}
	if _, ok := s.inspectTicket(otherTicket, db.ProxyHostname{Hostname: other.binding.hostname, Label: other.binding.label}, other.binding.proxyAuthority, otherVendor, now); !ok {
		t.Fatal("unrelated parent ticket removed")
	}
	s.cleanup(now.Add(handoffTicketTTL))
	if len(s.tickets) != 0 {
		t.Fatal("explicit cleanup retained expired tickets")
	}
}

func TestHandoffTicketConcurrentConfirmation(t *testing.T) {
	s := newPendingHandoffs()
	pending, handoff, central, _, now := preparedTicketFixture(t, s, "parent", time.Hour)
	const attempts = 16
	results := make(chan error, attempts)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := s.confirm(handoff, pending.binding, central, now)
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, errInvalidPendingHandoff) {
			t.Fatal(err)
		}
	}
	if successes != 1 || len(s.entries) != 0 || len(s.tickets) != 1 {
		t.Fatal("concurrent confirmation created multiple tickets or lost state")
	}
}
