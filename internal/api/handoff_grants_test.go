package api

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"example.org/odo/internal/auth/local"
	"example.org/odo/internal/db"
)

func grantTicketFixture(t *testing.T, s *pendingHandoffs, parentID string, now, parentExpires time.Time) (handoffTicket, string, string) {
	t.Helper()
	binding, target, central, _ := pendingHandoffFixture(t)
	binding.parentSessionID = parentID
	handoff, err := s.create(binding, target, "vendor", central, parentExpires, now)
	if err != nil {
		t.Fatal(err)
	}
	vendor, err := local.NewToken("", 32)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := s.prepare(handoff, db.ProxyHostname{Hostname: binding.hostname, Label: binding.label}, binding.proxyAuthority, vendor, now)
	if err != nil {
		t.Fatal("preflight failed")
	}
	ticket, err := s.confirm(handoff, binding, central, proof, now)
	if err != nil {
		t.Fatal(err)
	}
	return s.tickets[local.HashToken(ticket)], ticket, vendor
}

func TestHandoffGrantRedemptionBindingsAndPrivacy(t *testing.T) {
	_, _, _, now := pendingHandoffFixture(t)
	s := newPendingHandoffs()
	ticket, token, vendor := grantTicketFixture(t, s, "parent", now, now.Add(time.Hour))
	for _, change := range []func(*handoffBinding){
		func(b *handoffBinding) { b.parentSessionID = "other-parent" }, func(b *handoffBinding) { b.parentSessionHash = local.HashToken("wrong-parent-hash") },
		func(b *handoffBinding) { b.hostname = "other.example" }, func(b *handoffBinding) { b.label = "other-label" }, func(b *handoffBinding) { b.proxyAuthority = "other-proxy.example" },
	} {
		wrong := ticket.binding
		change(&wrong)
		if grant, target, err := s.redeem(token, wrong, vendor, now); grant != "" || target != "" || !errors.Is(err, errInvalidHandoffTicket) {
			t.Fatal("swapped binding redeemed ticket")
		}
	}
	otherNonce, err := local.NewToken("", 32)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []struct{ token, nonce string }{{token, "malformed"}, {token, otherNonce}, {"malformed", vendor}, {otherNonce, vendor}} {
		if grant, target, err := s.redeem(input.token, ticket.binding, input.nonce, now); grant != "" || target != "" || !errors.Is(err, errInvalidHandoffTicket) {
			t.Fatal("invalid token/nonce redeemed ticket")
		}
	}
	if len(s.grants) != 0 || s.tickets[local.HashToken(token)] != ticket {
		t.Fatal("invalid redemption changed live state")
	}
	grantToken, target, err := s.redeem(token, ticket.binding, vendor, now)
	if err != nil {
		t.Fatal(err)
	}
	if !validLaunchToken(grantToken) || grantToken == token || target != ticket.target || len(s.tickets) != 0 || len(s.grants) != 1 {
		t.Fatal("redemption lost target/binding or failed to consume ticket")
	}
	if _, found := s.grants[grantToken]; found {
		t.Fatal("plaintext grant token retained")
	}
	stored := s.grants[local.HashToken(grantToken)]
	if stored.binding != ticket.binding || stored.expires != now.Add(handoffGrantTTL) {
		t.Fatal("grant lost parent/host binding or lifetime")
	}
	state := fmt.Sprintf("%+v", stored)
	for _, private := range []string{target, vendor, ticket.centralNonceHash, ticket.vendorNonceHash} {
		if strings.Contains(state, private) {
			t.Fatal("grant retained target or browser nonce state")
		}
	}
	if grant, target, err := s.redeem(token, ticket.binding, vendor, now); grant != "" || target != "" || !errors.Is(err, errInvalidHandoffTicket) {
		t.Fatal("replay minted another grant")
	}
	mapping := db.ProxyHostname{Hostname: ticket.binding.hostname, Label: ticket.binding.label}
	for _, input := range []struct {
		token, authority string
		mapping          db.ProxyHostname
	}{
		{grantToken, ticket.binding.proxyAuthority, db.ProxyHostname{Hostname: "other.example", Label: mapping.Label}},
		{grantToken, ticket.binding.proxyAuthority, db.ProxyHostname{Hostname: mapping.Hostname, Label: "other-label"}},
		{grantToken, "other-proxy.example", mapping}, {token, ticket.binding.proxyAuthority, mapping}, {"malformed", ticket.binding.proxyAuthority, mapping},
	} {
		if got, ok := s.inspectGrant(input.token, input.mapping, input.authority, now); ok || got != (handoffGrant{}) {
			t.Fatal("wrong origin/token exposed grant")
		}
	}
	got, ok := s.inspectGrant(grantToken, mapping, ticket.binding.proxyAuthority, now.Add(time.Minute))
	if !ok || got != stored {
		t.Fatal("inspection changed expiry or lost grant")
	}
	got.binding.parentSessionID = "edited copy"
	if again, ok := s.inspectGrant(grantToken, mapping, ticket.binding.proxyAuthority, now); !ok || again != stored {
		t.Fatal("inspection exposed mutable grant")
	}
	if _, ok := newPendingHandoffs().inspectGrant(grantToken, mapping, ticket.binding.proxyAuthority, now); ok {
		t.Fatal("new store recovered previous grant")
	}
}

func TestHandoffGrantExpiryAndParentCap(t *testing.T) {
	for _, parentTTL := range []time.Duration{30 * time.Second, time.Hour} {
		t.Run(parentTTL.String(), func(t *testing.T) {
			_, _, _, now := pendingHandoffFixture(t)
			s := newPendingHandoffs()
			ticket, token, vendor := grantTicketFixture(t, s, "parent", now, now.Add(parentTTL))
			grant, _, err := s.redeem(token, ticket.binding, vendor, now)
			if err != nil {
				t.Fatal(err)
			}
			ttl := handoffGrantTTL
			if parentTTL < ttl {
				ttl = parentTTL
			}
			mapping := db.ProxyHostname{Hostname: ticket.binding.hostname, Label: ticket.binding.label}
			if got, ok := s.inspectGrant(grant, mapping, ticket.binding.proxyAuthority, now.Add(ttl-time.Nanosecond)); !ok || got.expires != now.Add(ttl) {
				t.Fatal("grant expired early or exceeded parent cap")
			}
			if got, ok := s.inspectGrant(grant, mapping, ticket.binding.proxyAuthority, now.Add(ttl)); ok || got != (handoffGrant{}) || len(s.grants) != 0 {
				t.Fatal("grant survived exact expiry")
			}
		})
	}
	_, _, _, now := pendingHandoffFixture(t)
	s := newPendingHandoffs()
	ticket, token, vendor := grantTicketFixture(t, s, "parent", now, now.Add(time.Hour))
	if grant, target, err := s.redeem(token, ticket.binding, vendor, now.Add(handoffTicketTTL)); grant != "" || target != "" || !errors.Is(err, errInvalidHandoffTicket) || len(s.tickets) != 0 || len(s.grants) != 0 {
		t.Fatal("expired ticket created grant")
	}
}

func TestHandoffGrantConcurrentReplay(t *testing.T) {
	_, _, _, now := pendingHandoffFixture(t)
	s := newPendingHandoffs()
	ticket, token, vendor := grantTicketFixture(t, s, "parent", now, now.Add(time.Hour))
	const attempts = 16
	start := make(chan struct{})
	results := make(chan error, attempts)
	var wg sync.WaitGroup
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _, err := s.redeem(token, ticket.binding, vendor, now)
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
		} else if !errors.Is(err, errInvalidHandoffTicket) {
			t.Fatal(err)
		}
	}
	if successes != 1 || len(s.tickets) != 0 || len(s.grants) != 1 {
		t.Fatal("concurrent replay created multiple grants or lost state")
	}
}

func TestHandoffGrantAtomicCapacityAndRetry(t *testing.T) {
	for _, global := range []bool{false, true} {
		t.Run(map[bool]string{false: "per parent", true: "global"}[global], func(t *testing.T) {
			_, _, _, now := pendingHandoffFixture(t)
			s := newPendingHandoffs()
			limit := maxHandoffGrantsPerParent
			if global {
				limit = maxHandoffGrants
			}
			var firstToken string
			var firstBinding handoffBinding
			for i := 0; i < limit-1; i++ {
				parent := "parent"
				if global {
					parent = fmt.Sprintf("parent-%d", i/maxHandoffGrantsPerParent)
				}
				ticket, token, vendor := grantTicketFixture(t, s, parent, now, now.Add(time.Hour))
				grant, _, err := s.redeem(token, ticket.binding, vendor, now)
				if err != nil {
					t.Fatal(err)
				}
				if i == 0 {
					firstToken, firstBinding = grant, ticket.binding
				}
			}
			// Fresh tickets remain valid as earlier grants reach expiry, allowing
			// capacity retry to be tested without deleting the parent's tickets.
			freshAt := now.Add(handoffGrantTTL - 30*time.Second)
			var records [2]handoffTicket
			var tokens, nonces [2]string
			for i := range records {
				parent := "parent"
				if global {
					parent = fmt.Sprintf("retry-parent-%d", i)
				}
				records[i], tokens[i], nonces[i] = grantTicketFixture(t, s, parent, freshAt, now.Add(time.Hour))
			}
			start := make(chan struct{})
			results := make(chan error, 2)
			var wg sync.WaitGroup
			for i := range records {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					_, _, err := s.redeem(tokens[i], records[i].binding, nonces[i], freshAt)
					results <- err
				}()
			}
			close(start)
			wg.Wait()
			close(results)
			succeeded, full := 0, 0
			for err := range results {
				if err == nil {
					succeeded++
				} else if errors.Is(err, errHandoffGrantsFull) {
					full++
				} else {
					t.Fatal(err)
				}
			}
			if succeeded != 1 || full != 1 || len(s.grants) != limit || len(s.tickets) != 1 {
				t.Fatal("concurrent redemption exceeded capacity or consumed failed ticket")
			}
			mapping := db.ProxyHostname{Hostname: firstBinding.hostname, Label: firstBinding.label}
			if _, ok := s.inspectGrant(firstToken, mapping, firstBinding.proxyAuthority, freshAt); !ok {
				t.Fatal("capacity pressure evicted live grant")
			}
			remaining := -1
			for i, token := range tokens {
				if stored, found := s.tickets[local.HashToken(token)]; found {
					remaining = i
					if stored != records[i] {
						t.Fatal("failed redemption changed ticket")
					}
				}
			}
			if remaining < 0 {
				t.Fatal("retry ticket missing")
			}
			if grant, target, err := s.redeem("malformed", records[remaining].binding, nonces[remaining], freshAt); grant != "" || target != "" || !errors.Is(err, errInvalidHandoffTicket) {
				t.Fatal("full store changed invalid-state result")
			}
			if _, _, err := s.redeem(tokens[remaining], records[remaining].binding, nonces[remaining], now.Add(handoffGrantTTL)); err != nil {
				t.Fatal("capacity retry failed after expired grants freed room")
			}
			if len(s.tickets) != 0 || len(s.grants) != 2 {
				t.Fatal("retry did not clean expired grants and consume ticket")
			}
		})
	}
}

func TestHandoffGrantParentCleanup(t *testing.T) {
	_, _, _, now := pendingHandoffFixture(t)
	s := newPendingHandoffs()
	ticket, token, vendor := grantTicketFixture(t, s, "parent", now, now.Add(time.Hour))
	grant, _, err := s.redeem(token, ticket.binding, vendor, now)
	if err != nil {
		t.Fatal(err)
	}
	other, otherTicket, otherVendor := grantTicketFixture(t, s, "other-parent", now, now.Add(time.Hour))
	otherGrant, _, err := s.redeem(otherTicket, other.binding, otherVendor, now)
	if err != nil {
		t.Fatal(err)
	}
	grantTicketFixture(t, s, "parent", now, now.Add(time.Hour))
	preparedTicketFixture(t, s, "parent", time.Hour)
	s.removeParent("parent", now)
	if len(s.entries) != 0 || len(s.tickets) != 0 || len(s.grants) != 1 {
		t.Fatal("parent cleanup did not remove all three state types")
	}
	mapping := db.ProxyHostname{Hostname: ticket.binding.hostname, Label: ticket.binding.label}
	if _, ok := s.inspectGrant(grant, mapping, ticket.binding.proxyAuthority, now); ok {
		t.Fatal("removed parent grant survived")
	}
	if _, ok := s.inspectGrant(otherGrant, mapping, other.binding.proxyAuthority, now); !ok {
		t.Fatal("unrelated parent grant removed")
	}
	s.cleanup(now.Add(handoffGrantTTL))
	if len(s.grants) != 0 {
		t.Fatal("explicit cleanup retained expired grants")
	}
}

func TestHandoffGrantConcurrentParentRemoval(t *testing.T) {
	_, _, _, now := pendingHandoffFixture(t)
	s := newPendingHandoffs()
	ticket, token, vendor := grantTicketFixture(t, s, "parent", now, now.Add(time.Hour))
	start := make(chan struct{})
	results := make(chan error, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _, err := s.redeem(token, ticket.binding, vendor, now)
			results <- err
		}()
	}
	wg.Add(1)
	go func() { defer wg.Done(); <-start; s.removeParent("parent", now) }()
	close(start)
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil && !errors.Is(err, errInvalidHandoffTicket) {
			t.Fatal(err)
		}
	}
	if len(s.entries) != 0 || len(s.tickets) != 0 || len(s.grants) != 0 {
		t.Fatal("redemption escaped concurrent parent cleanup")
	}
}

// Renewing a grant renews its sibling-host grants, never beyond their limit,
// and never revives one from another family or parent.
func TestHandoffGrantFamilyRenewsTogether(t *testing.T) {
	_, _, _, now := pendingHandoffFixture(t)
	s := newPendingHandoffs()
	ticket, token, vendor := grantTicketFixture(t, s, "parent", now, now.Add(2*time.Hour))
	mainToken, _, err := s.redeem(token, ticket.binding, vendor, now)
	if err != nil {
		t.Fatal(err)
	}
	main, ok := s.grantFamily(mainToken, now)
	if !ok {
		t.Fatal("main grant missing")
	}
	sibling := siblingHost{mapping: db.ProxyHostname{Hostname: "cdn.vendor.example", Label: "h-cdn"}, authority: "h-cdn.proxy.library.example"}
	first, err := s.issueSiblings(main, "vendor", []siblingHost{sibling}, "https://final.example/", now)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(first)
	hop, found := s.inspectSibling(parsed.Query().Get("sibling"), sibling.mapping, sibling.authority, now)
	if !found || hop.next != "https://final.example/" {
		t.Fatal("sibling hop not chained to the final location")
	}
	siblingToken, siblingGrant, err := s.redeemSibling(parsed.Query().Get("sibling"), hop.binding, now)
	if err != nil || siblingGrant.family != main.family || siblingGrant.binding.parentSessionID != "parent" {
		t.Fatalf("sibling grant: %+v %v", siblingGrant, err)
	}
	later := now.Add(handoffGrantTTL - time.Minute)
	if _, renewed := s.renewGrant(mainToken, db.ProxyHostname{Hostname: ticket.binding.hostname, Label: ticket.binding.label}, ticket.binding.proxyAuthority, later); !renewed {
		t.Fatal("main grant not renewed")
	}
	if _, alive := s.grantFamily(siblingToken, now.Add(handoffGrantTTL+time.Minute)); !alive {
		t.Fatal("sibling grant expired although its family was in use")
	}
}
