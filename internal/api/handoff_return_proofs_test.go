package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"example.org/odo/internal/auth/local"
	"example.org/odo/internal/db"
	"example.org/odo/internal/resources"
)

func TestHandoffReturnProofPrivacyAndBinding(t *testing.T) {
	s := newPendingHandoffs()
	pending, token, central, vendor, proof, now := preparedTicketFixture(t, s, "parent", time.Hour)
	if !validLaunchToken(proof) || proof == token || proof == central || proof == vendor || pending.returnProofHash != local.HashToken(proof) || pending.returnProofExpires != now.Add(returnProofTTL) {
		t.Fatal("proof format, hash or expiry incorrect")
	}
	if strings.Contains(fmt.Sprint(pending), proof) {
		t.Fatal("raw proof retained in pending state")
	}
	other, otherToken, _, _, otherProof, _ := preparedTicketFixture(t, s, "other", time.Hour)
	before := s.entries[local.HashToken(token)]
	for _, wrong := range []string{"", "malformed", proof + "=", token, central, vendor, otherProof} {
		if ticket, err := s.confirm(token, pending.binding, central, wrong, now); err == nil || ticket != "" {
			t.Fatal("invalid or substituted proof confirmed")
		}
		if s.entries[local.HashToken(token)] != before {
			t.Fatal("failed proof changed pending state")
		}
	}
	wrongHost := pending.binding
	wrongHost.hostname = "other.example"
	if _, err := s.confirm(token, wrongHost, central, proof, now); err == nil {
		t.Fatal("proof accepted with wrong host")
	}
	if s.entries[local.HashToken(otherToken)] != other {
		t.Fatal("another handoff was changed")
	}
	inspected, ok := s.inspect(token, pending.binding, central, now)
	if !ok || inspected != before {
		t.Fatal("inspection consumed or changed proof state")
	}
	ticket, err := s.confirm(token, pending.binding, central, proof, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.confirm(token, pending.binding, central, proof, now); err == nil {
		t.Fatal("proof replay confirmed")
	}
	if strings.Contains(fmt.Sprint(s.tickets[local.HashToken(ticket)]), pending.returnProofHash) {
		t.Fatal("proof hash transferred to ticket")
	}
	grant, _, err := s.redeem(ticket, pending.binding, vendor, now)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprint(s.grants[local.HashToken(grant)]), pending.returnProofHash) {
		t.Fatal("proof hash transferred to grant")
	}
}

func TestHandoffReturnProofExpiryAndCleanup(t *testing.T) {
	for _, parentTTL := range []time.Duration{30 * time.Second, time.Hour} {
		t.Run(parentTTL.String(), func(t *testing.T) {
			s := newPendingHandoffs()
			p, token, central, _, proof, now := preparedTicketFixture(t, s, "parent", parentTTL)
			ttl := returnProofTTL
			if parentTTL < ttl {
				ttl = parentTTL
			}
			if !p.acceptsReturnProof(proof, now.Add(ttl-time.Nanosecond)) || p.returnProofExpires != now.Add(ttl) {
				t.Fatal("proof expired early or exceeded parent")
			}
			if ticket, err := s.confirm(token, p.binding, central, proof, now.Add(ttl)); err == nil || ticket != "" {
				t.Fatal("expired proof confirmed")
			}
			if _, err := newPendingHandoffs().confirm(token, p.binding, central, proof, now); err == nil {
				t.Fatal("restart recovered proof")
			}
			s.removeParent(p.binding.parentSessionID, now)
			if _, err := s.confirm(token, p.binding, central, proof, now); err == nil || len(s.entries) != 0 {
				t.Fatal("removed parent retained proof")
			}
		})
	}
	s := newPendingHandoffs()
	p, token, _, vendor, _, now := preparedTicketFixture(t, s, "parent", time.Hour)
	at := now.Add(pendingHandoffTTL - time.Second)
	proof, err := s.prepare(token, db.ProxyHostname{Hostname: p.binding.hostname, Label: p.binding.label}, p.binding.proxyAuthority, vendor, at)
	if err != nil {
		t.Fatal(err)
	}
	p = s.entries[local.HashToken(token)]
	if p.returnProofExpires != now.Add(pendingHandoffTTL) || !p.acceptsReturnProof(proof, at) {
		t.Fatal("proof exceeded pending deadline")
	}
	s.cleanup(now.Add(pendingHandoffTTL))
	if len(s.entries) != 0 {
		t.Fatal("expired pending record retained proof")
	}
}

func TestHandoffReturnProofCapacityRetry(t *testing.T) {
	s := newPendingHandoffs()
	var first handoffTicket
	var firstToken, firstVendor string
	for i := 0; i < maxHandoffTickets; i++ {
		p, token, central, vendor, proof, now := preparedTicketFixture(t, s, "parent", time.Hour)
		ticket, err := s.confirm(token, p.binding, central, proof, now)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = s.tickets[local.HashToken(ticket)]
			firstToken = ticket
			firstVendor = vendor
		}
	}
	p, token, central, _, proof, now := preparedTicketFixture(t, s, "parent", time.Hour)
	if ticket, err := s.confirm(token, p.binding, central, proof, now); !errors.Is(err, errHandoffTicketsFull) || ticket != "" {
		t.Fatal("ticket capacity not enforced")
	}
	if s.entries[local.HashToken(token)] != p {
		t.Fatal("capacity failure consumed or renewed proof")
	}
	if _, _, err := s.redeem(firstToken, first.binding, firstVendor, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.confirm(token, p.binding, central, proof, now.Add(time.Second)); err != nil {
		t.Fatal("live proof could not retry after capacity freed")
	}
}

func TestHandoffReturnProofRejectsTwoBrowserSplicing(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	pendingA, err := f.h.begin(ctx, f.central, f.authority, f.target, f.nonce, f.now)
	if err != nil {
		t.Fatal(err)
	}
	// Browser B has a separate login for the same user. A cannot obtain the proof
	// returned only to B's vendor preflight response.
	parent, _, err := f.h.server.store.GetSession(local.SessionIDFromToken(f.central))
	if err != nil {
		t.Fatal(err)
	}
	user, _, err := f.h.server.store.GetUser(parent.UserID)
	if err != nil {
		t.Fatal(err)
	}
	centralB, sessionB, err := f.h.server.newBrowserSession(user.ID, httptest.NewRequest("GET", "/", nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.h.server.store.CreateAuthenticatedSession(sessionB, user); err != nil {
		t.Fatal(err)
	}
	nonceB, err := local.NewToken("", 32)
	if err != nil {
		t.Fatal(err)
	}
	vendorB, err := local.NewToken("", 32)
	if err != nil {
		t.Fatal(err)
	}
	proofB, err := f.h.preflight(pendingA, f.authority, vendorB, f.now)
	if err != nil {
		t.Fatal(err)
	}
	ownPending, err := f.h.begin(ctx, f.central, f.authority, f.target, f.nonce, f.now)
	if err != nil {
		t.Fatal(err)
	}
	ownProof, err := f.h.preflight(ownPending, f.authority, f.vendor, f.now)
	if err != nil {
		t.Fatal(err)
	}
	for _, attempt := range []struct{ central, nonce, proof string }{
		{f.central, f.nonce, ""}, {f.central, f.nonce, ownProof},
		{centralB, nonceB, proofB}, {centralB, f.nonce, proofB},
	} {
		if ticket, err := f.h.confirm(ctx, pendingA, attempt.central, f.authority, attempt.nonce, attempt.proof, f.now); err == nil || ticket != "" {
			t.Fatal("two-browser splice confirmed")
		}
	}
	before := f.h.state.entries[local.HashToken(pendingA)]
	if proof, err := f.h.preflight(pendingA, f.authority, f.vendor, f.now); err == nil || proof != "" {
		t.Fatal("initiator replaced browser B's nonce")
	}
	if f.h.state.entries[local.HashToken(pendingA)] != before || len(f.h.state.tickets) != 0 || len(f.h.state.grants) != 0 {
		t.Fatal("failed splice changed live state or minted credentials")
	}
	// B can complete a fresh handoff initiated in B's own central session.
	pendingB, err := f.h.begin(ctx, centralB, f.authority, f.target, nonceB, f.now)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := f.h.preflight(pendingB, f.authority, vendorB, f.now)
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := f.h.confirm(ctx, pendingB, centralB, f.authority, nonceB, proof, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.h.redeem(ctx, ticket, f.authority, vendorB, f.now); err != nil {
		t.Fatal(err)
	}
}

func TestHandoffReturnProofFailuresPreserveRetryState(t *testing.T) {
	for _, kind := range []string{"database", "policy"} {
		t.Run(kind, func(t *testing.T) {
			f := newSecurityFixture(t)
			pending, err := f.h.begin(context.Background(), f.central, f.authority, f.target, f.nonce, f.now)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := f.h.preflight(pending, f.authority, f.vendor, f.now)
			if err != nil {
				t.Fatal(err)
			}
			before := f.h.state.entries[local.HashToken(pending)]
			if kind == "database" {
				if _, err := f.control.Exec(`ALTER TABLE sessions RENAME TO unavailable_sessions`); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := f.h.server.store.UpsertResource(resources.Resource{ID: "vendor", Name: "Vendor", Status: "disabled", Domains: []resources.DomainRule{{Host: "vendor.example"}}}); err != nil {
					t.Fatal(err)
				}
			}
			if ticket, err := f.h.confirm(context.Background(), pending, f.central, f.authority, f.nonce, proof, f.now); err == nil || ticket != "" {
				t.Fatal("failed live validation minted ticket")
			}
			if f.h.state.entries[local.HashToken(pending)] != before {
				t.Fatal("failed live validation consumed or renewed proof")
			}
			if kind == "database" {
				if _, err := f.control.Exec(`ALTER TABLE unavailable_sessions RENAME TO sessions`); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := f.h.server.store.UpsertResource(resources.Resource{ID: "vendor", Name: "Vendor", Domains: []resources.DomainRule{{Host: "vendor.example"}}}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.h.confirm(context.Background(), pending, f.central, f.authority, f.nonce, proof, f.now); err != nil {
				t.Fatal("preserved proof could not retry")
			}
		})
	}
}

func TestHandoffReturnProofRotationDuringConfirmation(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	pending, err := f.h.begin(ctx, f.central, f.authority, f.target, f.nonce, f.now)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := f.h.preflight(pending, f.authority, f.vendor, f.now)
	if err != nil {
		t.Fatal(err)
	}
	// Rotate after the coordinator's snapshot check, while it revalidates DNS.
	// The final store transition must check the current proof under its lock.
	var nextProof string
	rotated := false
	f.h.server.ipLookup = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		if !rotated {
			rotated = true
			var err error
			nextProof, err = f.h.preflight(pending, f.authority, f.vendor, f.now)
			if err != nil {
				return nil, err
			}
		}
		return publicTestResolver(ctx, host)
	}
	if ticket, err := f.h.confirm(ctx, pending, f.central, f.authority, f.nonce, proof, f.now); err == nil || ticket != "" {
		t.Fatal("stale snapshot proof confirmed")
	}
	if !rotated || len(f.h.state.tickets) != 0 {
		t.Fatal("proof rotation interleaving was not checked")
	}
	if _, err := f.h.confirm(ctx, pending, f.central, f.authority, f.nonce, nextProof, f.now); err != nil {
		t.Fatal("replacement proof could not confirm")
	}
}

func TestHandoffReturnProofParentRevocation(t *testing.T) {
	for _, kind := range []string{"session", "auth_version"} {
		t.Run(kind, func(t *testing.T) {
			f := newSecurityFixture(t)
			pending, err := f.h.begin(context.Background(), f.central, f.authority, f.target, f.nonce, f.now)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := f.h.preflight(pending, f.authority, f.vendor, f.now)
			if err != nil {
				t.Fatal(err)
			}
			id := local.SessionIDFromToken(f.central)
			if kind == "session" {
				if err := f.h.server.store.RevokeSession(id); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := f.control.Exec(`UPDATE users SET auth_version=auth_version+1 WHERE id=(SELECT user_id FROM sessions WHERE id=?)`, id); err != nil {
					t.Fatal(err)
				}
			}
			if ticket, err := f.h.confirm(context.Background(), pending, f.central, f.authority, f.nonce, proof, f.now); err == nil || ticket != "" {
				t.Fatal("revoked parent confirmed proof")
			}
			if len(f.h.state.entries) != 0 || len(f.h.state.tickets) != 0 {
				t.Fatal("revoked parent retained proof or minted ticket")
			}
		})
	}
}
