package api

import (
	"errors"
	"sync"
	"time"

	"example.org/odo/internal/auth/local"
	"example.org/odo/internal/db"
	"example.org/odo/internal/proxy"
)

const (
	pendingHandoffTTL           = 5 * time.Minute
	maxPendingHandoffs          = 256
	handoffTicketTTL            = time.Minute
	maxHandoffTickets           = 256
	maxHandoffSessionFieldBytes = 128
)

var (
	errPendingHandoffsFull   = errors.New("pending handoff capacity reached")
	errInvalidPendingHandoff = errors.New("pending handoff state is invalid")
	errHandoffTicketsFull    = errors.New("handoff ticket capacity reached")
)

// All fields must come from authenticated/current datastore and deployment
// state, never directly from request cookies, Host headers or query parameters.
// Registry identity is the hostname/label pair, not a resource identifier.
type handoffBinding struct {
	parentSessionID   string
	parentSessionHash string
	hostname          string
	label             string
	proxyAuthority    string
}

type pendingHandoff struct {
	binding          handoffBinding
	centralNonceHash string
	vendorNonceHash  string
	target           string
	expires          time.Time
	parentExpires    time.Time
}

type handoffTicket struct {
	binding          handoffBinding
	centralNonceHash string
	vendorNonceHash  string
	target           string
	expires          time.Time
}

// This passive store has no routes, cookie handling, database access, DNS or
// fetching. It is deliberately not attached to Server yet. Its records alone
// do not authorize a target, parent session or registry entry.
type pendingHandoffs struct {
	mu      sync.Mutex
	entries map[string]pendingHandoff
	tickets map[string]handoffTicket
}

func newPendingHandoffs() *pendingHandoffs {
	return &pendingHandoffs{entries: make(map[string]pendingHandoff), tickets: make(map[string]handoffTicket)}
}

func (s *pendingHandoffs) create(binding handoffBinding, target, centralNonce string, parentExpires, now time.Time) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(now)
	// Bound every retained input, not only the number of records. Syntax checks
	// do not establish live session validity, registry membership or SSRF safety.
	if binding.parentSessionID == "" || len(binding.parentSessionID) > maxHandoffSessionFieldBytes ||
		binding.parentSessionHash == "" || len(binding.parentSessionHash) > maxHandoffSessionFieldBytes ||
		binding.label == "" || len(binding.label) > 63 ||
		binding.proxyAuthority == "" || len(binding.proxyAuthority) > 253 ||
		binding.hostname == "" || len(binding.hostname) > 253 ||
		len(target) > proxy.MaxLaunchQueryBytes-len("url=") ||
		!validLaunchToken(centralNonce) || !now.Before(parentExpires) {
		return "", errInvalidPendingHandoff
	}
	parsed, err := proxy.ParseLaunchQuery("url=" + target)
	if err != nil || parsed.Hostname() != binding.hostname || len(parsed.String())+len("url=") > proxy.MaxLaunchQueryBytes {
		return "", errInvalidPendingHandoff
	}
	if len(s.entries) >= maxPendingHandoffs {
		return "", errPendingHandoffsFull
	}
	token, err := local.NewToken("", 32)
	if err != nil {
		return "", errors.New("pending handoff token generation failed")
	}
	key := local.HashToken(token)
	if _, exists := s.entries[key]; exists {
		return "", errors.New("pending handoff token collision")
	}
	if _, exists := s.tickets[key]; exists {
		return "", errors.New("pending handoff token collision")
	}
	expires := now.Add(pendingHandoffTTL)
	if parentExpires.Before(expires) {
		expires = parentExpires
	}
	s.entries[key] = pendingHandoff{binding: binding, centralNonceHash: local.HashToken(centralNonce), target: parsed.String(), expires: expires, parentExpires: parentExpires}
	return token, nil
}

// inspect is non-consuming and returns a value copy, not mutable store state.
// HTTP confirmation must recheck live authorization before calling confirm;
// inspection followed by a separate consume step would not be atomic.
func (s *pendingHandoffs) inspect(token string, binding handoffBinding, centralNonce string, now time.Time) (pendingHandoff, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(now)
	if !validLaunchToken(token) || !validLaunchToken(centralNonce) {
		return pendingHandoff{}, false
	}
	pending, found := s.entries[local.HashToken(token)]
	if !found || pending.binding != binding || pending.centralNonceHash != local.HashToken(centralNonce) {
		return pendingHandoff{}, false
	}
	return pending, true
}

// bindVendorNonce records the first vendor browser nonce after exact host
// admission/registry lookup by the caller. Vendor preflight does not receive
// central-session credentials or the central nonce. This operation reveals no
// target/parent data and is not authorization or ticket issuance.
func (s *pendingHandoffs) bindVendorNonce(token string, mapping db.ProxyHostname, authority, nonce string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(now)
	if !validLaunchToken(token) || !validLaunchToken(nonce) {
		return false
	}
	key := local.HashToken(token)
	pending, found := s.entries[key]
	if !found || pending.binding.hostname != mapping.Hostname || pending.binding.label != mapping.Label || pending.binding.proxyAuthority != authority {
		return false
	}
	hash := local.HashToken(nonce)
	if pending.vendorNonceHash != "" {
		return pending.vendorNonceHash == hash
	}
	pending.vendorNonceHash = hash
	s.entries[key] = pending
	return true
}

// confirm atomically replaces a prepared handoff with a bounded ticket. The
// caller must first check live parent/user, registry, method and target safety.
// Capacity/randomness/collision failure preserves pending state for retry.
func (s *pendingHandoffs) confirm(token string, binding handoffBinding, centralNonce string, now time.Time) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(now)
	if !validLaunchToken(token) || !validLaunchToken(centralNonce) {
		return "", errInvalidPendingHandoff
	}
	key := local.HashToken(token)
	pending, found := s.entries[key]
	if !found || pending.binding != binding || pending.centralNonceHash != local.HashToken(centralNonce) || pending.vendorNonceHash == "" {
		return "", errInvalidPendingHandoff
	}
	if len(s.tickets) >= maxHandoffTickets {
		return "", errHandoffTicketsFull
	}
	ticket, err := local.NewToken("", 32)
	if err != nil {
		return "", errors.New("handoff ticket generation failed")
	}
	ticketKey := local.HashToken(ticket)
	if _, exists := s.tickets[ticketKey]; exists {
		return "", errors.New("handoff ticket collision")
	}
	if _, exists := s.entries[ticketKey]; exists {
		return "", errors.New("handoff ticket collision")
	}
	expires := now.Add(handoffTicketTTL)
	if pending.parentExpires.Before(expires) {
		expires = pending.parentExpires
	}
	s.tickets[ticketKey] = handoffTicket{binding: pending.binding, centralNonceHash: pending.centralNonceHash, vendorNonceHash: pending.vendorNonceHash, target: pending.target, expires: expires}
	delete(s.entries, key)
	return ticket, nil
}

// inspectTicket is not redemption. It returns a value copy for the exact vendor
// mapping/authority and browser nonce, without needing central credentials.
// A future ticket-to-grant transition must consume/create atomically, after live
// authorization; do not implement it as inspection followed by separate removal.
func (s *pendingHandoffs) inspectTicket(token string, mapping db.ProxyHostname, authority, nonce string, now time.Time) (handoffTicket, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(now)
	if !validLaunchToken(token) || !validLaunchToken(nonce) {
		return handoffTicket{}, false
	}
	ticket, found := s.tickets[local.HashToken(token)]
	if !found || ticket.binding.hostname != mapping.Hostname || ticket.binding.label != mapping.Label || ticket.binding.proxyAuthority != authority || ticket.vendorNonceHash != local.HashToken(nonce) {
		return handoffTicket{}, false
	}
	return ticket, true
}

// removeParent accepts a trusted parent reference for explicit local cleanup.
// Durable revocation and live validation are still required before grant use.
func (s *pendingHandoffs) removeParent(parentSessionID string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(now)
	for key, pending := range s.entries {
		if pending.binding.parentSessionID == parentSessionID {
			delete(s.entries, key)
		}
	}
	for key, ticket := range s.tickets {
		if ticket.binding.parentSessionID == parentSessionID {
			delete(s.tickets, key)
		}
	}
}

func (s *pendingHandoffs) cleanup(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(now)
}

func (s *pendingHandoffs) cleanupLocked(now time.Time) {
	for key, pending := range s.entries {
		if !now.Before(pending.expires) {
			delete(s.entries, key)
		}
	}
	for key, ticket := range s.tickets {
		if !now.Before(ticket.expires) {
			delete(s.tickets, key)
		}
	}
}
