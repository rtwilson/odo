package api

import (
	"crypto/subtle"
	"errors"
	"sync"
	"time"

	"example.org/odo/internal/auth/local"
	"example.org/odo/internal/db"
	"example.org/odo/internal/proxy"
)

const (
	pendingHandoffTTL           = 5 * time.Minute
	returnProofTTL              = time.Minute
	maxPendingHandoffs          = 256
	handoffTicketTTL            = time.Minute
	maxHandoffTickets           = 256
	handoffGrantTTL             = 30 * time.Minute
	maxHandoffGrants            = 4096
	maxHandoffGrantsPerParent   = 64
	maxHandoffSessionFieldBytes = 128
)

var (
	errPendingHandoffsFull   = errors.New("pending handoff capacity reached")
	errInvalidPendingHandoff = errors.New("pending handoff state is invalid")
	errHandoffTicketsFull    = errors.New("handoff ticket capacity reached")
	errInvalidHandoffTicket  = errors.New("handoff ticket state is invalid")
	errHandoffGrantsFull     = errors.New("host grant capacity reached")
)

// All fields must come from authenticated/current datastore and deployment
// state, never directly from request cookies, Host headers or query parameters.
// Registry identity is the hostname/label pair, not a resource identifier.
type handoffBinding struct {
	parentUserID      string
	parentAuthVersion int64
	parentSessionID   string
	parentSessionHash string
	hostname          string
	label             string
	proxyAuthority    string
}

type pendingHandoff struct {
	returnProofHash    string
	returnProofExpires time.Time
	binding            handoffBinding
	centralNonceHash   string
	vendorNonceHash    string
	target             string
	resourceID         string
	created            time.Time
	expires            time.Time
	parentExpires      time.Time
}

type handoffTicket struct {
	binding          handoffBinding
	centralNonceHash string
	vendorNonceHash  string
	target           string
	resourceID       string
	created          time.Time
	expires          time.Time
	parentExpires    time.Time
}

// A grant retains no target, browser nonce or browsing history.
type handoffGrant struct {
	binding handoffBinding
	created time.Time
	expires time.Time
}

// This passive store has no routes, cookie handling, database access, DNS or
// fetching. It is deliberately not attached to Server yet. Its records alone
// do not authorize a target, parent session or registry entry.
type pendingHandoffs struct {
	mu      sync.Mutex
	entries map[string]pendingHandoff
	tickets map[string]handoffTicket
	grants  map[string]handoffGrant
}

func newPendingHandoffs() *pendingHandoffs {
	return &pendingHandoffs{entries: make(map[string]pendingHandoff), tickets: make(map[string]handoffTicket), grants: make(map[string]handoffGrant)}
}

func (s *pendingHandoffs) create(binding handoffBinding, target, resourceID, centralNonce string, parentExpires, now time.Time) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(now)
	// Bound every retained input, not only the number of records. Syntax checks
	// do not establish live session validity, registry membership or SSRF safety.
	if resourceID == "" || len(resourceID) > maxHandoffSessionFieldBytes ||
		binding.parentUserID == "" || len(binding.parentUserID) > maxHandoffSessionFieldBytes || binding.parentAuthVersion < 0 ||
		binding.parentSessionID == "" || len(binding.parentSessionID) > maxHandoffSessionFieldBytes ||
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
	if _, exists := s.grants[key]; exists {
		return "", errors.New("pending handoff token collision")
	}
	expires := now.Add(pendingHandoffTTL)
	if parentExpires.Before(expires) {
		expires = parentExpires
	}
	s.entries[key] = pendingHandoff{binding: binding, centralNonceHash: local.HashToken(centralNonce), target: parsed.String(), resourceID: resourceID, created: now, expires: expires, parentExpires: parentExpires}
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

// prepare binds the vendor browser nonce once and issues a fresh return proof.
// Only the caller performing vendor preflight receives the raw proof; inspection
// cannot recover it. Same-nonce retries replace only this record's proof.
func (s *pendingHandoffs) prepare(token string, mapping db.ProxyHostname, authority, nonce string, now time.Time) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(now)
	if !validLaunchToken(token) || !validLaunchToken(nonce) {
		return "", errInvalidPendingHandoff
	}
	key := local.HashToken(token)
	pending, found := s.entries[key]
	if !found || pending.binding.hostname != mapping.Hostname || pending.binding.label != mapping.Label || pending.binding.proxyAuthority != authority {
		return "", errInvalidPendingHandoff
	}
	hash := local.HashToken(nonce)
	if pending.vendorNonceHash != "" && pending.vendorNonceHash != hash {
		return "", errInvalidPendingHandoff
	}
	proof, err := local.NewToken("", 32)
	if err != nil {
		return "", errors.New("handoff return proof generation failed")
	}
	proofHash := local.HashToken(proof)
	if proofHash == key || proofHash == hash || proofHash == pending.centralNonceHash || proofHash == pending.returnProofHash {
		return "", errors.New("handoff return proof collision")
	}
	expires := now.Add(returnProofTTL)
	if pending.expires.Before(expires) {
		expires = pending.expires
	}
	pending.vendorNonceHash = hash
	pending.returnProofHash = proofHash
	pending.returnProofExpires = expires
	s.entries[key] = pending
	return proof, nil
}

// This check is repeated under the store lock at confirmation, so proof rotation
// between live authorization and the transition cannot authorize an old proof.
func (p pendingHandoff) acceptsReturnProof(proof string, now time.Time) bool {
	return validLaunchToken(proof) && now.Before(p.returnProofExpires) &&
		subtle.ConstantTimeCompare([]byte(p.returnProofHash), []byte(local.HashToken(proof))) == 1
}

// confirm atomically replaces a prepared handoff with a bounded ticket. The
// caller must first check live parent/user, registry, method and target safety.
// Capacity/randomness/collision failure preserves pending state for retry.
func (s *pendingHandoffs) confirm(token string, binding handoffBinding, centralNonce, proof string, now time.Time) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(now)
	if !validLaunchToken(token) || !validLaunchToken(centralNonce) {
		return "", errInvalidPendingHandoff
	}
	key := local.HashToken(token)
	pending, found := s.entries[key]
	if !found || pending.binding != binding || pending.centralNonceHash != local.HashToken(centralNonce) || pending.vendorNonceHash == "" || !pending.acceptsReturnProof(proof, now) {
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
	if _, exists := s.grants[ticketKey]; exists {
		return "", errors.New("handoff ticket collision")
	}
	expires := now.Add(handoffTicketTTL)
	if pending.parentExpires.Before(expires) {
		expires = pending.parentExpires
	}
	s.tickets[ticketKey] = handoffTicket{binding: pending.binding, centralNonceHash: pending.centralNonceHash, vendorNonceHash: pending.vendorNonceHash, target: pending.target, resourceID: pending.resourceID, created: now, expires: expires, parentExpires: pending.parentExpires}
	delete(s.entries, key)
	return ticket, nil
}

// inspectTicket is not redemption. It returns a value copy for the exact vendor
// mapping/authority and browser nonce, without needing central credentials.
// HTTP redemption must recheck live authorization before calling redeem;
// inspection followed by a separate consume step would not be atomic.
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

// redeem atomically replaces a ticket with a grant and returns the stored target
// separately, so no destination survives in grant state. binding must include
// the parent reference verified by the caller, not a client-supplied session ID.
// All failures preserve a live ticket; replay cannot produce another grant.
func (s *pendingHandoffs) redeem(token string, binding handoffBinding, vendorNonce string, now time.Time) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(now)
	if !validLaunchToken(token) || !validLaunchToken(vendorNonce) {
		return "", "", errInvalidHandoffTicket
	}
	key := local.HashToken(token)
	ticket, found := s.tickets[key]
	if !found || ticket.binding != binding || ticket.vendorNonceHash != local.HashToken(vendorNonce) {
		return "", "", errInvalidHandoffTicket
	}
	if len(s.grants) >= maxHandoffGrants {
		return "", "", errHandoffGrantsFull
	}
	parentCount := 0
	for _, grant := range s.grants {
		if grant.binding.parentSessionID == binding.parentSessionID {
			parentCount++
		}
	}
	if parentCount >= maxHandoffGrantsPerParent {
		return "", "", errHandoffGrantsFull
	}
	grantToken, err := local.NewToken("", 32)
	if err != nil {
		return "", "", errors.New("host grant token generation failed")
	}
	grantKey := local.HashToken(grantToken)
	if _, exists := s.grants[grantKey]; exists {
		return "", "", errors.New("host grant token collision")
	}
	if _, exists := s.tickets[grantKey]; exists {
		return "", "", errors.New("host grant token collision")
	}
	if _, exists := s.entries[grantKey]; exists {
		return "", "", errors.New("host grant token collision")
	}
	expires := now.Add(handoffGrantTTL)
	if ticket.parentExpires.Before(expires) {
		expires = ticket.parentExpires
	}
	s.grants[grantKey] = handoffGrant{binding: ticket.binding, created: now, expires: expires}
	delete(s.tickets, key)
	return grantToken, ticket.target, nil
}

// inspectGrant locates state for the exact admitted vendor origin. It does not
// renew the grant or authorize a fetch. The caller must validate its trusted
// parent reference and current user/policy/safety before using vendor content.
func (s *pendingHandoffs) inspectGrant(token string, mapping db.ProxyHostname, authority string, now time.Time) (handoffGrant, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(now)
	if !validLaunchToken(token) {
		return handoffGrant{}, false
	}
	grant, found := s.grants[local.HashToken(token)]
	if !found || grant.binding.hostname != mapping.Hostname || grant.binding.label != mapping.Label || grant.binding.proxyAuthority != authority {
		return handoffGrant{}, false
	}
	return grant, true
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
	for key, grant := range s.grants {
		if grant.binding.parentSessionID == parentSessionID {
			delete(s.grants, key)
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
	for key, grant := range s.grants {
		if !now.Before(grant.expires) {
			delete(s.grants, key)
		}
	}
}
