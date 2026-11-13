package api

import (
	"crypto/subtle"
	"errors"
	"net/url"
	"sync"
	"time"

	"example.org/odo/internal/auth/local"
	"example.org/odo/internal/db"
	"example.org/odo/internal/proxy"
)

const (
	pendingHandoffTTL         = 5 * time.Minute
	returnProofTTL            = time.Minute
	maxPendingHandoffs        = 256
	handoffTicketTTL          = time.Minute
	maxHandoffTickets         = 256
	handoffGrantTTL           = 30 * time.Minute
	handoffGrantRenewInterval = time.Minute
	maxHandoffGrants          = 4096
	maxHandoffGrantsPerParent = 64
	// maxSiblingHosts bounds the extra hosts one redemption grants, keeping the
	// redirect chain well under browser redirect limits.
	maxSiblingHosts             = 6
	siblingTicketTTL            = 30 * time.Second
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

// A grant retains no target, browser nonce or browsing history. expires is an
// inactivity deadline that authorized use may slide; limit is the parent's
// absolute session expiry, which no renewal can exceed.
type handoffGrant struct {
	binding handoffBinding
	created time.Time
	expires time.Time
	limit   time.Time
	// family links the grants one redemption issued for a resource's hosts.
	// Renewing any member renews all of them; it is never a credential.
	family string
}

// A siblingTicket lets the browser, already redirected through one redemption,
// pick up a host-only grant on another registered host of the same resource.
// It is single-use, short-lived, bound to the redeemed parent and family, and
// stores the next hop server-side so no destination appears in URLs.
type siblingTicket struct {
	binding       handoffBinding
	resourceID    string
	family        string
	next          string
	expires       time.Time
	parentExpires time.Time
}

// This passive store has no routes, cookie handling, database access, DNS or
// fetching. The experimental handoff runtime (handoffSecurity.state) owns one
// per Server. Its records alone do not authorize a target, parent session or
// registry entry.
type pendingHandoffs struct {
	mu      sync.Mutex
	entries map[string]pendingHandoff
	tickets map[string]handoffTicket
	grants  map[string]handoffGrant
	// siblings are pending cross-host grant hops (see siblingTicket).
	siblings map[string]siblingTicket
	// lastSweep throttles full expiry sweeps; lookups check their own key.
	lastSweep time.Time
	// persist, when set, keeps host grants across restarts (write-through).
	// Pending handoffs, tickets and sibling hops stay memory-only: they live
	// for seconds to minutes and a restart simply restarts the flow.
	persist          grantStore
	lastPersistSweep time.Time
}

// grantStore persists host grants. A stored grant is a cache entry, never an
// authority: each use re-validates the live parent session, account version,
// registry mapping, resource policy and DNS safety.
type grantStore interface {
	SaveHandoffGrants([]db.HandoffGrantRecord) error
	DeleteHandoffGrantsForParent(string) error
	DeleteExpiredHandoffGrants(time.Time) error
	LiveHandoffGrants(time.Time) ([]db.HandoffGrantRecord, error)
}

// persistedGrantSweepInterval bounds how often expired grant rows are deleted.
const persistedGrantSweepInterval = 10 * time.Minute

func grantRecord(key string, g handoffGrant) db.HandoffGrantRecord {
	b := g.binding
	return db.HandoffGrantRecord{
		TokenHash: key, ParentUserID: b.parentUserID, ParentAuthVersion: b.parentAuthVersion,
		ParentSessionID: b.parentSessionID, ParentSessionHash: b.parentSessionHash, Hostname: b.hostname,
		Label: b.label, ProxyAuthority: b.proxyAuthority, Family: g.family,
		Created: g.created, Expires: g.expires, Limit: g.limit,
	}
}

// saveGrantsLocked writes grants through to the store, if any.
func (s *pendingHandoffs) saveGrantsLocked(records ...db.HandoffGrantRecord) error {
	if s.persist == nil {
		return nil
	}
	return s.persist.SaveHandoffGrants(records)
}

// loadGrants restores live persisted grants at startup, within the same
// capacity bounds as newly issued ones.
func (s *pendingHandoffs) loadGrants(now time.Time) error {
	if s.persist == nil {
		return nil
	}
	records, err := s.persist.LiveHandoffGrants(now)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	perParent := map[string]int{}
	for _, r := range records {
		if len(s.grants) >= maxHandoffGrants || perParent[r.ParentSessionID] >= maxHandoffGrantsPerParent || !now.Before(r.Expires) {
			continue
		}
		perParent[r.ParentSessionID]++
		s.grants[r.TokenHash] = handoffGrant{
			binding: handoffBinding{parentUserID: r.ParentUserID, parentAuthVersion: r.ParentAuthVersion, parentSessionID: r.ParentSessionID,
				parentSessionHash: r.ParentSessionHash, hostname: r.Hostname, label: r.Label, proxyAuthority: r.ProxyAuthority},
			created: r.Created, expires: r.Expires, limit: r.Limit, family: r.Family,
		}
	}
	return nil
}

// handoffSweepInterval bounds how often every record is scanned. Lookups never
// depend on the sweep: they treat an expired record as absent themselves, and
// capacity checks sweep before refusing.
const handoffSweepInterval = time.Second

func newPendingHandoffs() *pendingHandoffs {
	return &pendingHandoffs{entries: make(map[string]pendingHandoff), tickets: make(map[string]handoffTicket), grants: make(map[string]handoffGrant), siblings: make(map[string]siblingTicket)}
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
		s.sweepLocked(now)
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
	pending, found := s.liveEntry(local.HashToken(token), now)
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
	pending, found := s.liveEntry(key, now)
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
	pending, found := s.liveEntry(key, now)
	if !found || pending.binding != binding || pending.centralNonceHash != local.HashToken(centralNonce) || pending.vendorNonceHash == "" || !pending.acceptsReturnProof(proof, now) {
		return "", errInvalidPendingHandoff
	}
	if len(s.tickets) >= maxHandoffTickets {
		s.sweepLocked(now)
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
	ticket, found := s.liveTicket(local.HashToken(token), now)
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
	ticket, found := s.liveTicket(key, now)
	if !found || ticket.binding != binding || ticket.vendorNonceHash != local.HashToken(vendorNonce) {
		return "", "", errInvalidHandoffTicket
	}
	if len(s.grants) >= maxHandoffGrants {
		s.sweepLocked(now)
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
	grant := handoffGrant{binding: ticket.binding, created: now, expires: expires, limit: ticket.parentExpires, family: grantKey}
	// Fail closed: a grant that cannot be saved is not issued, and the ticket
	// stays live for a retry.
	if err := s.saveGrantsLocked(grantRecord(grantKey, grant)); err != nil {
		return "", "", errors.New("host grant could not be saved")
	}
	s.grants[grantKey] = grant
	delete(s.tickets, key)
	return grantToken, ticket.target, nil
}

// renewGrant slides a live grant's inactivity deadline to now+handoffGrantTTL,
// capped at the parent's absolute expiry. Call it only after a use was fully
// authorized: it checks the exact host binding but is not authorization. It is
// throttled to handoffGrantRenewInterval so routine assets do not rewrite the
// grant cookie, and it never revives an expired or removed grant.
func (s *pendingHandoffs) renewGrant(token string, mapping db.ProxyHostname, authority string, now time.Time) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(now)
	if !validLaunchToken(token) {
		return time.Time{}, false
	}
	key := local.HashToken(token)
	grant, found := s.liveGrant(key, now)
	if !found || grant.binding.hostname != mapping.Hostname || grant.binding.label != mapping.Label || grant.binding.proxyAuthority != authority {
		return time.Time{}, false
	}
	next := now.Add(handoffGrantTTL)
	if grant.limit.Before(next) {
		next = grant.limit
	}
	if next.Sub(grant.expires) < handoffGrantRenewInterval {
		return grant.expires, false
	}
	grant.expires = next
	s.grants[key] = grant
	changed := []db.HandoffGrantRecord{grantRecord(key, grant)}
	// Assets on sibling hosts are used whenever the main host is, so keep the
	// whole family alive together, never past each member's own limit.
	if grant.family != "" {
		for otherKey, other := range s.grants {
			if otherKey == key || other.family != grant.family || other.binding.parentSessionID != grant.binding.parentSessionID {
				continue
			}
			deadline := now.Add(handoffGrantTTL)
			if other.limit.Before(deadline) {
				deadline = other.limit
			}
			if deadline.After(other.expires) {
				other.expires = deadline
				s.grants[otherKey] = other
				changed = append(changed, grantRecord(otherKey, other))
			}
		}
	}
	// Renewal is not authorization; if it cannot be saved, the stored grant
	// simply expires sooner after a restart (failing closed).
	_ = s.saveGrantsLocked(changed...)
	return next, true
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
	grant, found := s.liveGrant(local.HashToken(token), now)
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
	for key, sibling := range s.siblings {
		if sibling.binding.parentSessionID == parentSessionID {
			delete(s.siblings, key)
		}
	}
	if s.persist != nil {
		// Live parent validation stays authoritative if this delete fails.
		_ = s.persist.DeleteHandoffGrantsForParent(parentSessionID)
	}
}

func (s *pendingHandoffs) cleanup(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(now)
}

// cleanupLocked runs a full sweep at most once per handoffSweepInterval (or
// whenever the clock moves backwards), so routine vendor requests do not scan
// every record under the lock.
func (s *pendingHandoffs) cleanupLocked(now time.Time) {
	if !s.lastSweep.IsZero() && !now.Before(s.lastSweep) && now.Sub(s.lastSweep) < handoffSweepInterval {
		return
	}
	s.sweepLocked(now)
}

func (s *pendingHandoffs) liveEntry(key string, now time.Time) (pendingHandoff, bool) {
	pending, found := s.entries[key]
	if found && !now.Before(pending.expires) {
		delete(s.entries, key)
		return pendingHandoff{}, false
	}
	return pending, found
}

func (s *pendingHandoffs) liveTicket(key string, now time.Time) (handoffTicket, bool) {
	ticket, found := s.tickets[key]
	if found && !now.Before(ticket.expires) {
		delete(s.tickets, key)
		return handoffTicket{}, false
	}
	return ticket, found
}

func (s *pendingHandoffs) liveGrant(key string, now time.Time) (handoffGrant, bool) {
	grant, found := s.grants[key]
	if found && !now.Before(grant.expires) {
		delete(s.grants, key)
		return handoffGrant{}, false
	}
	return grant, found
}

func (s *pendingHandoffs) sweepLocked(now time.Time) {
	s.lastSweep = now
	if s.persist != nil && (s.lastPersistSweep.IsZero() || now.Sub(s.lastPersistSweep) >= persistedGrantSweepInterval || now.Before(s.lastPersistSweep)) {
		s.lastPersistSweep = now
		_ = s.persist.DeleteExpiredHandoffGrants(now)
	}
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
	for key, sibling := range s.siblings {
		if !now.Before(sibling.expires) {
			delete(s.siblings, key)
		}
	}
}

// grantFamily returns the family and limit of a live grant, for issuing its
// sibling hops. It authorizes nothing.
func (s *pendingHandoffs) grantFamily(token string, now time.Time) (handoffGrant, bool) {
	if !validLaunchToken(token) {
		return handoffGrant{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.liveGrant(local.HashToken(token), now)
}

// issueSiblings creates one single-use hop per host, chained in order and
// ending at final. It returns the first hop's URL. Hosts must be registered
// mappings the caller verified for this grant's resource; bindings copy the
// parent of grant, so a hop can only extend that same patron session.
func (s *pendingHandoffs) issueSiblings(grant handoffGrant, resourceID string, hosts []siblingHost, final string, now time.Time) (string, error) {
	if len(hosts) == 0 {
		return final, nil
	}
	if len(hosts) > maxSiblingHosts || resourceID == "" || grant.family == "" {
		return "", errHandoffDenied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.siblings)+len(hosts) > maxHandoffTickets {
		s.sweepLocked(now)
	}
	if len(s.siblings)+len(hosts) > maxHandoffTickets {
		return "", errHandoffTicketsFull
	}
	expires := now.Add(siblingTicketTTL)
	if grant.limit.Before(expires) {
		expires = grant.limit
	}
	next := final
	created := make([]string, 0, len(hosts))
	for i := len(hosts) - 1; i >= 0; i-- {
		host := hosts[i]
		token, err := local.NewToken("", 32)
		if err != nil {
			for _, key := range created {
				delete(s.siblings, key)
			}
			return "", errors.New("sibling ticket generation failed")
		}
		key := local.HashToken(token)
		binding := grant.binding
		binding.hostname, binding.label, binding.proxyAuthority = host.mapping.Hostname, host.mapping.Label, host.authority
		s.siblings[key] = siblingTicket{binding: binding, resourceID: resourceID, family: grant.family, next: next, expires: expires, parentExpires: grant.limit}
		created = append(created, key)
		next = (&url.URL{Scheme: "https", Host: host.authority, Path: handoffVendorPath, RawQuery: url.Values{"sibling": {token}}.Encode()}).String()
	}
	return next, nil
}

// inspectSibling returns a live sibling hop for this exact host without
// consuming it, so the caller can recheck the parent and resource first.
func (s *pendingHandoffs) inspectSibling(token string, mapping db.ProxyHostname, authority string, now time.Time) (siblingTicket, bool) {
	if !validLaunchToken(token) {
		return siblingTicket{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := local.HashToken(token)
	sibling, found := s.siblings[key]
	if found && !now.Before(sibling.expires) {
		delete(s.siblings, key)
		return siblingTicket{}, false
	}
	if !found || sibling.binding.hostname != mapping.Hostname || sibling.binding.label != mapping.Label || sibling.binding.proxyAuthority != authority {
		return siblingTicket{}, false
	}
	return sibling, true
}

// discardSibling consumes a sibling hop without issuing a grant and returns
// the hop's stored continuation. Replays find nothing.
func (s *pendingHandoffs) discardSibling(token string, binding handoffBinding, now time.Time) (string, bool) {
	if !validLaunchToken(token) {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := local.HashToken(token)
	sibling, found := s.siblings[key]
	if !found || !now.Before(sibling.expires) || sibling.binding != binding {
		return "", false
	}
	delete(s.siblings, key)
	return sibling.next, true
}

// redeemSibling consumes a sibling hop and issues its host-only grant in the
// same family. Replays find nothing.
func (s *pendingHandoffs) redeemSibling(token string, binding handoffBinding, now time.Time) (string, handoffGrant, error) {
	if !validLaunchToken(token) {
		return "", handoffGrant{}, errInvalidHandoffTicket
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := local.HashToken(token)
	sibling, found := s.siblings[key]
	if !found || !now.Before(sibling.expires) || sibling.binding != binding {
		return "", handoffGrant{}, errInvalidHandoffTicket
	}
	delete(s.siblings, key)
	if len(s.grants) >= maxHandoffGrants {
		s.sweepLocked(now)
	}
	if len(s.grants) >= maxHandoffGrants {
		return "", handoffGrant{}, errHandoffGrantsFull
	}
	parentCount := 0
	for _, grant := range s.grants {
		if grant.binding.parentSessionID == binding.parentSessionID {
			parentCount++
		}
	}
	if parentCount >= maxHandoffGrantsPerParent {
		return "", handoffGrant{}, errHandoffGrantsFull
	}
	grantToken, err := local.NewToken("", 32)
	if err != nil {
		return "", handoffGrant{}, errors.New("host grant token generation failed")
	}
	grantKey := local.HashToken(grantToken)
	if _, exists := s.grants[grantKey]; exists {
		return "", handoffGrant{}, errors.New("host grant token collision")
	}
	expires := now.Add(handoffGrantTTL)
	if sibling.parentExpires.Before(expires) {
		expires = sibling.parentExpires
	}
	grant := handoffGrant{binding: binding, created: now, expires: expires, limit: sibling.parentExpires, family: sibling.family}
	if err := s.saveGrantsLocked(grantRecord(grantKey, grant)); err != nil {
		return "", handoffGrant{}, errors.New("host grant could not be saved")
	}
	s.grants[grantKey] = grant
	return grantToken, grant, nil
}

// siblingHost is one verified registered host of a resource and its authority.
type siblingHost struct {
	mapping   db.ProxyHostname
	authority string
}
