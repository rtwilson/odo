package api

import (
	"errors"
	"sync"
	"time"

	"example.org/odo/internal/auth/local"
	"example.org/odo/internal/proxy"
)

const (
	pendingHandoffTTL           = 5 * time.Minute
	maxPendingHandoffs          = 256
	maxHandoffSessionFieldBytes = 128
)

var (
	errPendingHandoffsFull   = errors.New("pending handoff capacity reached")
	errInvalidPendingHandoff = errors.New("pending handoff state is invalid")
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
	target           string
	expires          time.Time
}

// This passive store has no routes, cookie handling, database access, DNS or
// fetching. It is deliberately not attached to Server yet. Its records are not
// credentials and do not authorize a target, parent session or registry entry.
type pendingHandoffs struct {
	mu      sync.Mutex
	entries map[string]pendingHandoff
}

func newPendingHandoffs() *pendingHandoffs {
	return &pendingHandoffs{entries: make(map[string]pendingHandoff)}
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
	expires := now.Add(pendingHandoffTTL)
	if parentExpires.Before(expires) {
		expires = parentExpires
	}
	s.entries[key] = pendingHandoff{binding: binding, centralNonceHash: local.HashToken(centralNonce), target: parsed.String(), expires: expires}
	return token, nil
}

// inspect is non-consuming and returns a value copy, not mutable store state.
// Future confirmation must recheck live authorization and atomically transition
// this record into a ticket under the state lock, not inspect then consume later.
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
}
