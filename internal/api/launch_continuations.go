package api

import (
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"time"

	"example.org/odo/internal/auth/local"
)

const (
	launchContinuationTTL  = 5 * time.Minute
	maxLaunchContinuations = 1024
	launchNonceCookieName  = "odo_launch_nonce"
	launchContinuePath     = "/launch/continue"
)

type pendingLaunch struct {
	target    string
	nonceHash string
	expires   time.Time
}

// Pending destinations live only in bounded process memory. Both URL tokens
// and browser nonces are indexed/stored as hashes, never as bearer credentials.
type launchContinuations struct {
	mu      sync.Mutex
	entries map[string]pendingLaunch
}

func newLaunchContinuations() *launchContinuations {
	return &launchContinuations{entries: make(map[string]pendingLaunch)}
}

func (s *launchContinuations) create(target, nonce string, now time.Time) (string, error) {
	token, err := local.NewToken("", 32)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, pending := range s.entries {
		if !now.Before(pending.expires) {
			delete(s.entries, key)
		}
	}
	// Anonymous visitors create these entries, so refusing new ones at capacity
	// would let anyone deny launch-then-login to every patron. Evict the oldest
	// instead: a flood can at worst displace an older continuation, and that
	// patron still signs in normally, landing on the resource list.
	for len(s.entries) >= maxLaunchContinuations {
		oldestKey, oldest := "", time.Time{}
		for key, pending := range s.entries {
			if oldestKey == "" || pending.expires.Before(oldest) {
				oldestKey, oldest = key, pending.expires
			}
		}
		delete(s.entries, oldestKey)
	}
	key := local.HashToken(token)
	if _, exists := s.entries[key]; exists {
		return "", errors.New("pending launch token collision")
	}
	s.entries[key] = pendingLaunch{target: target, nonceHash: local.HashToken(nonce), expires: now.Add(launchContinuationTTL)}
	return token, nil
}

func (s *launchContinuations) consume(token, nonce string, now time.Time) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := local.HashToken(token)
	pending, found := s.entries[key]
	if !found {
		return "", false
	}
	if !now.Before(pending.expires) {
		delete(s.entries, key)
		return "", false
	}
	if pending.nonceHash != local.HashToken(nonce) {
		return "", false
	}
	delete(s.entries, key)
	return pending.target, true
}

// peek returns a live continuation's target for the browser holding its nonce,
// without consuming it. It is for rendering decisions only (the login page's
// CSP); consume still performs the authoritative one-time check.
func (s *launchContinuations) peek(token, nonce string, now time.Time) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pending, found := s.entries[local.HashToken(token)]
	if !found || !now.Before(pending.expires) || pending.nonceHash != local.HashToken(nonce) {
		return "", false
	}
	return pending.target, true
}

func validLaunchToken(token string) bool {
	if len(token) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	return err == nil && len(token) == 43 && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == token
}

func launchContinuationToken(rawQuery string) (string, bool) {
	if len(rawQuery) != len("token=")+43 || !strings.HasPrefix(rawQuery, "token=") {
		return "", false
	}
	token := strings.TrimPrefix(rawQuery, "token=")
	// Require the exact generated envelope, without aliases or empty segments.
	return token, validLaunchToken(token) && rawQuery == "token="+token
}
