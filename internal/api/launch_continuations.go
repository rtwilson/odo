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
	maxLaunchContinuations = 256
	launchNonceCookieName  = "odo_launch_nonce"
	launchContinuePath     = "/launch/continue"
)

var errLaunchContinuationsFull = errors.New("pending launch capacity reached")

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
	if len(s.entries) >= maxLaunchContinuations {
		return "", errLaunchContinuationsFull
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
