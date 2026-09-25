package api

import (
	"crypto/sha256"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	loginFailureWindow = 10 * time.Minute
	loginLockout       = time.Minute
	loginAccountLimit  = 5
	loginSourceLimit   = 20
	loginMaxKeys       = 10000
)

type loginFailureState struct {
	expires      time.Time
	blockedUntil time.Time
	lastAudit    time.Time
	failures     int
	pending      int
}

// loginThrottle is process-local. Pending attempts reserve capacity before any
// database lookup or bcrypt work, so concurrent requests cannot bypass limits.
type loginThrottle struct {
	mu                sync.Mutex
	entries           map[[32]byte]*loginFailureState
	nextPrune         time.Time
	lastCapacityAudit time.Time
}

type loginAttempt struct {
	accountKey, sourceKey [32]byte
	account, source       *loginFailureState
}

func newLoginThrottle() *loginThrottle {
	return &loginThrottle{entries: make(map[[32]byte]*loginFailureState)}
}

func loginSourceKey(remoteAddr string) string {
	host := remoteIPOnly(remoteAddr)
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	// Real HTTP connections have an IP address. Malformed addresses share one
	// bucket rather than allowing arbitrary strings to create new source keys.
	return "unknown"
}

func (l *loginThrottle) begin(username, source string, now time.Time) (*loginAttempt, string, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !now.Before(l.nextPrune) {
		for key, state := range l.entries {
			if state.pending == 0 && !now.Before(state.expires) {
				delete(l.entries, key)
			}
		}
		l.nextPrune = now.Add(time.Minute)
	}
	accountKey := sha256.Sum256([]byte("account:" + strings.ToLower(strings.TrimSpace(username))))
	sourceKey := sha256.Sum256([]byte("source:" + source))
	keys := [2][32]byte{accountKey, sourceKey}
	limits := [2]int{loginAccountLimit, loginSourceLimit}
	reasons := [2]string{"account", "source"}
	var states [2]*loginFailureState
	missing := 0
	for i, key := range keys {
		state := l.entries[key]
		if state != nil && state.pending == 0 && !now.Before(state.expires) {
			delete(l.entries, key)
			state = nil
		}
		states[i] = state
		if state == nil {
			missing++
			continue
		}
		blocked := now.Before(state.blockedUntil)
		if state.failures >= limits[i] {
			// After a cooldown, allow one probe at a time until window expiry.
			blocked = blocked || state.pending > 0
		} else {
			blocked = blocked || state.failures+state.pending >= limits[i]
		}
		if blocked {
			audit := state.lastAudit.IsZero() || now.Sub(state.lastAudit) >= time.Minute
			if audit {
				state.lastAudit = now
			}
			return nil, reasons[i], audit
		}
	}
	if len(l.entries)+missing > loginMaxKeys {
		// Do not evict live counters: key churn must not reset active lockouts.
		audit := l.lastCapacityAudit.IsZero() || now.Sub(l.lastCapacityAudit) >= time.Minute
		if audit {
			l.lastCapacityAudit = now
		}
		return nil, "capacity", audit
	}
	for i, key := range keys {
		if states[i] == nil {
			states[i] = &loginFailureState{expires: now.Add(loginFailureWindow)}
			l.entries[key] = states[i]
		}
		states[i].pending++
	}
	return &loginAttempt{accountKey, sourceKey, states[0], states[1]}, "", false
}

// finish releases reservations on every outcome, including internal errors.
// Only credential failures count; successful sessions clear account failures
// while source failures persist. Returns true on a threshold crossing.
func (l *loginThrottle) finish(attempt *loginAttempt, failed, success bool, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	excessive := false
	states := [2]*loginFailureState{attempt.account, attempt.source}
	keys := [2][32]byte{attempt.accountKey, attempt.sourceKey}
	limits := [2]int{loginAccountLimit, loginSourceLimit}
	for i, state := range states {
		state.pending--
		if failed {
			if state.failures < limits[i] {
				state.failures++
				excessive = excessive || state.failures == limits[i]
			}
			if state.failures >= limits[i] && !now.Before(state.blockedUntil) {
				state.blockedUntil = now.Add(loginLockout)
			}
		}
		if success && i == 0 {
			state.failures = 0
			state.blockedUntil = time.Time{}
			state.lastAudit = time.Time{}
		}
		if state.pending == 0 && state.failures == 0 {
			delete(l.entries, keys[i])
		}
	}
	return excessive
}
