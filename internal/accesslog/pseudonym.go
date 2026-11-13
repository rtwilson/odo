package accesslog

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// MinPseudonymSecretBytes is the minimum configured secret length.
const MinPseudonymSecretBytes = 32

// Rotation modes for patron keys.
const (
	RotationNever   = "never"   // one stable key per user
	RotationSession = "session" // a new key for every login session
	RotationTime    = "time"    // a new key every Count Units (UTC-aligned)
)

// Time units for RotationTime.
const (
	UnitDay   = "day"
	UnitWeek  = "week"
	UnitMonth = "month"
)

// RotationPolicy decides how long a patron key stays the same. Policies apply
// from EffectiveFrom onward; earlier lines keep the keys they were written with.
type RotationPolicy struct {
	Mode          string    `json:"mode"`
	Unit          string    `json:"unit,omitempty"`
	Count         int       `json:"count,omitempty"`
	EffectiveFrom time.Time `json:"effective_from"`
}

// DefaultRotationPolicy rotates on UTC calendar months.
func DefaultRotationPolicy() RotationPolicy {
	return RotationPolicy{Mode: RotationTime, Unit: UnitMonth, Count: 1, EffectiveFrom: time.Unix(0, 0).UTC()}
}

// Normalize validates a policy and clears fields its mode does not use.
func (p RotationPolicy) Normalize() (RotationPolicy, error) {
	p.Mode = strings.ToLower(strings.TrimSpace(p.Mode))
	p.Unit = strings.ToLower(strings.TrimSpace(p.Unit))
	switch p.Mode {
	case RotationNever, RotationSession:
		p.Unit, p.Count = "", 0
		return p, nil
	case RotationTime:
	default:
		return p, errors.New("mode must be never, session or time")
	}
	limits := map[string]int{UnitDay: 366, UnitWeek: 104, UnitMonth: 24}
	limit, ok := limits[p.Unit]
	if !ok {
		return p, errors.New("unit must be day, week or month")
	}
	if p.Count < 1 || p.Count > limit {
		return p, fmt.Errorf("count must be between 1 and %d for unit %s", limit, p.Unit)
	}
	return p, nil
}

// Window returns the time-based rotation window containing t: its start, its
// exclusive end and a stable label. Weeks start on Monday; all in UTC.
func (p RotationPolicy) Window(t time.Time) (time.Time, time.Time, string) {
	t = t.UTC()
	switch p.Unit {
	case UnitMonth:
		months := (t.Year()-1970)*12 + int(t.Month()) - 1
		index := floorDiv(months, p.Count)
		start := time.Date(1970, time.Month(1+index*p.Count), 1, 0, 0, 0, 0, time.UTC)
		return start, start.AddDate(0, p.Count, 0), "m" + strconv.Itoa(p.Count) + ":" + strconv.Itoa(index)
	case UnitWeek:
		// 1970-01-05 was a Monday; day 4 since the epoch.
		days := floorDiv(int(t.Unix()), 86400) - 4
		index := floorDiv(days, 7*p.Count)
		start := time.Unix(int64(4+index*7*p.Count)*86400, 0).UTC()
		return start, start.AddDate(0, 0, 7*p.Count), "w" + strconv.Itoa(p.Count) + ":" + strconv.Itoa(index)
	default:
		index := floorDiv(floorDiv(int(t.Unix()), 86400), p.Count)
		start := time.Unix(int64(index*p.Count)*86400, 0).UTC()
		return start, start.AddDate(0, 0, p.Count), "d" + strconv.Itoa(p.Count) + ":" + strconv.Itoa(index)
	}
}

func floorDiv(a, b int) int {
	q := a / b
	if (a%b != 0) && ((a < 0) != (b < 0)) {
		q--
	}
	return q
}

// Pseudonymizer derives the patron key written to access logs in place of user
// and session identifiers: an HMAC under a secret, scoped by the rotation
// policy in force. Re-identification is forward-only: someone authorized and
// holding the secret derives a named user's keys and searches for them. No
// table maps keys back to users.
type Pseudonymizer struct {
	secret []byte
	policy atomic.Pointer[RotationPolicy]
}

var keyEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewPseudonymizer uses a configured secret of at least MinPseudonymSecretBytes
// and the default (monthly) policy.
func NewPseudonymizer(secret string) (*Pseudonymizer, error) {
	if len(secret) < MinPseudonymSecretBytes {
		return nil, errors.New("log pseudonym secret must be at least 32 bytes")
	}
	p := &Pseudonymizer{secret: []byte(secret)}
	p.SetPolicy(DefaultRotationPolicy())
	return p, nil
}

// NewEphemeralPseudonymizer uses a random per-process secret. Keys are still
// unlinkable to users, but cannot be re-identified after a restart.
func NewEphemeralPseudonymizer() *Pseudonymizer {
	secret := make([]byte, MinPseudonymSecretBytes)
	if _, err := rand.Read(secret); err != nil {
		panic("accesslog: random secret unavailable: " + err.Error())
	}
	p := &Pseudonymizer{secret: secret}
	p.SetPolicy(DefaultRotationPolicy())
	return p
}

// SetPolicy changes the policy used for new log lines. Invalid policies are
// ignored, keeping the current one.
func (p *Pseudonymizer) SetPolicy(policy RotationPolicy) {
	if normalized, err := policy.Normalize(); err == nil {
		p.policy.Store(&normalized)
	}
}

// Policy returns the policy currently applied to new log lines.
func (p *Pseudonymizer) Policy() RotationPolicy { return *p.policy.Load() }

// Key returns the current-policy patron key for a request at t, or "" for an
// anonymous request.
func (p *Pseudonymizer) Key(userID, sessionID string, t time.Time) string {
	if p == nil {
		return ""
	}
	return p.KeyUnder(p.Policy(), userID, sessionID, t)
}

// KeyUnder returns the patron key under a specific policy. Session mode needs
// the session ID; a request without one falls back to the user-stable key.
func (p *Pseudonymizer) KeyUnder(policy RotationPolicy, userID, sessionID string, t time.Time) string {
	if p == nil || userID == "" {
		return ""
	}
	var scope string
	switch policy.Mode {
	case RotationSession:
		if sessionID == "" {
			scope = "never"
		} else {
			scope = "session\x00" + sessionID
		}
	case RotationTime:
		_, _, label := policy.Window(t)
		scope = "time\x00" + label
	default:
		scope = "never"
	}
	mac := hmac.New(sha256.New, p.secret)
	mac.Write([]byte("odo-patron-key-v2\x00" + scope + "\x00" + userID))
	return "pk_" + strings.ToLower(keyEncoding.EncodeToString(mac.Sum(nil)[:15]))
}
