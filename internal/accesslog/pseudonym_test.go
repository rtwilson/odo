package accesslog

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPatronKeyFollowsRotationPolicy(t *testing.T) {
	p, err := NewPseudonymizer(strings.Repeat("s", 32))
	if err != nil {
		t.Fatal(err)
	}
	other, _ := NewPseudonymizer(strings.Repeat("t", 32))
	early := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	late := time.Date(2026, 11, 30, 23, 59, 59, 0, time.UTC)
	next := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	key := p.Key("user_a", "sess_1", early)
	if !strings.HasPrefix(key, "pk_") || len(key) != 27 || p.Key("user_a", "sess_2", late) != key {
		t.Fatalf("default monthly key not stable within a month across sessions: %q", key)
	}
	if p.Key("user_a", "sess_1", next) == key || p.Key("user_b", "sess_1", early) == key || other.Key("user_a", "sess_1", early) == key {
		t.Fatal("key must change by period, user and secret")
	}
	if p.Key("", "sess_1", early) != "" {
		t.Fatal("anonymous request got a key")
	}

	never := RotationPolicy{Mode: RotationNever}
	if p.KeyUnder(never, "user_a", "sess_1", early) != p.KeyUnder(never, "user_a", "sess_9", early.AddDate(5, 0, 0)) {
		t.Fatal("never-rotating key changed")
	}
	session := RotationPolicy{Mode: RotationSession}
	if p.KeyUnder(session, "user_a", "sess_1", early) != p.KeyUnder(session, "user_a", "sess_1", next.AddDate(1, 0, 0)) ||
		p.KeyUnder(session, "user_a", "sess_1", early) == p.KeyUnder(session, "user_a", "sess_2", early) {
		t.Fatal("session key must follow the session only")
	}
	for _, policy := range []RotationPolicy{never, session, {Mode: RotationTime, Unit: UnitDay, Count: 1}} {
		if p.KeyUnder(policy, "user_a", "sess_1", early) == key {
			t.Fatalf("%+v key collides with the monthly key", policy)
		}
	}
	p.SetPolicy(RotationPolicy{Mode: RotationTime, Unit: UnitDay, Count: 3})
	if p.Policy().Unit != UnitDay || p.Key("user_a", "", early) == key {
		t.Fatal("policy change not applied to new keys")
	}
	p.SetPolicy(RotationPolicy{Mode: "bogus"})
	if p.Policy().Unit != UnitDay {
		t.Fatal("invalid policy replaced the current one")
	}
}

func TestRotationWindows(t *testing.T) {
	at := time.Date(2026, 11, 13, 15, 0, 0, 0, time.UTC) // a Friday
	for _, tc := range []struct {
		policy     RotationPolicy
		start, end string
	}{
		{RotationPolicy{Mode: RotationTime, Unit: UnitDay, Count: 1}, "2026-11-13", "2026-11-14"},
		{RotationPolicy{Mode: RotationTime, Unit: UnitWeek, Count: 1}, "2026-11-09", "2026-11-16"},
		{RotationPolicy{Mode: RotationTime, Unit: UnitMonth, Count: 1}, "2026-11-01", "2026-12-01"},
		{RotationPolicy{Mode: RotationTime, Unit: UnitMonth, Count: 3}, "2026-10-01", "2027-01-01"},
	} {
		start, end, label := tc.policy.Window(at)
		if start.Format("2006-01-02") != tc.start || end.Format("2006-01-02") != tc.end || label == "" {
			t.Fatalf("%+v: %s..%s", tc.policy, start, end)
		}
		if again, _, sameLabel := tc.policy.Window(start); !again.Equal(start) || sameLabel != label {
			t.Fatalf("%+v: window start not inside its own window", tc.policy)
		}
		if _, _, nextLabel := tc.policy.Window(end); nextLabel == label {
			t.Fatalf("%+v: window end not exclusive", tc.policy)
		}
	}
}

func TestRotationPolicyValidation(t *testing.T) {
	for _, bad := range []RotationPolicy{{Mode: "monthly"}, {Mode: RotationTime}, {Mode: RotationTime, Unit: "hour", Count: 1},
		{Mode: RotationTime, Unit: UnitDay, Count: 0}, {Mode: RotationTime, Unit: UnitMonth, Count: 25}} {
		if _, err := bad.Normalize(); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	if p, err := (RotationPolicy{Mode: " Never ", Unit: "day", Count: 4}).Normalize(); err != nil || p.Mode != RotationNever || p.Unit != "" || p.Count != 0 {
		t.Fatalf("normalize: %+v %v", p, err)
	}
	if _, err := NewPseudonymizer("short"); err == nil {
		t.Fatal("short secret accepted")
	}
}

// No log format ever writes a raw user or session identifier.
func TestLoggerNeverWritesRawPatronIdentifiers(t *testing.T) {
	for _, format := range []string{FormatPrivacy, FormatJSON, FormatCommon, FormatCombined} {
		var out bytes.Buffer
		logger, err := New(format, &out)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest("GET", "/x", nil)
		ctx, metadata := WithMetadata(req.Context())
		metadata.UserID, metadata.SessionID = "user_secretid", "sess_secretid"
		logger.Log(req.WithContext(ctx), 200, 1, time.Millisecond)
		if strings.Contains(out.String(), "secretid") {
			t.Fatalf("%s format wrote a raw identifier: %s", format, out.String())
		}
		key := logger.Pseudonymizer().Key("user_secretid", "sess_secretid", time.Now())
		if (format == FormatPrivacy || format == FormatJSON) && !strings.Contains(out.String(), key) {
			t.Fatalf("%s format missing patron key: %s", format, out.String())
		}
		if entries := logger.Recent(); entries[0].PatronKey != key {
			t.Fatal("recent entry missing patron key")
		}
	}
}
