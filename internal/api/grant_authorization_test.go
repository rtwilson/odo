package api

import (
	"context"
	"net"
	"testing"
	"time"

	"example.org/odo/internal/auth/local"
	"example.org/odo/internal/resources"
)

func TestGrantAuthorizationParentResourceAndDeadline(t *testing.T) {
	for _, kind := range []string{"absolute", "idle"} {
		t.Run(kind, func(t *testing.T) {
			f := newSecurityFixture(t)
			token := f.grant(t)
			parent, _, err := f.h.server.store.GetSession(local.SessionIDFromToken(f.central))
			if err != nil {
				t.Fatal(err)
			}
			now := f.now.Truncate(time.Second).Add(time.Second)
			expires, seen := now.Add(5*time.Minute), now.Add(-5*time.Minute)
			want := expires
			if kind == "idle" {
				expires, seen = now.Add(2*time.Hour), now.Add(-50*time.Minute)
				want = now.Add(10 * time.Minute)
			}
			if _, err := f.control.Exec(`UPDATE sessions SET expires_at=?, last_seen_at=? WHERE id=?`, expires.Format(time.RFC3339), seen.Format(time.RFC3339), parent.ID); err != nil {
				t.Fatal(err)
			}
			got, err := f.h.authorizeGrant(context.Background(), token, f.authority, f.target, "GET", now)
			if err != nil || got.parentSessionID != parent.ID || got.parentSessionHash != parent.SessionHash || got.resourceID != "vendor" || !got.parentExpires.Equal(want) {
				t.Fatalf("incorrect live grant binding/deadline: %v", err)
			}
			after, _, err := f.h.server.store.GetSession(parent.ID)
			if err != nil || after.LastSeenAt != seen.Format(time.RFC3339) {
				t.Fatal("authorization touched session activity")
			}
		})
	}
}

func TestGrantAuthorizationUsesCurrentWinningResource(t *testing.T) {
	f := newSecurityFixture(t)
	token := f.grant(t)
	if _, err := f.h.server.store.DeleteResource("vendor"); err != nil {
		t.Fatal(err)
	}
	if err := f.h.server.store.UpsertResource(resources.Resource{ID: "replacement", Name: "Replacement", Domains: []resources.DomainRule{{Host: "vendor.example"}}}); err != nil {
		t.Fatal(err)
	}
	got, err := f.h.authorizeGrant(context.Background(), token, f.authority, f.target, "GET", f.now)
	if err != nil || got.resourceID != "replacement" {
		t.Fatalf("grant retained its launch resource: %v", err)
	}
}

func TestGrantAuthorizationFailuresReturnNoBinding(t *testing.T) {
	for _, kind := range []string{"token", "authority", "method", "target", "dns", "database", "auth_version", "session_hash", "revoked", "idle boundary", "absolute boundary"} {
		t.Run(kind, func(t *testing.T) {
			f := newSecurityFixture(t)
			token := f.grant(t)
			authority, target, method, now := f.authority, f.target, "GET", f.now
			parentID := local.SessionIDFromToken(f.central)
			var mutation string
			switch kind {
			case "token":
				token = "invalid"
			case "authority":
				authority = "unknown.proxy.example"
			case "method":
				method = "DELETE"
			case "target":
				target = "https://other.example/private"
			case "dns":
				f.h.server.ipLookup = func(context.Context, string) ([]net.IPAddr, error) {
					return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
				}
			case "database":
				mutation = `ALTER TABLE sessions RENAME TO unavailable_sessions`
			case "auth_version":
				mutation = `UPDATE users SET auth_version=auth_version+1`
			case "session_hash":
				mutation = `UPDATE sessions SET session_hash='changed-hash'`
			case "revoked":
				if err := f.h.server.store.RevokeSession(parentID); err != nil {
					t.Fatal(err)
				}
			case "idle boundary", "absolute boundary":
				now = now.Truncate(time.Second).Add(time.Second)
				seen, expires := now, now.Add(time.Hour)
				if kind == "idle boundary" {
					seen = now.Add(-sessionIdleTimeout())
				} else {
					expires = now
				}
				if _, err := f.control.Exec(`UPDATE sessions SET last_seen_at=?, expires_at=? WHERE id=?`, seen.Format(time.RFC3339), expires.Format(time.RFC3339), parentID); err != nil {
					t.Fatal(err)
				}
			}
			if mutation != "" {
				if _, err := f.control.Exec(mutation); err != nil {
					t.Fatal(err)
				}
			}
			got, err := f.h.authorizeGrant(context.Background(), token, authority, target, method, now)
			if err == nil || got != (grantAuthorization{}) {
				t.Fatal("failed authorization returned parent/resource facts")
			}
		})
	}
}
