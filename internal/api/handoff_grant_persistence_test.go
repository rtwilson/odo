package api

import (
	"context"
	"errors"
	"testing"
	"time"

	"example.org/odo/internal/auth/local"
	"example.org/odo/internal/db"
)

// A host grant issued before a restart keeps working on a fresh runtime built
// from the same database, while every live check still applies to it.
func TestHostGrantSurvivesRestart(t *testing.T) {
	d := newDeliveryHarness(t)
	now := time.Now().UTC()
	var stored, raw int
	if err := d.control.QueryRow(`SELECT COUNT(*) FROM handoff_grants WHERE token_hash = ?`, local.HashToken(d.grant)).Scan(&stored); err != nil || stored != 1 {
		t.Fatalf("grant not persisted: %d %v", stored, err)
	}
	if err := d.control.QueryRow(`SELECT COUNT(*) FROM handoff_grants WHERE token_hash = ? OR family = ?`, d.grant, d.grant).Scan(&raw); err != nil || raw != 0 {
		t.Fatal("raw grant token stored")
	}

	restarted, err := newHandoffRuntime(d.h.server, d.h.config)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.validateGrant(context.Background(), d.grant, d.authority, d.target, "GET", now); err != nil {
		t.Fatalf("grant lost across restart: %v", err)
	}
	if err := restarted.validateGrant(context.Background(), d.grant, "other-example.proxy.example", d.target, "GET", now); err == nil {
		t.Fatal("restored grant accepted on another host")
	}
	// Revocation remains authoritative after a restart, and clears the rows.
	if err := d.h.server.store.RevokeSession(local.SessionIDFromToken(d.central)); err != nil {
		t.Fatal(err)
	}
	if err := restarted.validateGrant(context.Background(), d.grant, d.authority, d.target, "GET", now); err == nil {
		t.Fatal("revoked parent's restored grant accepted")
	}
	if err := d.control.QueryRow(`SELECT COUNT(*) FROM handoff_grants`).Scan(&stored); err != nil || stored != 0 {
		t.Fatalf("revoked parent's grant rows remain: %d", stored)
	}
}

type failingGrantStore struct{ grantStore }

func (failingGrantStore) SaveHandoffGrants([]db.HandoffGrantRecord) error {
	return errors.New("disk full")
}

// A grant that cannot be saved is not issued, and its ticket stays usable.
func TestHostGrantNotIssuedWhenItCannotBeSaved(t *testing.T) {
	f := newSecurityFixture(t)
	ticket := f.ticket(t)
	f.h.state.persist = failingGrantStore{}
	if _, _, err := f.h.redeem(context.Background(), ticket, f.authority, f.vendor, f.now); err == nil {
		t.Fatal("grant issued without being saved")
	}
	f.h.state.mu.Lock()
	grants := len(f.h.state.grants)
	f.h.state.mu.Unlock()
	if grants != 0 {
		t.Fatal("unsaved grant kept in memory")
	}
	f.h.state.persist = nil
	if _, _, err := f.h.redeem(context.Background(), ticket, f.authority, f.vendor, f.now); err != nil {
		t.Fatalf("ticket not preserved after save failure: %v", err)
	}
}

// Expired rows are neither loaded nor kept.
func TestExpiredPersistedGrantsAreNotLoaded(t *testing.T) {
	d := newDeliveryHarness(t)
	if _, err := d.control.Exec(`UPDATE handoff_grants SET expires_at = '2000-01-01T00:00:00.000000000Z'`); err != nil {
		t.Fatal(err)
	}
	restarted, err := newHandoffRuntime(d.h.server, d.h.config)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.validateGrant(context.Background(), d.grant, d.authority, d.target, "GET", time.Now().UTC()); err == nil {
		t.Fatal("expired persisted grant loaded")
	}
	restarted.state.cleanup(time.Now().UTC())
	var stored int
	if err := d.control.QueryRow(`SELECT COUNT(*) FROM handoff_grants`).Scan(&stored); err != nil || stored != 0 {
		t.Fatalf("expired grant rows not swept: %d", stored)
	}
}
