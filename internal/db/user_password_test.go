package db

import (
	"reflect"
	"testing"
)

func TestSetUserPasswordRevokesOnlyTargetSessions(t *testing.T) {
	s := lifecycleStore(t)
	original, _, err := s.GetSession("old-session")
	if err != nil {
		t.Fatal(err)
	}
	for _, session := range []Session{
		{ID: "second-session", UserID: "patron", SessionHash: "second-hash", CreatedAt: original.CreatedAt, LastSeenAt: original.LastSeenAt, ExpiresAt: original.ExpiresAt},
		{ID: "already-revoked", UserID: "patron", SessionHash: "revoked-hash", RevokedAt: "2020-01-01T00:00:00Z", CreatedAt: original.CreatedAt, LastSeenAt: original.LastSeenAt, ExpiresAt: original.ExpiresAt},
		{ID: "admin-session", UserID: "admin", SessionHash: "admin-hash", CreatedAt: original.CreatedAt, LastSeenAt: original.LastSeenAt, ExpiresAt: original.ExpiresAt},
	} {
		if err := s.CreateSession(session); err != nil {
			t.Fatal(err)
		}
	}
	if updated, err := s.SetUserPassword("patron", "replacement-hash"); err != nil || !updated {
		t.Fatalf("set password: updated=%v err=%v", updated, err)
	}
	u, found, err := s.GetUser("patron")
	if err != nil || !found || u.PasswordHash != "replacement-hash" {
		t.Fatal("password not persisted")
	}
	for _, id := range []string{"old-session", "second-session", "already-revoked", "admin-session"} {
		session, found, err := s.GetSession(id)
		if err != nil || !found {
			t.Fatalf("read session %s: found=%v err=%v", id, found, err)
		}
		switch id {
		case "admin-session":
			if session.RevokedAt != "" {
				t.Fatal("revoked another account's session")
			}
		case "already-revoked":
			if session.RevokedAt != "2020-01-01T00:00:00Z" {
				t.Fatal("changed earlier revocation timestamp")
			}
		default:
			if session.RevokedAt == "" {
				t.Fatalf("session %s not revoked", id)
			}
		}
	}
}

func TestSetUserPasswordRollsBackWriteFailures(t *testing.T) {
	for _, failure := range []string{"password", "revocation"} {
		t.Run(failure, func(t *testing.T) {
			s := lifecycleStore(t)
			if _, err := s.db.Exec(`UPDATE users SET updated_at = '2020-01-01T00:00:00Z' WHERE id = 'patron'`); err != nil {
				t.Fatal(err)
			}
			before, _, err := s.GetUser("patron")
			if err != nil {
				t.Fatal(err)
			}
			sessionBefore, _, err := s.GetSession("old-session")
			if err != nil {
				t.Fatal(err)
			}
			trigger := `CREATE TRIGGER fail_password BEFORE UPDATE OF password_hash ON users BEGIN SELECT RAISE(ABORT, 'password write failed'); END`
			if failure == "revocation" {
				trigger = `CREATE TRIGGER fail_revocation BEFORE UPDATE OF revoked_at ON sessions BEGIN SELECT RAISE(ABORT, 'revocation failed'); END`
			}
			if _, err := s.db.Exec(trigger); err != nil {
				t.Fatal(err)
			}
			if updated, err := s.SetUserPassword("patron", "replacement-hash"); err == nil || updated {
				t.Fatalf("reported success on %s failure", failure)
			}
			after, _, err := s.GetUser("patron")
			if err != nil || !reflect.DeepEqual(after, before) {
				t.Fatal("user changed despite rollback")
			}
			sessionAfter, _, err := s.GetSession("old-session")
			if err != nil || sessionAfter != sessionBefore {
				t.Fatal("session changed despite rollback")
			}
		})
	}
}

func TestSetUserPasswordMissingOrDeletedDoesNotRevoke(t *testing.T) {
	s := lifecycleStore(t)
	if _, err := s.DeleteUser("patron", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`CREATE TRIGGER fail_revocation BEFORE UPDATE OF revoked_at ON sessions BEGIN SELECT RAISE(ABORT, 'unnecessary revocation'); END`); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"missing", "patron"} {
		if updated, err := s.SetUserPassword(id, "replacement-hash"); err != nil || updated {
			t.Fatalf("unavailable user %s: updated=%v err=%v", id, updated, err)
		}
	}
	u, _, err := s.GetUser("patron")
	if err != nil || u.Status != "deleted" || u.PasswordHash != "" {
		t.Fatal("modified deleted account")
	}
}
