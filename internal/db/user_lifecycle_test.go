package db

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func lifecycleStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "odo.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Migrate(); err != nil {
		t.Fatal(err)
	}
	for _, user := range []User{
		{ID: "admin", Username: "admin", Status: "active", Roles: []string{"super_admin"}, PasswordHash: "admin-private-hash"},
		{ID: "patron", Username: "patron", Status: "active", Roles: []string{"user"}, PasswordHash: "patron-private-hash"},
	} {
		if err := s.CreateUser(user); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	if err := s.CreateSession(Session{ID: "old-session", UserID: "patron", SessionHash: "private-session-hash", CreatedAt: now.Format(time.RFC3339), LastSeenAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestDeleteAndRestoreUser(t *testing.T) {
	s := lifecycleStore(t)
	if found, err := s.DeleteUser("patron", "admin"); err != nil || !found {
		t.Fatalf("delete: found=%v err=%v", found, err)
	}
	u, found, err := s.GetUser("patron")
	if err != nil || !found || u.Status != "deleted" || u.PasswordHash != "" || u.DisabledAt == "" {
		t.Fatalf("deleted user: %+v found=%v err=%v", u, found, err)
	}
	session, _, err := s.GetSession("old-session")
	if err != nil || session.RevokedAt == "" {
		t.Fatalf("session not revoked: %+v %v", session, err)
	}
	users, err := s.ListUsers()
	if err != nil || len(users) != 1 || users[0].ID != "admin" {
		t.Fatalf("default list: %+v %v", users, err)
	}
	deleted, err := s.ListDeletedUsers()
	if err != nil || len(deleted) != 1 || deleted[0].ID != "patron" {
		t.Fatalf("deleted list: %+v %v", deleted, err)
	}
	if err := s.CreateUser(User{ID: "replacement", Username: "patron", PasswordHash: "new"}); err == nil {
		t.Fatal("deleted username was reusable")
	}
	if _, found, err := s.SetUserStatus("patron", "active"); !errors.Is(err, ErrUserDeleted) || !found {
		t.Fatalf("enabled deleted account: %v %v", found, err)
	}
	u.Status = "active"
	if _, _, err := s.UpdateUser(u); !errors.Is(err, ErrUserDeleted) {
		t.Fatalf("updated deleted account: %v", err)
	}
	if updated, err := s.SetUserPassword("patron", "bypass"); err != nil || updated {
		t.Fatalf("changed deleted account password: %v %v", updated, err)
	}
	if found, err := s.DeleteUser("patron", "admin"); err != nil || !found {
		t.Fatalf("repeat delete: %v %v", found, err)
	}
	if _, err := s.RestoreUser("patron", "admin", ""); err == nil {
		t.Fatal("restored without new password")
	}
	if found, err := s.RestoreUser("patron", "admin", "fresh-private-hash"); err != nil || !found {
		t.Fatalf("restore: %v %v", found, err)
	}
	u, _, err = s.GetUser("patron")
	if err != nil || u.Status != "disabled" || u.PasswordHash != "fresh-private-hash" {
		t.Fatalf("restored user: %+v %v", u, err)
	}
	if _, _, err := s.SetUserStatus("patron", "active"); err != nil {
		t.Fatal(err)
	}
	after, _, err := s.GetSession("old-session")
	if err != nil || after != session {
		t.Fatalf("restore revived or changed old session: %+v %v", after, err)
	}
	if _, err := s.RestoreUser("patron", "admin", "another"); !errors.Is(err, ErrUserNotDeleted) {
		t.Fatalf("repeat restore: %v", err)
	}
	events, err := s.ListAuditEvents(30)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, e := range events {
		if e.Event != "user_deleted" && e.Event != "user_restored" {
			continue
		}
		counts[e.Event]++
		if !strings.Contains(e.Detail, `"actor_id":"admin"`) || strings.Contains(e.Detail, "hash") || strings.Contains(e.Detail, "session") {
			t.Fatalf("unsafe audit metadata: %s", e.Detail)
		}
	}
	if counts["user_deleted"] != 1 || counts["user_restored"] != 1 {
		t.Fatalf("audit counts: %v", counts)
	}
}

func TestUserDeletionSafety(t *testing.T) {
	s := lifecycleStore(t)
	if _, err := s.DeleteUser("patron", "patron"); !errors.Is(err, ErrDeleteSelf) {
		t.Fatalf("self deletion: %v", err)
	}
	if _, err := s.DeleteUser("admin", ""); !errors.Is(err, ErrLastAdministrator) {
		t.Fatalf("last administrator: %v", err)
	}
	if found, err := s.DeleteUser("missing", "admin"); err != nil || found {
		t.Fatalf("missing delete: %v %v", found, err)
	}
	if found, err := s.RestoreUser("missing", "admin", "hash"); err != nil || found {
		t.Fatalf("missing restore: %v %v", found, err)
	}
	if err := s.CreateUser(User{ID: "other-admin", Username: "other-admin", Roles: []string{"admin"}, PasswordHash: "hash"}); err != nil {
		t.Fatal(err)
	}
	if found, err := s.DeleteUser("admin", "other-admin"); err != nil || !found {
		t.Fatalf("delete one of two administrators: %v %v", found, err)
	}
	if _, err := s.DeleteUser("other-admin", ""); !errors.Is(err, ErrLastAdministrator) {
		t.Fatalf("deleted admin counted as active: %v", err)
	}
}

func TestUserLifecycleRollback(t *testing.T) {
	for _, operation := range []string{"delete", "restore"} {
		for _, failure := range []string{"sessions", "audit"} {
			t.Run(operation+"/"+failure, func(t *testing.T) {
				s := lifecycleStore(t)
				if operation == "restore" {
					if _, err := s.DeleteUser("patron", "admin"); err != nil {
						t.Fatal(err)
					}
					// Ensure restore must also revoke sessions created during deletion.
					if _, err := s.db.Exec(`UPDATE sessions SET revoked_at = NULL`); err != nil {
						t.Fatal(err)
					}
				}
				before, _, _ := s.GetUser("patron")
				session, _, _ := s.GetSession("old-session")
				trigger := `CREATE TRIGGER fail_change BEFORE UPDATE OF revoked_at ON sessions BEGIN SELECT RAISE(ABORT, 'injected session failure'); END`
				if failure == "audit" {
					trigger = `CREATE TRIGGER fail_change BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END`
				}
				if _, err := s.db.Exec(trigger); err != nil {
					t.Fatal(err)
				}
				var found bool
				var err error
				if operation == "delete" {
					found, err = s.DeleteUser("patron", "admin")
				} else {
					found, err = s.RestoreUser("patron", "admin", "fresh")
				}
				if err == nil || found {
					t.Fatalf("reported success on %s failure: %v %v", failure, found, err)
				}
				after, _, err := s.GetUser("patron")
				if err != nil || after.Status != before.Status || after.PasswordHash != before.PasswordHash || after.UpdatedAt != before.UpdatedAt || after.DisabledAt != before.DisabledAt {
					t.Fatalf("account change not rolled back: %+v %v", after, err)
				}
				afterSession, _, err := s.GetSession("old-session")
				if err != nil || afterSession != session {
					t.Fatalf("session change not rolled back: %+v %v", afterSession, err)
				}
				events, err := s.ListAuditEvents(30)
				if err != nil {
					t.Fatal(err)
				}
				for _, event := range events {
					if (operation == "delete" && event.Event == "user_deleted") || (operation == "restore" && event.Event == "user_restored") {
						t.Fatalf("audit claimed rolled-back success: %+v", event)
					}
				}
			})
		}
	}
}
