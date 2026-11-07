package db

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func changeAccountSecurity(s *Store, operation string) error {
	switch operation {
	case "password":
		_, err := s.SetUserPassword("patron", "replacement-hash")
		return err
	case "disable", "lock", "disable-enable", "lock-unlock":
		status := "disabled"
		if strings.HasPrefix(operation, "lock") {
			status = "locked"
		}
		if _, _, err := s.SetUserStatus("patron", status); err != nil {
			return err
		}
		if strings.Contains(operation, "-") {
			_, _, err := s.SetUserStatus("patron", "active")
			return err
		}
	case "patch-disable", "patch-lock":
		status := "disabled"
		if operation == "patch-lock" {
			status = "locked"
		}
		_, _, err := s.PatchUser("patron", UserPatch{Status: status})
		return err
	case "roles", "roles-return":
		if _, _, err := s.PatchUser("patron", UserPatch{Roles: []string{"viewer"}}); err != nil {
			return err
		}
		if operation == "roles-return" {
			_, _, err := s.PatchUser("patron", UserPatch{Roles: []string{"user"}})
			return err
		}
	case "delete", "delete-restore":
		if _, err := s.DeleteUser("patron", "admin"); err != nil {
			return err
		}
		if operation == "delete-restore" {
			if _, err := s.RestoreUser("patron", "admin", "patron-private-hash"); err != nil {
				return err
			}
			_, _, err := s.SetUserStatus("patron", "active")
			return err
		}
	case "restore":
		_, err := s.RestoreUser("patron", "admin", "replacement-hash")
		return err
	case "revoke-all":
		return s.RevokeUserSessions("patron")
	}
	return nil
}

func TestAccountSecurityRejectsStaleLoginInBothOrders(t *testing.T) {
	for _, operation := range []string{"password", "disable", "lock", "disable-enable", "lock-unlock", "patch-disable", "patch-lock", "roles", "roles-return", "delete", "delete-restore", "revoke-all"} {
		t.Run(operation, func(t *testing.T) {
			s := lifecycleStore(t)
			verified, _, err := s.GetUser("patron")
			if err != nil {
				t.Fatal(err)
			}
			session, _, err := s.GetSession("old-session")
			if err != nil {
				t.Fatal(err)
			}
			session.ID = "inserted-before"
			if err := s.CreateAuthenticatedSession(session, verified); err != nil {
				t.Fatal(err)
			}
			if err := changeAccountSecurity(s, operation); err != nil {
				t.Fatal(err)
			}
			stored, _, err := s.GetUser("patron")
			if err != nil || stored.AuthVersion <= verified.AuthVersion {
				t.Fatal("security version did not advance")
			}
			old, _, found, err := s.GetSessionWithUser(session.ID)
			if err != nil || !found || old.RevokedAt == "" {
				t.Fatal("earlier session escaped revocation")
			}
			session.ID = "inserted-after"
			if err := s.CreateAuthenticatedSession(session, verified); !errors.Is(err, ErrLoginStateChanged) {
				t.Fatalf("stale login result: %v", err)
			}
			if _, found, err := s.GetSession(session.ID); err != nil || found {
				t.Fatal("stale login persisted a session")
			}
		})
	}
}

func TestAccountSecurityConcurrentLoginCannotEscapeRevocation(t *testing.T) {
	for _, operation := range []string{"password", "disable-enable", "lock-unlock", "roles-return", "delete-restore", "revoke-all"} {
		t.Run(operation, func(t *testing.T) {
			s := lifecycleStore(t)
			s.db.SetMaxOpenConns(1)
			var seq int
			var name, path string
			if err := s.db.QueryRow(`PRAGMA database_list`).Scan(&seq, &name, &path); err != nil {
				t.Fatal(err)
			}
			other, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = other.Close() })
			other.db.SetMaxOpenConns(1)
			for _, store := range []*Store{s, other} {
				if _, err := store.db.Exec(`PRAGMA busy_timeout = 3000`); err != nil {
					t.Fatal(err)
				}
			}
			verified, _, err := s.GetUser("patron")
			if err != nil {
				t.Fatal(err)
			}
			session, _, err := s.GetSession("old-session")
			if err != nil {
				t.Fatal(err)
			}
			session.ID = "racing-login"
			start := make(chan struct{})
			loginResult, mutationResult := make(chan error, 1), make(chan error, 1)
			go func() { <-start; loginResult <- other.CreateAuthenticatedSession(session, verified) }()
			go func() { <-start; mutationResult <- changeAccountSecurity(s, operation) }()
			close(start)
			if err := <-mutationResult; err != nil {
				t.Fatal(err)
			}
			loginErr := <-loginResult
			if loginErr != nil && !errors.Is(loginErr, ErrLoginStateChanged) {
				t.Fatal(loginErr)
			}
			stored, found, err := s.GetSession(session.ID)
			if err != nil {
				t.Fatal(err)
			}
			if found && stored.RevokedAt == "" {
				t.Fatal("concurrent session survived security change")
			}
			if loginErr == nil && !found {
				t.Fatal("successful insert missing")
			}
		})
	}
}

func TestAccountSecurityRollbackIncludesVersion(t *testing.T) {
	for _, operation := range []string{"password", "disable", "lock", "patch-disable", "patch-lock", "roles", "delete", "restore", "revoke-all"} {
		t.Run(operation, func(t *testing.T) {
			s := lifecycleStore(t)
			if operation == "restore" {
				if _, err := s.DeleteUser("patron", "admin"); err != nil {
					t.Fatal(err)
				}
				if _, err := s.db.Exec(`UPDATE sessions SET revoked_at = NULL`); err != nil {
					t.Fatal(err)
				}
			}
			before, _, err := s.GetUser("patron")
			if err != nil {
				t.Fatal(err)
			}
			session, _, err := s.GetSession("old-session")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec(`CREATE TRIGGER fail_security_revocation BEFORE UPDATE OF revoked_at ON sessions BEGIN SELECT RAISE(ABORT, 'injected failure'); END`); err != nil {
				t.Fatal(err)
			}
			if err := changeAccountSecurity(s, operation); err == nil {
				t.Fatal("failed revocation reported success")
			}
			after, _, err := s.GetUser("patron")
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("account/version did not roll back")
			}
			afterSession, _, err := s.GetSession(session.ID)
			if err != nil || afterSession != session {
				t.Fatal("session did not roll back")
			}
		})
	}
}

func TestMetadataAndEquivalentRolesPreserveLoginEligibility(t *testing.T) {
	s := lifecycleStore(t)
	if _, _, err := s.PatchUser("patron", UserPatch{Roles: []string{"user", "viewer"}}); err != nil {
		t.Fatal(err)
	}
	verified, _, err := s.GetUser("patron")
	if err != nil {
		t.Fatal(err)
	}
	display := "Updated"
	after, _, err := s.PatchUser("patron", UserPatch{DisplayName: &display, Roles: []string{"viewer", "user"}})
	if err != nil || after.AuthVersion != verified.AuthVersion {
		t.Fatal("metadata or role ordering changed security version")
	}
	session, _, err := s.GetSession("old-session")
	if err != nil {
		t.Fatal(err)
	}
	session.ID, session.RevokedAt = "fresh", ""
	if err := s.CreateAuthenticatedSession(session, verified); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(after)
	if err != nil || strings.Contains(string(payload), "auth_version") || strings.Contains(string(payload), "AuthVersion") {
		t.Fatal("security counter exposed in JSON")
	}
}

func TestAuthVersionMigrationPreservesExistingData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(User{ID: "legacy", Username: "legacy", PasswordHash: "legacy-hash"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`ALTER TABLE users DROP COLUMN auth_version`); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatal(err)
	}
	u, found, err := s.GetUser("legacy")
	if err != nil || !found || u.AuthVersion != 0 || u.PasswordHash != "legacy-hash" {
		t.Fatal("migration lost account data")
	}
	if _, err := s.SetUserPassword(u.ID, "new-hash"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Migrate(); err != nil {
		t.Fatal(err)
	}
	u, found, err = s.GetUser("legacy")
	if err != nil || !found || u.AuthVersion != 1 || u.PasswordHash != "new-hash" {
		t.Fatal("security version not persistent/idempotent")
	}
}
