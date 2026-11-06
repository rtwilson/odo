package db

import (
	"reflect"
	"testing"
)

func TestUserStatusReadbackFailureRollsBack(t *testing.T) {
	for _, patch := range []bool{false, true} {
		t.Run(map[bool]string{false: "status", true: "patch"}[patch], func(t *testing.T) {
			s := lifecycleStore(t)
			before, _, err := s.GetUser("patron")
			if err != nil {
				t.Fatal(err)
			}
			sessionBefore, _, err := s.GetSession("old-session")
			if err != nil {
				t.Fatal(err)
			}
			// Force decoding the updated account to fail after both writes.
			// The read must still be inside the transaction so it can roll back.
			if _, err := s.db.Exec(`CREATE TRIGGER corrupt_roles AFTER UPDATE OF status ON users BEGIN UPDATE users SET roles_json = 'invalid-json' WHERE id = NEW.id; END`); err != nil {
				t.Fatal(err)
			}
			var found bool
			if patch {
				u := before
				u.Status = "disabled"
				u.DisplayName = "Changed"
				_, found, err = s.UpdateUser(u)
			} else {
				_, found, err = s.SetUserStatus("patron", "locked")
			}
			if err == nil || found {
				t.Fatal("readback failure reported success")
			}
			after, _, err := s.GetUser("patron")
			if err != nil || !reflect.DeepEqual(after, before) {
				t.Fatal("account change not rolled back")
			}
			sessionAfter, _, err := s.GetSession("old-session")
			if err != nil || sessionAfter != sessionBefore {
				t.Fatal("session revocation not rolled back")
			}
		})
	}
}

func TestUserStatusPatchPreservesTimestampsOnMetadataUpdate(t *testing.T) {
	for _, status := range []string{"disabled", "locked"} {
		t.Run(status, func(t *testing.T) {
			s := lifecycleStore(t)
			if _, err := s.db.Exec(`UPDATE users SET status = ?, disabled_at = '2020-01-01T00:00:00Z', locked_at = '2020-01-02T00:00:00Z' WHERE id = 'patron'`, status); err != nil {
				t.Fatal(err)
			}
			u, _, err := s.GetUser("patron")
			if err != nil {
				t.Fatal(err)
			}
			u.DisplayName = "Updated"
			after, found, err := s.UpdateUser(u)
			if err != nil || !found || after.DisabledAt != u.DisabledAt || after.LockedAt != u.LockedAt {
				t.Fatal("metadata update changed status timestamps")
			}
			session, _, err := s.GetSession("old-session")
			if err != nil || session.RevokedAt == "" {
				t.Fatal("inactive user's session was not revoked")
			}
			after.Status = "active"
			active, found, err := s.UpdateUser(after)
			if err != nil || !found || active.DisabledAt != "" || active.LockedAt != "" {
				t.Fatal("PATCH reactivation did not clear status timestamps")
			}
			stillRevoked, _, err := s.GetSession("old-session")
			if err != nil || stillRevoked != session {
				t.Fatal("PATCH reactivation changed revoked session")
			}
		})
	}
}
