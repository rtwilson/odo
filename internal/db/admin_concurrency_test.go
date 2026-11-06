package db

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

func removeAdministrator(s *Store, operation string, user User) error {
	switch operation {
	case "delete":
		_, err := s.DeleteUser(user.ID, "")
		return err
	case "disable", "lock":
		status := "disabled"
		if operation == "lock" {
			status = "locked"
		}
		_, _, err := s.SetUserStatus(user.ID, status)
		return err
	case "demote":
		user.Roles = []string{"user"}
	case "patch-disable":
		user.Status = "disabled"
	}
	_, _, err := s.UpdateUser(user)
	return err
}

func TestConcurrentAdministratorRemovalPreservesOne(t *testing.T) {
	operations := []string{"delete", "disable", "lock", "demote", "patch-disable"}
	for _, left := range operations {
		for _, right := range operations {
			t.Run(left+"/"+right, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "odo.db")
				var stores [2]*Store
				admins := [2]User{
					{ID: "a", Username: "admin-a", Status: "active", Roles: []string{"admin"}, PasswordHash: "test-hash"},
					{ID: "b", Username: "admin-b", Status: "active", Roles: []string{"super_admin"}, PasswordHash: "test-hash"},
				}
				for i := range stores {
					s, err := Open(path)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = s.Close() })
					// Each store uses a separate real SQLite connection. Waiting
					// here is test-local; production lock contention still fails closed.
					s.db.SetMaxOpenConns(1)
					if _, err := s.db.Exec(`PRAGMA busy_timeout = 3000`); err != nil {
						t.Fatal(err)
					}
					stores[i] = s
				}
				if err := stores[0].Migrate(); err != nil {
					t.Fatal(err)
				}
				for _, admin := range admins {
					if err := stores[0].CreateUser(admin); err != nil {
						t.Fatal(err)
					}
				}
				start := make(chan struct{})
				results := make(chan error, 2)
				go func() { <-start; results <- removeAdministrator(stores[0], left, admins[0]) }()
				go func() { <-start; results <- removeAdministrator(stores[1], right, admins[1]) }()
				close(start)
				succeeded, protected := 0, 0
				for range 2 {
					err := <-results
					if err == nil {
						succeeded++
					} else if errors.Is(err, ErrLastAdministrator) {
						protected++
					} else {
						t.Fatalf("unexpected removal error: %v", err)
					}
				}
				if succeeded != 1 || protected != 1 {
					t.Fatalf("success=%d protected=%d", succeeded, protected)
				}
				users, err := stores[0].ListUsers()
				if err != nil {
					t.Fatal(err)
				}
				count := 0
				for _, user := range users {
					if user.Status == "active" && administratorRoles(user.Roles) {
						count++
					}
				}
				if count != 1 {
					t.Fatalf("active administrators remaining: %d", count)
				}
			})
		}
	}
}

func TestAdministratorProtectionUsesCurrentDatabaseState(t *testing.T) {
	s := lifecycleStore(t)
	if err := s.CreateUser(User{ID: "second", Username: "second", Roles: []string{"admin"}, PasswordHash: "hash"}); err != nil {
		t.Fatal(err)
	}
	stale, _, err := s.GetUser("second")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.SetUserStatus("admin", "disabled"); err != nil {
		t.Fatal(err)
	}
	stale.Roles = []string{"user"}
	if _, _, err := s.UpdateUser(stale); !errors.Is(err, ErrLastAdministrator) {
		t.Fatalf("stale snapshot bypassed protection: %v", err)
	}
	stored, _, err := s.GetUser("second")
	if err != nil || !administratorRoles(stored.Roles) || stored.Status != "active" {
		t.Fatal("last admin changed")
	}
}

func TestAdministratorCountFailureRollsBack(t *testing.T) {
	for _, operation := range []string{"delete", "disable", "lock", "demote", "patch-disable"} {
		t.Run(operation, func(t *testing.T) {
			s := lifecycleStore(t)
			before, _, err := s.GetUser("admin")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec(`UPDATE users SET roles_json = 'invalid-json' WHERE id = 'patron'`); err != nil {
				t.Fatal(err)
			}
			err = removeAdministrator(s, operation, before)
			if err == nil || errors.Is(err, ErrLastAdministrator) {
				t.Fatalf("count failure was hidden: %v", err)
			}
			after, _, err := s.GetUser("admin")
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("account changed on count failure")
			}
		})
	}
}
