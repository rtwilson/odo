package db

import (
	"slices"
	"sync"
	"testing"
	"time"

	"example.org/odo/internal/resources"
)

type hookRecorder struct {
	mu        sync.Mutex
	revoked   [][]string
	resources int
	guarded   bool
	revisions []int64
}

func recordHooks(t *testing.T, s *Store) *hookRecorder {
	t.Helper()
	r := &hookRecorder{guarded: true}
	s.AddCommitHooks(CommitHooks{
		ResourcesChanged: func() {
			// Must run while the committing writer still holds the guard.
			held := !s.resourceMu.TryLock()
			if !held {
				s.resourceMu.Unlock()
			}
			snapshot, err := s.ResourceSnapshot()
			r.mu.Lock()
			defer r.mu.Unlock()
			r.resources++
			r.guarded = r.guarded && held
			if err == nil {
				r.revisions = append(r.revisions, snapshot.Revision)
			}
		},
		SessionsRevoked: func(ids []string) {
			slices.Sort(ids)
			r.mu.Lock()
			defer r.mu.Unlock()
			r.revoked = append(r.revoked, ids)
		},
	})
	return r
}

func (r *hookRecorder) takeRevoked() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.revoked
	r.revoked = nil
	return out
}

func seedSessions(t *testing.T, s *Store, userID string, ids ...string) {
	t.Helper()
	now := time.Now().UTC()
	for _, id := range ids {
		if err := s.CreateSession(Session{ID: id, UserID: userID, SessionHash: "hash-" + id, CreatedAt: now.Format(time.RFC3339), LastSeenAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCommitHooksReportExactlyTheRevokedSessions(t *testing.T) {
	s := openConcurrencyStore(t)
	for _, id := range []string{"admin", "patron", "bob"} {
		roles := []string{"patron"}
		if id == "admin" {
			roles = []string{"admin"}
		}
		if err := s.CreateUser(User{ID: id, Username: id, PasswordHash: "hash", Roles: roles}); err != nil {
			t.Fatal(err)
		}
	}
	r := recordHooks(t, s)
	seedSessions(t, s, "bob", "bob-1")
	for _, tc := range []struct {
		name   string
		seed   []string
		mutate func() error
		want   [][]string
	}{
		{"revoke one", []string{"p-1", "p-2"}, func() error { return s.RevokeSession("p-1") }, [][]string{{"p-1"}}},
		{"revoke already revoked", nil, func() error { return s.RevokeSession("p-1") }, nil},
		{"revoke user sessions", nil, func() error { return s.RevokeUserSessions("patron") }, [][]string{{"p-2"}}},
		{"password", []string{"p-3", "p-4"}, func() error { _, err := s.SetUserPassword("patron", "new"); return err }, [][]string{{"p-3", "p-4"}}},
		{"status active", []string{"p-5"}, func() error { _, _, err := s.SetUserStatus("patron", "active"); return err }, nil},
		{"status locked", nil, func() error { _, _, err := s.SetUserStatus("patron", "locked"); return err }, [][]string{{"p-5"}}},
		{"metadata only", []string{"p-6"}, func() error {
			_, _, err := s.PatchUser("patron", UserPatch{Status: "active", Roles: []string{"patron"}})
			return err
		}, nil},
		{"role change", nil, func() error {
			_, _, err := s.PatchUser("patron", UserPatch{Status: "active", Roles: []string{"patron", "staff"}})
			return err
		}, [][]string{{"p-6"}}},
		{"delete", []string{"p-7"}, func() error { _, err := s.DeleteUser("patron", "admin"); return err }, [][]string{{"p-7"}}},
		{"password on deleted account", nil, func() error { _, err := s.SetUserPassword("patron", "x"); return err }, nil},
		{"restore with no open sessions", nil, func() error { _, err := s.RestoreUser("patron", "admin", "fresh"); return err }, nil},
	} {
		seedSessions(t, s, "patron", tc.seed...)
		if err := tc.mutate(); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := r.takeRevoked(); !slices.EqualFunc(got, tc.want, slices.Equal[[]string]) {
			t.Fatalf("%s: hooks reported %v, want %v", tc.name, got, tc.want)
		}
	}
	if session, _, _ := s.GetSession("bob-1"); session.RevokedAt != "" {
		t.Fatal("another user's session was revoked")
	}
}

func TestCommitHooksSeeCommittedResourceRevisionsUnderTheGuard(t *testing.T) {
	s := openConcurrencyStore(t)
	r := recordHooks(t, s)
	item := resources.Resource{ID: "vendor", Name: "Vendor", Domains: []resources.DomainRule{{Host: "vendor.example"}}}
	if err := s.UpsertResource(item); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteResource("vendor"); err != nil {
		t.Fatal(err)
	}
	if deleted, err := s.DeleteResource("vendor"); err != nil || deleted {
		t.Fatal("repeat delete changed state")
	}
	if err := s.UpsertResource(resources.Resource{ID: "bad"}); err == nil {
		t.Fatal("invalid resource accepted")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.resources != 2 || !r.guarded || !slices.Equal(r.revisions, []int64{1, 2}) {
		t.Fatalf("resource hooks: calls=%d guarded=%v revisions=%v", r.resources, r.guarded, r.revisions)
	}
}
