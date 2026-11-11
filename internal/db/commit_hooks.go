package db

import (
	"database/sql"
	"slices"
)

// CommitHooks let the process that owns in-memory credential state (handoff
// grants, upstream cookie jars) retire it as soon as a change commits. Hooks
// are notifications, never authorization: every request still revalidates live
// database state, so a missed hook (another process, direct SQL, a crash) only
// delays memory cleanup until the next request or expiry.
type CommitHooks struct {
	// ResourcesChanged runs after every resource write attempt that reached
	// commit, while that write still holds the resource guard. It therefore
	// observes exactly the committed state and cannot interleave with
	// WithResourceAccess users. It must be short and synchronous: no network
	// I/O, no Store writes, and no resource writer or WithResource* call (which
	// would deadlock). It may read ResourceSnapshot.
	ResourcesChanged func()
	// SessionsRevoked receives the IDs of the sessions a successful commit
	// revoked. It runs after the commit and holds no Store lock.
	SessionsRevoked func(sessionIDs []string)
}

// AddCommitHooks registers hooks for the lifetime of the Store. Register them
// before serving requests.
func (s *Store) AddCommitHooks(hooks CommitHooks) {
	s.hooksMu.Lock()
	defer s.hooksMu.Unlock()
	s.hooks = append(s.hooks, hooks)
}

func (s *Store) commitHooks() []CommitHooks {
	s.hooksMu.Lock()
	defer s.hooksMu.Unlock()
	return slices.Clone(s.hooks)
}

// resourcesChanged must be called with resourceMu held, after the commit
// attempt. Republishing after a failed commit is harmless: hooks read actual
// database state.
func (s *Store) resourcesChanged() {
	for _, hooks := range s.commitHooks() {
		if hooks.ResourcesChanged != nil {
			hooks.ResourcesChanged()
		}
	}
}

// sessionsRevoked must be called only after a successful commit, so a failed
// transaction never claims revocation.
func (s *Store) sessionsRevoked(ids []string) {
	if len(ids) == 0 {
		return
	}
	for _, hooks := range s.commitHooks() {
		if hooks.SessionsRevoked != nil {
			hooks.SessionsRevoked(slices.Clone(ids))
		}
	}
}

// revokeUserSessionsTx revokes every open session of userID in tx and returns
// the revoked session IDs for post-commit notification.
func revokeUserSessionsTx(tx *sql.Tx, now, userID string) ([]string, error) {
	rows, err := tx.Query(`UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL RETURNING id`, now, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
