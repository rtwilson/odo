package db

import (
	"database/sql"
	"errors"

	"example.org/odo/internal/resources"
)

// ResourceSnapshot binds validated resources to one committed database revision.
// Revision is configuration metadata, not a jar generation or authorization.
// Every successful upsert advances it, including identical JSON and reversions;
// deleting a missing resource does not. It is not added to resource JSON.
type ResourceSnapshot struct {
	Revision  int64
	Resources []resources.Resource
}

// WithResourceSnapshot reads a fresh snapshot and excludes resource upserts,
// deletes and other guarded callbacks on this Store until use returns. A
// cookie coordinator must keep policy installation, resource authorization and
// the complete PrepareRequest or StoreResponse operation inside use, not just
// the authorization callback. A snapshot read failure never calls use.
//
// The read transaction ends before use; this is an in-process mutex, not a
// database writer reservation. It does not protect against another Store,
// another process or direct SQL writes. It does not serialize session changes.
// The single-process caller must share one Store for all resource mutations.
//
// use must be short and synchronous: no DNS/network calls, resource writes or
// nested WithResourceSnapshot calls. Ordinary Store reads are allowed. Do not
// retain the snapshot as authorization after the callback returns. On an error,
// the caller is responsible for invalidating any previously published policies;
// this method has no cookie-manager state or rollback of callback side effects.
func (s *Store) WithResourceSnapshot(use func(ResourceSnapshot) error) error {
	return s.WithResourceAccess(func() error {
		snapshot, err := s.ResourceSnapshot()
		if err != nil {
			return err
		}
		return use(snapshot)
	})
}

// WithResourceAccess holds the same boundary as WithResourceSnapshot, but lets
// a synchronous callback (such as a cookie manager's authorizer) read the fresh
// snapshot itself. The same single-Store and no-network/no-write restrictions
// apply. Hold this boundary around the entire cookie operation, not just its
// authorizer, so a resource commit cannot intervene before jar access.
func (s *Store) WithResourceAccess(use func() error) error {
	s.resourceMu.Lock()
	defer s.resourceMu.Unlock()
	return use()
}

// ResourceSnapshot reads the counter and resources in one SQLite transaction.
// Callers must not combine its revision with a separate ListResources lookup.
// Unlike WithResourceSnapshot, it does not exclude later resource commits.
func (s *Store) ResourceSnapshot() (ResourceSnapshot, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return ResourceSnapshot{}, err
	}
	defer tx.Rollback()
	var snapshot ResourceSnapshot
	if err := tx.QueryRow(`SELECT revision FROM resource_state WHERE id = 1`).Scan(&snapshot.Revision); err != nil {
		return ResourceSnapshot{}, err
	}
	if snapshot.Revision < 0 {
		return ResourceSnapshot{}, errors.New("resource revision is invalid")
	}
	rows, err := tx.Query(`SELECT config_json FROM resources ORDER BY id`)
	if err != nil {
		return ResourceSnapshot{}, err
	}
	snapshot.Resources, err = decodeResourceRows(rows)
	if err != nil {
		return ResourceSnapshot{}, err
	}
	if err := tx.Commit(); err != nil {
		return ResourceSnapshot{}, err
	}
	return snapshot, nil
}

func advanceResourceRevision(tx *sql.Tx) error {
	result, err := tx.Exec(`UPDATE resource_state SET revision = revision + 1 WHERE id = 1 AND revision < 9223372036854775807`)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return errors.New("resource revision is unavailable or exhausted")
	}
	return nil
}
