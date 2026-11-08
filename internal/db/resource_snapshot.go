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

// ResourceSnapshot reads the counter and resources in one SQLite transaction.
// Callers must not combine its revision with a separate ListResources lookup.
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
