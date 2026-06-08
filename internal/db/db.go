package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"example.org/odo/internal/resources"
	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	return &Store{db: conn}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) Migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS resources (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	status TEXT NOT NULL,
	config_json TEXT NOT NULL,
	updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	ts TEXT NOT NULL,
	event TEXT NOT NULL,
	detail TEXT NOT NULL
);
`)
	return err
}

func (s *Store) UpsertResource(resource resources.Resource) error {
	resource, err := resources.Validate(resource)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(resource)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)

	_, err = s.db.Exec(`
INSERT INTO resources (id, name, status, config_json, updated_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	name = excluded.name,
	status = excluded.status,
	config_json = excluded.config_json,
	updated_at = excluded.updated_at
`, resource.ID, resource.Name, resource.Status, string(payload), now)
	if err != nil {
		return err
	}

	return s.Audit("resource.upsert", fmt.Sprintf(`{"id":%q,"status":%q}`, resource.ID, resource.Status))
}

func (s *Store) ListResources() ([]resources.Resource, error) {
	rows, err := s.db.Query(`SELECT config_json FROM resources ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []resources.Resource
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		resource, err := resources.Decode([]byte(payload))
		if err != nil {
			return nil, err
		}
		out = append(out, resource)
	}
	return out, rows.Err()
}

func (s *Store) Audit(event, detail string) error {
	_, err := s.db.Exec(
		`INSERT INTO audit_events (ts, event, detail) VALUES (?, ?, ?)`,
		time.Now().UTC().Format(time.RFC3339),
		event,
		detail,
	)
	return err
}
