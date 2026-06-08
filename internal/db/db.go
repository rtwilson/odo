package db

import (
	"database/sql"
	"encoding/json"
	"errors"
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

type ConfigRevision struct {
	ID         int64  `json:"id"`
	TS         string `json:"ts"`
	Source     string `json:"source"`
	Status     string `json:"status"`
	Summary    string `json:"summary"`
	ConfigJSON string `json:"config_json,omitempty"`
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

CREATE TABLE IF NOT EXISTS config_revisions (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	ts TEXT NOT NULL,
	source TEXT NOT NULL,
	status TEXT NOT NULL,
	summary TEXT NOT NULL,
	config_json TEXT NOT NULL
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

func (s *Store) CreateConfigRevision(source, status, summary string, configJSON []byte) (int64, error) {
	ts := time.Now().UTC().Format(time.RFC3339)
	result, err := s.db.Exec(
		`INSERT INTO config_revisions (ts, source, status, summary, config_json) VALUES (?, ?, ?, ?, ?)`,
		ts,
		source,
		status,
		summary,
		string(configJSON),
	)
	if err != nil {
		return 0, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	if err := s.Audit("config_revision.create", fmt.Sprintf(`{"id":%d,"source":%q,"status":%q}`, id, source, status)); err != nil {
		return 0, err
	}
	return id, nil
}

func (s *Store) ListConfigRevisions(limit int) ([]ConfigRevision, error) {
	if limit <= 0 {
		limit = 25
	}
	rows, err := s.db.Query(
		`SELECT id, ts, source, status, summary FROM config_revisions ORDER BY id DESC LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ConfigRevision
	for rows.Next() {
		var revision ConfigRevision
		if err := rows.Scan(&revision.ID, &revision.TS, &revision.Source, &revision.Status, &revision.Summary); err != nil {
			return nil, err
		}
		out = append(out, revision)
	}
	return out, rows.Err()
}

func (s *Store) GetConfigRevision(id int64) (ConfigRevision, bool, error) {
	var revision ConfigRevision
	err := s.db.QueryRow(
		`SELECT id, ts, source, status, summary, config_json FROM config_revisions WHERE id = ?`,
		id,
	).Scan(&revision.ID, &revision.TS, &revision.Source, &revision.Status, &revision.Summary, &revision.ConfigJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return ConfigRevision{}, false, nil
	}
	if err != nil {
		return ConfigRevision{}, false, err
	}
	return revision, true, nil
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
