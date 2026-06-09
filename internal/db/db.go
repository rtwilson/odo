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

type AuditEvent struct {
	ID     int64  `json:"id"`
	TS     string `json:"ts"`
	Event  string `json:"event"`
	Detail string `json:"detail"`
}

type APIKey struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	KeyHash    string   `json:"-"`
	KeyPrefix  string   `json:"key_prefix"`
	Scopes     []string `json:"scopes"`
	Status     string   `json:"status"`
	ExpiresAt  string   `json:"expires_at,omitempty"`
	CreatedAt  string   `json:"created_at"`
	UpdatedAt  string   `json:"updated_at"`
	LastUsedAt string   `json:"last_used_at,omitempty"`
	RevokedAt  string   `json:"revoked_at,omitempty"`
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

CREATE TABLE IF NOT EXISTS api_keys (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	key_hash TEXT NOT NULL,
	key_prefix TEXT NOT NULL,
	scopes_json TEXT NOT NULL,
	status TEXT NOT NULL,
	expires_at TEXT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	last_used_at TEXT NULL,
	revoked_at TEXT NULL
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

func (s *Store) GetResource(id string) (resources.Resource, bool, error) {
	var payload string
	err := s.db.QueryRow(`SELECT config_json FROM resources WHERE id = ?`, id).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return resources.Resource{}, false, nil
	}
	if err != nil {
		return resources.Resource{}, false, err
	}
	resource, err := resources.Decode([]byte(payload))
	if err != nil {
		return resources.Resource{}, false, err
	}
	return resource, true, nil
}

func (s *Store) DeleteResource(id string) (bool, error) {
	result, err := s.db.Exec(`DELETE FROM resources WHERE id = ?`, id)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if rows == 0 {
		return false, nil
	}
	if err := s.Audit("resource.delete", fmt.Sprintf(`{"id":%q}`, id)); err != nil {
		return false, err
	}
	return true, nil
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

func (s *Store) ListAuditEvents(limit int) ([]AuditEvent, error) {
	if limit <= 0 {
		limit = 25
	}
	rows, err := s.db.Query(`SELECT id, ts, event, detail FROM audit_events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AuditEvent
	for rows.Next() {
		var event AuditEvent
		if err := rows.Scan(&event.ID, &event.TS, &event.Event, &event.Detail); err != nil {
			return nil, err
		}
		out = append(out, event)
	}
	return out, rows.Err()
}

func (s *Store) CountAPIKeys() (int, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM api_keys`).Scan(&count)
	return count, err
}

func (s *Store) CreateAPIKey(key APIKey) error {
	if key.CreatedAt == "" {
		key.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if key.UpdatedAt == "" {
		key.UpdatedAt = key.CreatedAt
	}
	scopes, err := json.Marshal(key.Scopes)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
INSERT INTO api_keys (id, name, key_hash, key_prefix, scopes_json, status, expires_at, created_at, updated_at, last_used_at, revoked_at)
VALUES (?, ?, ?, ?, ?, ?, nullif(?, ''), ?, ?, nullif(?, ''), nullif(?, ''))
`, key.ID, key.Name, key.KeyHash, key.KeyPrefix, string(scopes), key.Status, key.ExpiresAt, key.CreatedAt, key.UpdatedAt, key.LastUsedAt, key.RevokedAt)
	if err != nil {
		return err
	}
	return s.Audit("api_key_created", fmt.Sprintf(`{"id":%q,"name":%q,"key_prefix":%q}`, key.ID, key.Name, key.KeyPrefix))
}

func (s *Store) ListAPIKeys() ([]APIKey, error) {
	rows, err := s.db.Query(`
SELECT id, name, key_hash, key_prefix, scopes_json, status, coalesce(expires_at, ''), created_at, updated_at, coalesce(last_used_at, ''), coalesce(revoked_at, '')
FROM api_keys ORDER BY created_at DESC, id DESC
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIKey
	for rows.Next() {
		key, err := scanAPIKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, key)
	}
	return out, rows.Err()
}

func (s *Store) GetAPIKey(id string) (APIKey, bool, error) {
	row := s.db.QueryRow(`
SELECT id, name, key_hash, key_prefix, scopes_json, status, coalesce(expires_at, ''), created_at, updated_at, coalesce(last_used_at, ''), coalesce(revoked_at, '')
FROM api_keys WHERE id = ?
`, id)
	key, err := scanAPIKey(row)
	if errors.Is(err, sql.ErrNoRows) {
		return APIKey{}, false, nil
	}
	if err != nil {
		return APIKey{}, false, err
	}
	return key, true, nil
}

func (s *Store) GetAPIKeyByHash(hash string) (APIKey, bool, error) {
	row := s.db.QueryRow(`
SELECT id, name, key_hash, key_prefix, scopes_json, status, coalesce(expires_at, ''), created_at, updated_at, coalesce(last_used_at, ''), coalesce(revoked_at, '')
FROM api_keys WHERE key_hash = ?
`, hash)
	key, err := scanAPIKey(row)
	if errors.Is(err, sql.ErrNoRows) {
		return APIKey{}, false, nil
	}
	if err != nil {
		return APIKey{}, false, err
	}
	return key, true, nil
}

func (s *Store) RotateAPIKey(id, keyHash, keyPrefix string) (APIKey, bool, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	result, err := s.db.Exec(`
UPDATE api_keys SET key_hash = ?, key_prefix = ?, status = 'active', updated_at = ?, revoked_at = NULL
WHERE id = ?
`, keyHash, keyPrefix, now, id)
	if err != nil {
		return APIKey{}, false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return APIKey{}, false, err
	}
	if rows == 0 {
		return APIKey{}, false, nil
	}
	if err := s.Audit("api_key_rotated", fmt.Sprintf(`{"id":%q,"key_prefix":%q}`, id, keyPrefix)); err != nil {
		return APIKey{}, false, err
	}
	key, found, err := s.GetAPIKey(id)
	return key, found, err
}

func (s *Store) RevokeAPIKey(id string) (APIKey, bool, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	result, err := s.db.Exec(`UPDATE api_keys SET status = 'revoked', revoked_at = ?, updated_at = ? WHERE id = ?`, now, now, id)
	if err != nil {
		return APIKey{}, false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return APIKey{}, false, err
	}
	if rows == 0 {
		return APIKey{}, false, nil
	}
	if err := s.Audit("api_key_revoked", fmt.Sprintf(`{"id":%q}`, id)); err != nil {
		return APIKey{}, false, err
	}
	key, found, err := s.GetAPIKey(id)
	return key, found, err
}

func (s *Store) DeleteAPIKey(id string) (APIKey, bool, error) {
	key, found, err := s.RevokeAPIKey(id)
	if err != nil || !found {
		return key, found, err
	}
	if err := s.Audit("api_key_deleted", fmt.Sprintf(`{"id":%q}`, id)); err != nil {
		return APIKey{}, false, err
	}
	return key, true, nil
}

func (s *Store) MarkAPIKeyUsed(id string) error {
	_, err := s.db.Exec(`UPDATE api_keys SET last_used_at = ? WHERE id = ?`, time.Now().UTC().Format(time.RFC3339), id)
	return err
}

type apiKeyScanner interface {
	Scan(dest ...any) error
}

func scanAPIKey(row apiKeyScanner) (APIKey, error) {
	var key APIKey
	var scopesJSON string
	if err := row.Scan(&key.ID, &key.Name, &key.KeyHash, &key.KeyPrefix, &scopesJSON, &key.Status, &key.ExpiresAt, &key.CreatedAt, &key.UpdatedAt, &key.LastUsedAt, &key.RevokedAt); err != nil {
		return APIKey{}, err
	}
	if err := json.Unmarshal([]byte(scopesJSON), &key.Scopes); err != nil {
		return APIKey{}, err
	}
	return key, nil
}
