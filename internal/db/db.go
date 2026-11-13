package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"example.org/odo/internal/auth/saml"
	"example.org/odo/internal/resources"
	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
	// Orders resource commits with WithResourceSnapshot callbacks on this Store.
	resourceMu sync.Mutex
	hooksMu    sync.Mutex
	hooks      []CommitHooks
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

type User struct {
	ID           string   `json:"id"`
	Username     string   `json:"username"`
	Email        string   `json:"email,omitempty"`
	DisplayName  string   `json:"display_name,omitempty"`
	PasswordHash string   `json:"-"`
	AuthVersion  int64    `json:"-"`
	Status       string   `json:"status"`
	Roles        []string `json:"roles"`
	CreatedAt    string   `json:"created_at"`
	UpdatedAt    string   `json:"updated_at"`
	LastLoginAt  string   `json:"last_login_at,omitempty"`
	LockedAt     string   `json:"locked_at,omitempty"`
	DisabledAt   string   `json:"disabled_at,omitempty"`
}

type Session struct {
	ID            string `json:"id"`
	UserID        string `json:"user_id"`
	SessionHash   string `json:"-"`
	CreatedAt     string `json:"created_at"`
	LastSeenAt    string `json:"last_seen_at"`
	ExpiresAt     string `json:"expires_at"`
	RevokedAt     string `json:"revoked_at,omitempty"`
	UserAgentHash string `json:"user_agent_hash,omitempty"`
	IPHash        string `json:"ip_hash,omitempty"`
}

// sqliteConnectionParams applies to every pooled connection. SQLite allows one
// writer at a time: without a busy timeout, a connection that meets another
// connection's write lock fails at once with SQLITE_BUSY (concurrent session
// touches, logins, resource or registry writes). Immediate transactions take the
// write lock at BEGIN, so read-then-write transactions wait for it instead of
// failing on lock upgrade, where SQLite skips the busy handler. The journal
// mode is unchanged.
const sqliteConnectionParams = "?_pragma=busy_timeout(5000)&_txlock=immediate"

func Open(path string) (*Store, error) {
	// The driver splits a plain DSN at its first '?', which would silently open
	// a different file and drop the connection parameters.
	if strings.Contains(path, "?") {
		return nil, errors.New("database path must not contain '?'")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	conn, err := sql.Open("sqlite", path+sqliteConnectionParams)
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

CREATE TABLE IF NOT EXISTS resource_state (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	revision INTEGER NOT NULL CHECK (typeof(revision) = 'integer' AND revision >= 0)
);
INSERT OR IGNORE INTO resource_state (id, revision) VALUES (1, 0);

-- Append-only history of patron-key rotation policies. The latest row applies
-- to new access-log lines; earlier rows let re-identification derive keys for
-- lines written under them.
CREATE TABLE IF NOT EXISTS log_pseudonym_policies (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	mode TEXT NOT NULL CHECK (mode IN ('never', 'session', 'time')),
	unit TEXT NOT NULL DEFAULT '',
	count INTEGER NOT NULL DEFAULT 0,
	effective_from TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS log_pseudonym_policies_append_only_update
BEFORE UPDATE ON log_pseudonym_policies
BEGIN SELECT RAISE(ABORT, 'pseudonym policy history is append-only'); END;
CREATE TRIGGER IF NOT EXISTS log_pseudonym_policies_append_only_delete
BEFORE DELETE ON log_pseudonym_policies
BEGIN SELECT RAISE(ABORT, 'pseudonym policy history is append-only'); END;

-- Host grants survive restarts. Only the SHA-256 hash of each grant token is
-- stored; every use still re-validates the live parent session, account,
-- registry mapping, resource policy and DNS safety, so a row never authorizes
-- anything by itself.
CREATE TABLE IF NOT EXISTS handoff_grants (
	token_hash TEXT PRIMARY KEY NOT NULL,
	parent_user_id TEXT NOT NULL,
	parent_auth_version INTEGER NOT NULL,
	parent_session_id TEXT NOT NULL,
	parent_session_hash TEXT NOT NULL,
	hostname TEXT NOT NULL,
	label TEXT NOT NULL,
	proxy_authority TEXT NOT NULL,
	family TEXT NOT NULL,
	created_at TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	limit_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS handoff_grants_parent ON handoff_grants (parent_session_id);
CREATE INDEX IF NOT EXISTS handoff_grants_expires ON handoff_grants (expires_at);

CREATE TABLE IF NOT EXISTS proxy_hostnames (
	hostname TEXT PRIMARY KEY NOT NULL,
	label TEXT UNIQUE NOT NULL
);

-- Retired names are permanent tombstones, never routable aliases.
CREATE TABLE IF NOT EXISTS proxy_hostname_retired_labels (
 label TEXT PRIMARY KEY NOT NULL,
 hostname TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS proxy_hostname_no_retired_insert
BEFORE INSERT ON proxy_hostnames
WHEN EXISTS (SELECT 1 FROM proxy_hostname_retired_labels WHERE label = NEW.label)
BEGIN SELECT RAISE(ABORT, 'proxy hostname label is retired'); END;
CREATE TRIGGER IF NOT EXISTS proxy_hostname_no_retired_update
BEFORE UPDATE OF label ON proxy_hostnames
WHEN EXISTS (SELECT 1 FROM proxy_hostname_retired_labels WHERE label = NEW.label)
BEGIN SELECT RAISE(ABORT, 'proxy hostname label is retired'); END;

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

CREATE TABLE IF NOT EXISTS saml_providers (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	status TEXT NOT NULL,
	config_json TEXT NOT NULL,
	updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
	id TEXT PRIMARY KEY,
	username TEXT UNIQUE NOT NULL,
	email TEXT NULL,
	display_name TEXT NULL,
	password_hash TEXT NOT NULL,
	status TEXT NOT NULL,
	roles_json TEXT NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	last_login_at TEXT NULL,
	locked_at TEXT NULL,
	disabled_at TEXT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
	id TEXT PRIMARY KEY,
	user_id TEXT NOT NULL,
	session_hash TEXT NOT NULL,
	created_at TEXT NOT NULL,
	last_seen_at TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	revoked_at TEXT NULL,
	user_agent_hash TEXT NULL,
	ip_hash TEXT NULL
);
`)
	if err != nil {
		return err
	}
	// Additive, idempotent migration for existing databases. Keep this private
	// counter out of user JSON; zero preserves all existing account/session data.
	rows, err := s.db.Query(`PRAGMA table_info(users)`)
	if err != nil {
		return err
	}
	found := false
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			return err
		}
		if name == "auth_version" {
			found = true
		}
	}
	readErr := rows.Err()
	closeErr := rows.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if !found {
		_, err = s.db.Exec(`ALTER TABLE users ADD COLUMN auth_version INTEGER NOT NULL DEFAULT 0`)
	}
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
	s.resourceMu.Lock()
	defer s.resourceMu.Unlock()
	now := time.Now().UTC().Format(time.RFC3339)

	// Resource state and its audit must succeed together. Future policy
	// publication must not miss a committed write reported as an audit failure.
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`
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

	if err := advanceResourceRevision(tx); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO audit_events (ts, event, detail) VALUES (?, ?, ?)`, now,
		"resource.upsert", fmt.Sprintf(`{"id":%q,"status":%q}`, resource.ID, resource.Status)); err != nil {
		return err
	}
	err = tx.Commit()
	s.resourcesChanged()
	return err
}

func (s *Store) ListResources() ([]resources.Resource, error) {
	rows, err := s.db.Query(`SELECT config_json FROM resources ORDER BY id`)
	if err != nil {
		return nil, err
	}
	return decodeResourceRows(rows)
}

// Both ordinary reads and transactional snapshots use the same validation.
func decodeResourceRows(rows *sql.Rows) ([]resources.Resource, error) {
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
	s.resourceMu.Lock()
	defer s.resourceMu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`DELETE FROM resources WHERE id = ?`, id)
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
	if err := advanceResourceRevision(tx); err != nil {
		return false, err
	}
	if _, err := tx.Exec(`INSERT INTO audit_events (ts, event, detail) VALUES (?, ?, ?)`, time.Now().UTC().Format(time.RFC3339),
		"resource.delete", fmt.Sprintf(`{"id":%q}`, id)); err != nil {
		return false, err
	}
	err = tx.Commit()
	s.resourcesChanged()
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) UpsertSAMLProvider(provider saml.Provider) error {
	provider, err := saml.Validate(provider, "")
	if err != nil {
		return err
	}
	payload, err := json.Marshal(provider)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = s.db.Exec(`
INSERT INTO saml_providers (id, name, status, config_json, updated_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	name = excluded.name,
	status = excluded.status,
	config_json = excluded.config_json,
	updated_at = excluded.updated_at
`, provider.ID, provider.Name, provider.Status, string(payload), now)
	if err != nil {
		return err
	}
	return s.Audit("saml_provider_upsert", fmt.Sprintf(`{"id":%q,"status":%q}`, provider.ID, provider.Status))
}

func (s *Store) ListSAMLProviders() ([]saml.Provider, error) {
	rows, err := s.db.Query(`SELECT config_json FROM saml_providers ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []saml.Provider
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		provider, err := saml.Decode([]byte(payload))
		if err != nil {
			return nil, err
		}
		out = append(out, provider)
	}
	return out, rows.Err()
}

func (s *Store) GetSAMLProvider(id string) (saml.Provider, bool, error) {
	var payload string
	err := s.db.QueryRow(`SELECT config_json FROM saml_providers WHERE id = ?`, id).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return saml.Provider{}, false, nil
	}
	if err != nil {
		return saml.Provider{}, false, err
	}
	provider, err := saml.Decode([]byte(payload))
	if err != nil {
		return saml.Provider{}, false, err
	}
	return provider, true, nil
}

func (s *Store) DeleteSAMLProvider(id string) (bool, error) {
	result, err := s.db.Exec(`DELETE FROM saml_providers WHERE id = ?`, id)
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
	if err := s.Audit("saml_provider_delete", fmt.Sprintf(`{"id":%q}`, id)); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) ActiveSAMLProvider() (saml.Provider, bool, error) {
	providers, err := s.ListSAMLProviders()
	if err != nil {
		return saml.Provider{}, false, err
	}
	for _, provider := range providers {
		if provider.Status == "active" {
			return provider, true, nil
		}
	}
	return saml.Provider{}, false, nil
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

func (s *Store) CountUsers() (int, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count)
	return count, err
}

func (s *Store) CreateUser(user User) error {
	now := time.Now().UTC().Format(time.RFC3339)
	if user.CreatedAt == "" {
		user.CreatedAt = now
	}
	if user.UpdatedAt == "" {
		user.UpdatedAt = now
	}
	if user.Status == "" {
		user.Status = "active"
	}
	if len(user.Roles) == 0 {
		user.Roles = []string{"user"}
	}
	roles, err := json.Marshal(user.Roles)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
INSERT INTO users (id, username, email, display_name, password_hash, status, roles_json, created_at, updated_at, last_login_at, locked_at, disabled_at)
VALUES (?, ?, nullif(?, ''), nullif(?, ''), ?, ?, ?, ?, ?, nullif(?, ''), nullif(?, ''), nullif(?, ''))
`, user.ID, user.Username, user.Email, user.DisplayName, user.PasswordHash, user.Status, string(roles), user.CreatedAt, user.UpdatedAt, user.LastLoginAt, user.LockedAt, user.DisabledAt)
	if err != nil {
		return err
	}
	return s.Audit("user_created", fmt.Sprintf(`{"id":%q,"username":%q}`, user.ID, user.Username))
}

func (s *Store) ListUsers() ([]User, error) {
	return s.listUsers(false)
}

// ListDeletedUsers is separate so normal administration does not include deleted accounts.
func (s *Store) ListDeletedUsers() ([]User, error) {
	return s.listUsers(true)
}

func (s *Store) listUsers(deleted bool) ([]User, error) {
	rows, err := s.db.Query(`SELECT id, username, coalesce(email, ''), coalesce(display_name, ''), password_hash, status, roles_json, created_at, updated_at, coalesce(last_login_at, ''), coalesce(locked_at, ''), coalesce(disabled_at, ''), auth_version FROM users WHERE (status = 'deleted') = ? ORDER BY username`, deleted)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, user)
	}
	return out, rows.Err()
}

func (s *Store) GetUser(id string) (User, bool, error) {
	row := s.db.QueryRow(`SELECT id, username, coalesce(email, ''), coalesce(display_name, ''), password_hash, status, roles_json, created_at, updated_at, coalesce(last_login_at, ''), coalesce(locked_at, ''), coalesce(disabled_at, ''), auth_version FROM users WHERE id = ?`, id)
	return scanUserFound(row)
}

func (s *Store) GetUserByUsername(username string) (User, bool, error) {
	row := s.db.QueryRow(`SELECT id, username, coalesce(email, ''), coalesce(display_name, ''), password_hash, status, roles_json, created_at, updated_at, coalesce(last_login_at, ''), coalesce(locked_at, ''), coalesce(disabled_at, ''), auth_version FROM users WHERE username = ?`, username)
	return scanUserFound(row)
}

// UserPatch carries only fields explicitly supplied by a management caller.
type UserPatch struct {
	Email       *string
	DisplayName *string
	Status      string
	Roles       []string
}

func (s *Store) UpdateUser(user User) (User, bool, error) {
	return s.PatchUser(user.ID, UserPatch{Email: &user.Email, DisplayName: &user.DisplayName, Status: user.Status, Roles: user.Roles})
}

func (s *Store) PatchUser(id string, patch UserPatch) (User, bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return User{}, false, err
	}
	defer tx.Rollback()
	existing, found, err := userForUpdate(tx, id)
	if err != nil || !found {
		return User{}, found, err
	}
	if existing.Status == "deleted" {
		return User{}, true, ErrUserDeleted
	}
	user := existing
	if patch.Email != nil {
		user.Email = *patch.Email
	}
	if patch.DisplayName != nil {
		user.DisplayName = *patch.DisplayName
	}
	if patch.Status != "" {
		user.Status = patch.Status
	}
	if len(patch.Roles) > 0 {
		user.Roles = patch.Roles
	}
	securityChange := user.Status == "disabled" || user.Status == "locked" || !sameRoles(existing.Roles, user.Roles)
	if err := protectLastAdministrator(tx, existing, user.Status, user.Roles); err != nil {
		return User{}, false, err
	}
	roles, err := json.Marshal(user.Roles)
	if err != nil {
		return User{}, false, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if securityChange {
		user.AuthVersion++
	}
	disabledAt, lockedAt := existing.DisabledAt, existing.LockedAt
	if user.Status != existing.Status {
		disabledAt, lockedAt = "", ""
		if user.Status == "disabled" {
			disabledAt = now
		}
		if user.Status == "locked" {
			lockedAt = now
		}
	}
	result, err := tx.Exec(`UPDATE users SET email = nullif(?, ''), display_name = nullif(?, ''), status = ?, roles_json = ?, disabled_at = nullif(?, ''), locked_at = nullif(?, ''), updated_at = ?, auth_version = ? WHERE id = ? AND status != 'deleted'`,
		user.Email, user.DisplayName, user.Status, string(roles), disabledAt, lockedAt, now, user.AuthVersion, user.ID)
	if err != nil {
		return User{}, false, err
	}
	if rows, err := result.RowsAffected(); err != nil || rows == 0 {
		if err != nil {
			return User{}, false, err
		}
		return User{}, true, ErrUserDeleted
	}
	var revoked []string
	if securityChange {
		if revoked, err = revokeUserSessionsTx(tx, now, user.ID); err != nil {
			return User{}, false, err
		}
	}
	updated, found, err := scanUserFound(tx.QueryRow(`SELECT id, username, coalesce(email, ''), coalesce(display_name, ''), password_hash, status, roles_json, created_at, updated_at, coalesce(last_login_at, ''), coalesce(locked_at, ''), coalesce(disabled_at, ''), auth_version FROM users WHERE id = ?`, user.ID))
	if err != nil || !found {
		return User{}, found, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, false, err
	}
	s.sessionsRevoked(revoked)
	return updated, true, nil
}

// SetUserPassword commits the new password and session revocation together.
// Missing/deleted accounts remain unavailable and do not trigger revocation.
func (s *Store) SetUserPassword(id, hash string) (bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339)
	result, err := tx.Exec(`UPDATE users SET password_hash = ?, updated_at = ?, auth_version = auth_version + 1 WHERE id = ? AND status != 'deleted'`, hash, now, id)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows == 0 {
		return false, err
	}
	revoked, err := revokeUserSessionsTx(tx, now, id)
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	s.sessionsRevoked(revoked)
	return true, nil
}

func (s *Store) SetUserStatus(id, status string) (User, bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return User{}, false, err
	}
	defer tx.Rollback()
	existing, found, err := userForUpdate(tx, id)
	if err != nil || !found {
		return User{}, found, err
	}
	if existing.Status == "deleted" {
		// Match PatchUser: the account exists but must be restored first.
		return User{}, true, ErrUserDeleted
	}
	if err := protectLastAdministrator(tx, existing, status, existing.Roles); err != nil {
		return User{}, false, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	disabledAt, lockedAt := "", ""
	if status == "disabled" {
		disabledAt = now
	}
	if status == "locked" {
		lockedAt = now
	}
	version := existing.AuthVersion
	if status == "disabled" || status == "locked" {
		version++
	}
	result, err := tx.Exec(`UPDATE users SET status = ?, disabled_at = nullif(?, ''), locked_at = nullif(?, ''), updated_at = ?, auth_version = ? WHERE id = ? AND status != 'deleted'`, status, disabledAt, lockedAt, now, version, id)
	if err != nil {
		return User{}, false, err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows == 0 {
		return User{}, false, err
	}
	var revoked []string
	if status == "disabled" || status == "locked" {
		if revoked, err = revokeUserSessionsTx(tx, now, id); err != nil {
			return User{}, false, err
		}
	}
	user, found, err := scanUserFound(tx.QueryRow(`SELECT id, username, coalesce(email, ''), coalesce(display_name, ''), password_hash, status, roles_json, created_at, updated_at, coalesce(last_login_at, ''), coalesce(locked_at, ''), coalesce(disabled_at, ''), auth_version FROM users WHERE id = ?`, id))
	if err != nil || !found {
		return User{}, found, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, false, err
	}
	s.sessionsRevoked(revoked)
	return user, true, nil
}

func (s *Store) MarkUserLogin(id string) error {
	_, err := s.db.Exec(`UPDATE users SET last_login_at = ?, updated_at = ? WHERE id = ?`, time.Now().UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339), id)
	return err
}

// CreateSession stores trusted prepared session data (including test fixtures).
// Browser login must use CreateAuthenticatedSession to recheck eligibility.
func (s *Store) CreateSession(session Session) error {
	_, err := s.db.Exec(`
INSERT INTO sessions (id, user_id, session_hash, created_at, last_seen_at, expires_at, revoked_at, user_agent_hash, ip_hash)
VALUES (?, ?, ?, ?, ?, ?, nullif(?, ''), nullif(?, ''), nullif(?, ''))
`, session.ID, session.UserID, session.SessionHash, session.CreatedAt, session.LastSeenAt, session.ExpiresAt, session.RevokedAt, session.UserAgentHash, session.IPHash)
	return err
}

func (s *Store) GetSession(id string) (Session, bool, error) {
	row := s.db.QueryRow(`SELECT id, user_id, session_hash, created_at, last_seen_at, expires_at, coalesce(revoked_at, ''), coalesce(user_agent_hash, ''), coalesce(ip_hash, '') FROM sessions WHERE id = ?`, id)
	var session Session
	err := row.Scan(&session.ID, &session.UserID, &session.SessionHash, &session.CreatedAt, &session.LastSeenAt, &session.ExpiresAt, &session.RevokedAt, &session.UserAgentHash, &session.IPHash)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, false, nil
	}
	return session, err == nil, err
}

func (s *Store) TouchSession(id string) error {
	_, err := s.db.Exec(`UPDATE sessions SET last_seen_at = ? WHERE id = ?`, time.Now().UTC().Format(time.RFC3339), id)
	return err
}

func (s *Store) CountOpenSessions(now time.Time) (int, error) {
	row := s.db.QueryRow(`SELECT count(*) FROM sessions WHERE revoked_at IS NULL AND expires_at > ?`, now.UTC().Format(time.RFC3339))
	var count int
	err := row.Scan(&count)
	return count, err
}

func (s *Store) CountActiveSessionsSince(since time.Time, now time.Time) (int, error) {
	row := s.db.QueryRow(`SELECT count(*) FROM sessions WHERE revoked_at IS NULL AND expires_at > ? AND last_seen_at >= ?`, now.UTC().Format(time.RFC3339), since.UTC().Format(time.RFC3339))
	var count int
	err := row.Scan(&count)
	return count, err
}

func (s *Store) RevokeSession(id string) error {
	result, err := s.db.Exec(`UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, time.Now().UTC().Format(time.RFC3339), id)
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err == nil && rows > 0 {
		s.sessionsRevoked([]string{id})
	}
	return nil
}

func (s *Store) RevokeUserSessions(userID string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE users SET auth_version = auth_version + 1 WHERE id = ?`, userID); err != nil {
		return err
	}
	revoked, err := revokeUserSessionsTx(tx, time.Now().UTC().Format(time.RFC3339), userID)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.sessionsRevoked(revoked)
	return nil
}

type userScanner interface {
	Scan(dest ...any) error
}

func scanUserFound(row userScanner) (User, bool, error) {
	user, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, err
	}
	return user, true, nil
}

func scanUser(row userScanner) (User, error) {
	var user User
	var rolesJSON string
	if err := row.Scan(&user.ID, &user.Username, &user.Email, &user.DisplayName, &user.PasswordHash, &user.Status, &rolesJSON, &user.CreatedAt, &user.UpdatedAt, &user.LastLoginAt, &user.LockedAt, &user.DisabledAt, &user.AuthVersion); err != nil {
		return User{}, err
	}
	if err := json.Unmarshal([]byte(rolesJSON), &user.Roles); err != nil {
		return User{}, err
	}
	return user, nil
}
