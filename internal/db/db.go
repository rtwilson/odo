package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"example.org/odo/internal/auth/saml"
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

type User struct {
	ID           string   `json:"id"`
	Username     string   `json:"username"`
	Email        string   `json:"email,omitempty"`
	DisplayName  string   `json:"display_name,omitempty"`
	PasswordHash string   `json:"-"`
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
	rows, err := s.db.Query(`SELECT id, username, coalesce(email, ''), coalesce(display_name, ''), password_hash, status, roles_json, created_at, updated_at, coalesce(last_login_at, ''), coalesce(locked_at, ''), coalesce(disabled_at, '') FROM users ORDER BY username`)
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
	row := s.db.QueryRow(`SELECT id, username, coalesce(email, ''), coalesce(display_name, ''), password_hash, status, roles_json, created_at, updated_at, coalesce(last_login_at, ''), coalesce(locked_at, ''), coalesce(disabled_at, '') FROM users WHERE id = ?`, id)
	return scanUserFound(row)
}

func (s *Store) GetUserByUsername(username string) (User, bool, error) {
	row := s.db.QueryRow(`SELECT id, username, coalesce(email, ''), coalesce(display_name, ''), password_hash, status, roles_json, created_at, updated_at, coalesce(last_login_at, ''), coalesce(locked_at, ''), coalesce(disabled_at, '') FROM users WHERE username = ?`, username)
	return scanUserFound(row)
}

func (s *Store) UpdateUser(user User) (User, bool, error) {
	existing, found, err := s.GetUser(user.ID)
	if err != nil || !found {
		return User{}, found, err
	}
	if user.Username == "" {
		user.Username = existing.Username
	}
	if user.Status == "" {
		user.Status = existing.Status
	}
	if len(user.Roles) == 0 {
		user.Roles = existing.Roles
	}
	roles, err := json.Marshal(user.Roles)
	if err != nil {
		return User{}, false, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = s.db.Exec(`UPDATE users SET email = nullif(?, ''), display_name = nullif(?, ''), status = ?, roles_json = ?, updated_at = ? WHERE id = ?`,
		user.Email, user.DisplayName, user.Status, string(roles), now, user.ID)
	if err != nil {
		return User{}, false, err
	}
	return s.GetUser(user.ID)
}

func (s *Store) SetUserPassword(id, hash string) (bool, error) {
	result, err := s.db.Exec(`UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?`, hash, time.Now().UTC().Format(time.RFC3339), id)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	return rows > 0, err
}

func (s *Store) SetUserStatus(id, status string) (User, bool, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	disabledAt, lockedAt := "", ""
	if status == "disabled" {
		disabledAt = now
	}
	if status == "locked" {
		lockedAt = now
	}
	result, err := s.db.Exec(`UPDATE users SET status = ?, disabled_at = nullif(?, ''), locked_at = nullif(?, ''), updated_at = ? WHERE id = ?`, status, disabledAt, lockedAt, now, id)
	if err != nil {
		return User{}, false, err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows == 0 {
		return User{}, false, err
	}
	if status == "disabled" || status == "locked" {
		_ = s.RevokeUserSessions(id)
	}
	return s.GetUser(id)
}

func (s *Store) MarkUserLogin(id string) error {
	_, err := s.db.Exec(`UPDATE users SET last_login_at = ?, updated_at = ? WHERE id = ?`, time.Now().UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339), id)
	return err
}

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

func (s *Store) RevokeSession(id string) error {
	_, err := s.db.Exec(`UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, time.Now().UTC().Format(time.RFC3339), id)
	return err
}

func (s *Store) RevokeUserSessions(userID string) error {
	_, err := s.db.Exec(`UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`, time.Now().UTC().Format(time.RFC3339), userID)
	return err
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
	if err := row.Scan(&user.ID, &user.Username, &user.Email, &user.DisplayName, &user.PasswordHash, &user.Status, &rolesJSON, &user.CreatedAt, &user.UpdatedAt, &user.LastLoginAt, &user.LockedAt, &user.DisabledAt); err != nil {
		return User{}, err
	}
	if err := json.Unmarshal([]byte(rolesJSON), &user.Roles); err != nil {
		return User{}, err
	}
	return user, nil
}
