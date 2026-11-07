package db

import (
	"database/sql"
	"encoding/json"
	"errors"
)

var ErrLoginStateChanged = errors.New("account security state changed during login")

// CreateAuthenticatedSession inserts only if the account still matches the
// credentials/security version checked by login. The INSERT's write lock orders
// it with every account mutation: an earlier insert is revoked by that mutation;
// a later insert from the old version is rejected. No password hashing runs while
// holding the database lock, and no raw password enters the datastore.
func (s *Store) CreateAuthenticatedSession(session Session, verified User) error {
	if session.UserID != verified.ID {
		return ErrLoginStateChanged
	}
	result, err := s.db.Exec(`
INSERT INTO sessions (id, user_id, session_hash, created_at, last_seen_at, expires_at, revoked_at, user_agent_hash, ip_hash)
SELECT ?, id, ?, ?, ?, ?, nullif(?, ''), nullif(?, ''), nullif(?, '') FROM users
WHERE id = ? AND status = 'active' AND password_hash = ? AND auth_version = ?`,
		session.ID, session.SessionHash, session.CreatedAt, session.LastSeenAt, session.ExpiresAt, session.RevokedAt, session.UserAgentHash, session.IPHash,
		verified.ID, verified.PasswordHash, verified.AuthVersion)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrLoginStateChanged
	}
	return nil
}

// GetSessionWithUser reads both records from a single SQLite snapshot, avoiding
// mixed pre-revocation session state and post-mutation user roles/status.
func (s *Store) GetSessionWithUser(id string) (Session, User, bool, error) {
	row := s.db.QueryRow(`SELECT
s.id, s.user_id, s.session_hash, s.created_at, s.last_seen_at, s.expires_at, coalesce(s.revoked_at, ''), coalesce(s.user_agent_hash, ''), coalesce(s.ip_hash, ''),
u.id, u.username, coalesce(u.email, ''), coalesce(u.display_name, ''), u.password_hash, u.status, u.roles_json, u.created_at, u.updated_at, coalesce(u.last_login_at, ''), coalesce(u.locked_at, ''), coalesce(u.disabled_at, ''), u.auth_version
FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ?`, id)
	var session Session
	var user User
	var roles string
	err := row.Scan(&session.ID, &session.UserID, &session.SessionHash, &session.CreatedAt, &session.LastSeenAt, &session.ExpiresAt, &session.RevokedAt, &session.UserAgentHash, &session.IPHash,
		&user.ID, &user.Username, &user.Email, &user.DisplayName, &user.PasswordHash, &user.Status, &roles, &user.CreatedAt, &user.UpdatedAt, &user.LastLoginAt, &user.LockedAt, &user.DisabledAt, &user.AuthVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, User{}, false, nil
	}
	if err != nil {
		return Session{}, User{}, false, err
	}
	if err := json.Unmarshal([]byte(roles), &user.Roles); err != nil {
		return Session{}, User{}, false, err
	}
	return session, user, true, nil
}
