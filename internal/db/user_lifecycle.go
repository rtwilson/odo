package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrUserDeleted       = errors.New("user is deleted")
	ErrUserNotDeleted    = errors.New("user is not deleted")
	ErrDeleteSelf        = errors.New("cannot delete own account")
	ErrLastAdministrator = errors.New("cannot remove the last active administrator")
)

// DeleteUser reserves the username and removes login credentials. The account,
// session revocations and minimal audit reference commit together. Repeating a
// deletion is a successful no-op, with no additional audit event.
// actorID identifies the authenticated administrator (empty for API-key callers).
func (s *Store) DeleteUser(id, actorID string) (bool, error) {
	if id == actorID {
		return false, ErrDeleteSelf
	}
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	// Acquire SQLite's writer lock before checking account/admin state. A
	// concurrent deletion cannot make its decision from the same stale count.
	if _, err := tx.Exec(`UPDATE users SET id = id WHERE id = ?`, id); err != nil {
		return false, err
	}
	var status, rolesJSON string
	err = tx.QueryRow(`SELECT status, roles_json FROM users WHERE id = ?`, id).Scan(&status, &rolesJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if status == "deleted" {
		return true, nil
	}
	var roles []string
	if err := json.Unmarshal([]byte(rolesJSON), &roles); err != nil {
		return false, err
	}
	if err := protectLastAdministrator(tx, User{Status: status, Roles: roles}, "deleted", roles); err != nil {
		return false, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := tx.Exec(`UPDATE users SET status = 'deleted', password_hash = '', disabled_at = ?, updated_at = ?, auth_version = auth_version + 1 WHERE id = ?`, now, now, id); err != nil {
		return false, err
	}
	if _, err := tx.Exec(`UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`, now, id); err != nil {
		return false, err
	}
	if err := auditUserLifecycle(tx, now, "user_deleted", id, actorID); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// RestoreUser requires a freshly generated password hash and leaves the account
// disabled for explicit administrative enablement. Revoked sessions stay revoked.
// Username uniqueness is preserved because deletion never releases the username.
func (s *Store) RestoreUser(id, actorID, passwordHash string) (bool, error) {
	if passwordHash == "" {
		return false, errors.New("new password hash is required")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339)
	result, err := tx.Exec(`UPDATE users SET status = 'disabled', password_hash = ?, disabled_at = ?, locked_at = NULL, updated_at = ?, auth_version = auth_version + 1 WHERE id = ? AND status = 'deleted'`, passwordHash, now, now, id)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if rows == 0 {
		var status string
		err := tx.QueryRow(`SELECT status FROM users WHERE id = ?`, id).Scan(&status)
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return false, ErrUserNotDeleted
	}
	// Defense in depth: revoke any session inserted while the account was deleted.
	if _, err := tx.Exec(`UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`, now, id); err != nil {
		return false, err
	}
	if err := auditUserLifecycle(tx, now, "user_restored", id, actorID); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func auditUserLifecycle(tx *sql.Tx, now, event, id, actorID string) error {
	detail, err := json.Marshal(map[string]string{"id": id, "actor_id": actorID})
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO audit_events (ts, event, detail) VALUES (?, ?, ?)`, now, event, string(detail))
	return err
}

func administratorRoles(roles []string) bool {
	for _, role := range roles {
		switch strings.ToLower(strings.TrimSpace(role)) {
		case "admin", "super_admin":
			return true
		}
	}
	return false
}

func sameRoles(left, right []string) bool {
	a, b := map[string]bool{}, map[string]bool{}
	for _, role := range left {
		a[strings.ToLower(strings.TrimSpace(role))] = true
	}
	for _, role := range right {
		b[strings.ToLower(strings.TrimSpace(role))] = true
	}
	if len(a) != len(b) {
		return false
	}
	for role := range a {
		if !b[role] {
			return false
		}
	}
	return true
}

// userForUpdate acquires SQLite's writer lock before reading account state.
// Every account mutation that can remove an administrator holds this lock until
// commit, so its admin count cannot race with deletion, disablement or demotion.
func userForUpdate(tx *sql.Tx, id string) (User, bool, error) {
	if _, err := tx.Exec(`UPDATE users SET id = id WHERE id = ?`, id); err != nil {
		return User{}, false, err
	}
	return scanUserFound(tx.QueryRow(`SELECT id, username, coalesce(email, ''), coalesce(display_name, ''), password_hash, status, roles_json, created_at, updated_at, coalesce(last_login_at, ''), coalesce(locked_at, ''), coalesce(disabled_at, ''), auth_version FROM users WHERE id = ?`, id))
}

func protectLastAdministrator(tx *sql.Tx, current User, status string, roles []string) error {
	if current.Status != "active" || !administratorRoles(current.Roles) || (status == "active" && administratorRoles(roles)) {
		return nil
	}
	count, err := activeAdministrators(tx)
	if err != nil {
		return err
	}
	if count <= 1 {
		return ErrLastAdministrator
	}
	return nil
}

func activeAdministrators(tx *sql.Tx) (int, error) {
	rows, err := tx.Query(`SELECT roles_json FROM users WHERE status = 'active'`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var payload string
		var roles []string
		if err := rows.Scan(&payload); err != nil {
			return 0, err
		}
		if err := json.Unmarshal([]byte(payload), &roles); err != nil {
			return 0, fmt.Errorf("read administrator roles: %w", err)
		}
		if administratorRoles(roles) {
			count++
		}
	}
	return count, rows.Err()
}
