package db

import "time"

// HandoffGrantRecord is a persisted host grant. TokenHash is the SHA-256 hash
// of the grant token; the token itself is never stored.
type HandoffGrantRecord struct {
	TokenHash         string
	ParentUserID      string
	ParentAuthVersion int64
	ParentSessionID   string
	ParentSessionHash string
	Hostname          string
	Label             string
	ProxyAuthority    string
	Family            string
	Created           time.Time
	Expires           time.Time
	Limit             time.Time
}

// grantTimeLayout is fixed-width UTC, so SQL string comparison orders times.
const grantTimeLayout = "2006-01-02T15:04:05.000000000Z"

// SaveHandoffGrants inserts or updates grants in one transaction.
func (s *Store) SaveHandoffGrants(records []HandoffGrantRecord) error {
	if len(records) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, r := range records {
		if _, err := tx.Exec(`INSERT INTO handoff_grants (token_hash, parent_user_id, parent_auth_version, parent_session_id,
parent_session_hash, hostname, label, proxy_authority, family, created_at, expires_at, limit_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(token_hash) DO UPDATE SET expires_at = excluded.expires_at`,
			r.TokenHash, r.ParentUserID, r.ParentAuthVersion, r.ParentSessionID, r.ParentSessionHash, r.Hostname, r.Label,
			r.ProxyAuthority, r.Family, r.Created.UTC().Format(grantTimeLayout), r.Expires.UTC().Format(grantTimeLayout),
			r.Limit.UTC().Format(grantTimeLayout)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DeleteHandoffGrantsForParent removes every grant of a parent session.
func (s *Store) DeleteHandoffGrantsForParent(parentSessionID string) error {
	_, err := s.db.Exec(`DELETE FROM handoff_grants WHERE parent_session_id = ?`, parentSessionID)
	return err
}

// DeleteExpiredHandoffGrants removes grants whose inactivity deadline passed.
func (s *Store) DeleteExpiredHandoffGrants(now time.Time) error {
	_, err := s.db.Exec(`DELETE FROM handoff_grants WHERE expires_at <= ?`, now.UTC().Format(grantTimeLayout))
	return err
}

// LiveHandoffGrants returns grants still within their inactivity deadline,
// oldest first.
func (s *Store) LiveHandoffGrants(now time.Time) ([]HandoffGrantRecord, error) {
	rows, err := s.db.Query(`SELECT token_hash, parent_user_id, parent_auth_version, parent_session_id, parent_session_hash,
hostname, label, proxy_authority, family, created_at, expires_at, limit_at
FROM handoff_grants WHERE expires_at > ? ORDER BY created_at`, now.UTC().Format(grantTimeLayout))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []HandoffGrantRecord
	for rows.Next() {
		var r HandoffGrantRecord
		var created, expires, limit string
		if err := rows.Scan(&r.TokenHash, &r.ParentUserID, &r.ParentAuthVersion, &r.ParentSessionID, &r.ParentSessionHash,
			&r.Hostname, &r.Label, &r.ProxyAuthority, &r.Family, &created, &expires, &limit); err != nil {
			return nil, err
		}
		var err1, err2, err3 error
		r.Created, err1 = time.Parse(grantTimeLayout, created)
		r.Expires, err2 = time.Parse(grantTimeLayout, expires)
		r.Limit, err3 = time.Parse(grantTimeLayout, limit)
		if err1 != nil || err2 != nil || err3 != nil {
			continue // a malformed row is never loaded
		}
		records = append(records, r)
	}
	return records, rows.Err()
}
