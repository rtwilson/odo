package db

import (
	"time"

	"example.org/odo/internal/accesslog"
)

// LogPseudonymPolicies returns the rotation-policy history, oldest first. With
// no stored change the default (monthly) policy applies from the epoch.
func (s *Store) LogPseudonymPolicies() ([]accesslog.RotationPolicy, error) {
	rows, err := s.db.Query(`SELECT mode, unit, count, effective_from FROM log_pseudonym_policies ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	history := []accesslog.RotationPolicy{accesslog.DefaultRotationPolicy()}
	for rows.Next() {
		var policy accesslog.RotationPolicy
		var effective string
		if err := rows.Scan(&policy.Mode, &policy.Unit, &policy.Count, &effective); err != nil {
			return nil, err
		}
		if policy.EffectiveFrom, err = time.Parse(time.RFC3339Nano, effective); err != nil {
			return nil, err
		}
		history = append(history, policy)
	}
	return history, rows.Err()
}

// CurrentLogPseudonymPolicy returns the policy for new log lines.
func (s *Store) CurrentLogPseudonymPolicy() (accesslog.RotationPolicy, error) {
	history, err := s.LogPseudonymPolicies()
	if err != nil {
		return accesslog.RotationPolicy{}, err
	}
	return history[len(history)-1], nil
}

// SetLogPseudonymPolicy appends a validated policy effective at now, together
// with its audit event, in one transaction.
func (s *Store) SetLogPseudonymPolicy(policy accesslog.RotationPolicy, now time.Time, auditDetail string) (accesslog.RotationPolicy, error) {
	policy, err := policy.Normalize()
	if err != nil {
		return accesslog.RotationPolicy{}, err
	}
	policy.EffectiveFrom = now.UTC()
	tx, err := s.db.Begin()
	if err != nil {
		return accesslog.RotationPolicy{}, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO log_pseudonym_policies (mode, unit, count, effective_from) VALUES (?, ?, ?, ?)`,
		policy.Mode, policy.Unit, policy.Count, policy.EffectiveFrom.Format(time.RFC3339Nano)); err != nil {
		return accesslog.RotationPolicy{}, err
	}
	if _, err := tx.Exec(`INSERT INTO audit_events (ts, event, detail) VALUES (?, ?, ?)`,
		policy.EffectiveFrom.Format(time.RFC3339), "log_pseudonym_policy_changed", auditDetail); err != nil {
		return accesslog.RotationPolicy{}, err
	}
	return policy, tx.Commit()
}

// UserSessionIDsBetween lists the IDs of a user's sessions that may have been
// active between from and to (created before to, expiring after from).
func (s *Store) UserSessionIDsBetween(userID string, from, to time.Time) ([]string, error) {
	rows, err := s.db.Query(`SELECT id, created_at, expires_at FROM sessions WHERE user_id = ? ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id, created, expires string
		if err := rows.Scan(&id, &created, &expires); err != nil {
			return nil, err
		}
		createdAt, err1 := time.Parse(time.RFC3339, created)
		expiresAt, err2 := time.Parse(time.RFC3339, expires)
		if err1 != nil || err2 != nil {
			// Unparseable rows are included rather than silently missed.
			ids = append(ids, id)
			continue
		}
		if createdAt.Before(to) && expiresAt.After(from) {
			ids = append(ids, id)
		}
	}
	return ids, rows.Err()
}
