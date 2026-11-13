package db

import (
	"database/sql"
	"errors"

	"example.org/odo/internal/proxy"
)

// ProxyHostname is a permanent identity record, not an authorization grant.
// Records are retained when resources are removed so a label cannot be reused.
type ProxyHostname struct {
	Hostname string
	Label    string
}

// RegisterProxyHostname is for explicit administrative enrollment only. No
// request handler calls it. centralHost and proxyBase must come from trusted
// deployment configuration. A repeated registration preserves the same identity.
func (s *Store) RegisterProxyHostname(raw, centralHost, proxyBase string) (ProxyHostname, error) {
	host, label, err := proxy.RegistryHostname(raw, centralHost, proxyBase)
	if err != nil {
		return ProxyHostname{}, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return ProxyHostname{}, err
	}
	defer tx.Rollback()
	stored, err := enrollProxyHostnameTx(tx, host, label)
	if err != nil {
		return ProxyHostname{}, err
	}
	if err := proxy.ValidateRegistryMapping(host, stored, centralHost, proxyBase); err != nil {
		return ProxyHostname{}, err
	}
	if err := tx.Commit(); err != nil {
		return ProxyHostname{}, err
	}
	return ProxyHostname{Hostname: host, Label: stored}, nil
}

// enrollProxyHostnameTx preserves an existing mapping or enrolls a new default.
// Collisions, including retired names, fail without choosing another label.
func enrollProxyHostnameTx(tx *sql.Tx, host, readable string) (string, error) {
	var stored string
	err := tx.QueryRow(`SELECT label FROM proxy_hostnames WHERE hostname = ?`, host).Scan(&stored)
	if err == nil {
		return stored, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	label, err := availableProxyLabelTx(tx, host, readable)
	if err != nil {
		return "", err
	}
	if _, err := tx.Exec(`INSERT INTO proxy_hostnames (hostname, label) VALUES (?, ?)`, host, label); err != nil {
		return "", err
	}
	return label, nil
}

// availableProxyLabelTx checks the default label under the transaction's write
// lock. The unique constraint and retired-name triggers also enforce this at SQL
// level. Never resolve a collision by silently choosing a different name.
func availableProxyLabelTx(tx *sql.Tx, host, label string) (string, error) {
	var taken bool
	if err := tx.QueryRow(`SELECT EXISTS (SELECT 1 FROM proxy_hostnames WHERE label = ? AND hostname != ?)
OR EXISTS (SELECT 1 FROM proxy_hostname_retired_labels WHERE label = ?)`, label, host, label).Scan(&taken); err != nil {
		return "", err
	}
	if taken {
		return "", errors.New("registry hostname has a conflicting identity")
	}
	return label, nil
}

// LookupProxyHostname resolves an exact stored label without decoding a host or
// creating a record. Callers must still authorize every request independently.
func (s *Store) LookupProxyHostname(label string) (ProxyHostname, bool, error) {
	var record ProxyHostname
	err := s.db.QueryRow(`SELECT hostname, label FROM proxy_hostnames WHERE label = ?`, label).Scan(&record.Hostname, &record.Label)
	if errors.Is(err, sql.ErrNoRows) {
		return ProxyHostname{}, false, nil
	}
	return record, err == nil, err
}

// ListProxyHostnames returns every enrolled hostname, ordered by hostname.
// Enrollment alone never authorizes a request.
func (s *Store) ListProxyHostnames() ([]ProxyHostname, error) {
	rows, err := s.db.Query(`SELECT hostname, label FROM proxy_hostnames ORDER BY hostname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProxyHostname
	for rows.Next() {
		var record ProxyHostname
		if err := rows.Scan(&record.Hostname, &record.Label); err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, rows.Err()
}

// LookupProxyHostnameByUpstream finds the actual enrolled identity, including
// legacy labels. The caller supplies a canonical upstream; no host is enrolled.
func (s *Store) LookupProxyHostnameByUpstream(host string) (ProxyHostname, bool, error) {
	var record ProxyHostname
	err := s.db.QueryRow(`SELECT hostname, label FROM proxy_hostnames WHERE hostname = ?`, host).Scan(&record.Hostname, &record.Label)
	if errors.Is(err, sql.ErrNoRows) {
		return ProxyHostname{}, false, nil
	}
	return record, err == nil, err
}
