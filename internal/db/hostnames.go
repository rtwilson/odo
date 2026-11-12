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
	// SQLite enforces both uniqueness constraints in a single statement. Never
	// overwrite an existing label or ignore a conflict belonging to another host.
	_, err = s.db.Exec(`INSERT INTO proxy_hostnames (hostname, label) SELECT ?, ?
WHERE NOT EXISTS (SELECT 1 FROM proxy_hostnames WHERE hostname = ?)
ON CONFLICT(hostname) DO NOTHING`, host, label, host)
	if err != nil {
		return ProxyHostname{}, err
	}
	var stored string
	if err := s.db.QueryRow(`SELECT label FROM proxy_hostnames WHERE hostname = ?`, host).Scan(&stored); err != nil {
		return ProxyHostname{}, err
	}
	if err := proxy.ValidateRegistryMapping(host, stored, centralHost, proxyBase); err != nil {
		return ProxyHostname{}, err
	}
	return ProxyHostname{Hostname: host, Label: stored}, nil
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
