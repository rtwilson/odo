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

// enrollProxyHostnameTx returns host's existing label, or enrolls it under its
// readable label. If another host already holds that label, or it is a retired
// label, the host gets its hashed fallback label instead: a readable name is
// never shared, reused or repointed. An unavailable fallback fails closed.
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

// availableProxyLabelTx picks readable when no other host holds it and it was
// never retired, otherwise the host's hashed fallback under the same rule.
func availableProxyLabelTx(tx *sql.Tx, host, readable string) (string, error) {
	for _, label := range []string{readable, proxy.FallbackRegistryLabel(host)} {
		var taken bool
		if err := tx.QueryRow(`SELECT EXISTS (SELECT 1 FROM proxy_hostnames WHERE label = ? AND hostname != ?)
OR EXISTS (SELECT 1 FROM proxy_hostname_retired_labels WHERE label = ?)`, label, host, label).Scan(&taken); err != nil {
			return "", err
		}
		if !taken {
			return label, nil
		}
	}
	return "", errors.New("registry hostname has a conflicting identity")
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
