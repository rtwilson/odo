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
	_, err = s.db.Exec(`INSERT INTO proxy_hostnames (hostname, label) VALUES (?, ?)
ON CONFLICT(hostname) DO NOTHING`, host, label)
	if err != nil {
		return ProxyHostname{}, err
	}
	var stored string
	if err := s.db.QueryRow(`SELECT label FROM proxy_hostnames WHERE hostname = ?`, host).Scan(&stored); err != nil {
		return ProxyHostname{}, err
	}
	if stored != label {
		return ProxyHostname{}, errors.New("registry hostname has a conflicting identity")
	}
	return ProxyHostname{Hostname: host, Label: label}, nil
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
