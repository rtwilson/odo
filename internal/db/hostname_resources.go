package db

import (
	"errors"
	"net/url"
	"sort"

	"example.org/odo/internal/proxy"
	"example.org/odo/internal/resources"
)

// ReconcileProxyHostnames explicitly enrolls active exact proxy domains and
// approved concrete hosts covered by current domain policy. It never discovers
// hosts through DNS, HTTP, entry URLs, or vendor content. Old identities remain
// reserved even if no current resource references them.
func (s *Store) ReconcileProxyHostnames(centralHost, proxyBase string, approvedHosts []string) ([]ProxyHostname, error) {
	// Validate deployment names even if there are no candidates.
	if _, err := proxy.NormalizeRegistryHostname(centralHost); err != nil {
		return nil, err
	}
	if _, err := proxy.NormalizeRegistryHostname(proxyBase); err != nil {
		return nil, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT config_json FROM resources ORDER BY id`)
	if err != nil {
		return nil, err
	}
	var items []resources.Resource
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			rows.Close()
			return nil, err
		}
		item, err := resources.Decode([]byte(payload))
		if err != nil {
			rows.Close()
			return nil, err
		}
		// Enrollment is based on domain policy, not path-specific anonymous
		// exceptions. Runtime authorization must still consider those exceptions.
		item.AnonymousURLRules = nil
		items = append(items, item)
	}
	readErr := rows.Err()
	closeErr := rows.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}

	candidates := make(map[string]ProxyHostname)
	add := func(raw string, explicit bool) error {
		host, label, err := proxy.RegistryHostname(raw, centralHost, proxyBase)
		if err != nil {
			return err
		}
		result := resources.TestURL((&url.URL{Scheme: "https", Host: host, Path: "/"}).String(), items)
		if !result.Allowed || result.Action != "proxy" {
			if explicit {
				return errors.New("approved hostname is not covered by active proxy domain policy")
			}
			return nil
		}
		candidates[host] = ProxyHostname{Hostname: host, Label: label}
		return nil
	}
	for _, item := range items {
		if item.Status != "active" {
			continue
		}
		for _, rule := range item.Domains {
			if rule.Match == "exact" && rule.Action == "proxy" {
				if err := add(rule.Host, false); err != nil {
					return nil, err
				}
			}
		}
	}
	for _, raw := range approvedHosts {
		if err := add(raw, true); err != nil {
			return nil, err
		}
	}
	out := make([]ProxyHostname, 0, len(candidates))
	for _, record := range candidates {
		out = append(out, record)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hostname < out[j].Hostname })
	for _, record := range out {
		if _, err := tx.Exec(`INSERT INTO proxy_hostnames (hostname, label) VALUES (?, ?)
ON CONFLICT(hostname) DO NOTHING`, record.Hostname, record.Label); err != nil {
			return nil, err
		}
		var stored string
		if err := tx.QueryRow(`SELECT label FROM proxy_hostnames WHERE hostname = ?`, record.Hostname).Scan(&stored); err != nil {
			return nil, err
		}
		if stored != record.Label {
			return nil, errors.New("registry hostname has a conflicting identity")
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

// ProxyHostnameResourceIDs reports current domain-policy associations for an
// enrolled label. It is an inspection operation, not a request authorization
// check: URL-specific anonymous rules, methods, sessions and DNS safety are not
// evaluated. A stored mapping alone never makes this result nonempty.
func (s *Store) ProxyHostnameResourceIDs(label string) ([]string, error) {
	record, found, err := s.LookupProxyHostname(label)
	if err != nil || !found {
		return nil, err
	}
	items, err := s.ListResources()
	if err != nil {
		return nil, err
	}
	for i := range items {
		items[i].AnonymousURLRules = nil
	}
	target := (&url.URL{Scheme: "https", Host: record.Hostname, Path: "/"}).String()
	result := resources.TestURL(target, items)
	if !result.Allowed || result.Action != "proxy" {
		return nil, nil
	}
	var ids []string
	for _, item := range items {
		result := resources.TestURL(target, []resources.Resource{item})
		if result.Allowed && result.Action == "proxy" {
			ids = append(ids, item.ID)
		}
	}
	return ids, nil
}
