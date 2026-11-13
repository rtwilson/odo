package proxy

import (
	"errors"
	"net/url"
	"strings"
)

// HostRoutingConfig holds normalized, trusted deployment names. Construction
// performs no DNS lookup and does not enable virtual-host routing.
type HostRoutingConfig struct {
	centralHost string
	proxyBase   string
}

func NewHostRoutingConfig(publicURL, proxyBase string) (HostRoutingConfig, error) {
	invalid := errors.New("hostname routing deployment settings are missing or invalid")
	publicURL = strings.TrimSpace(publicURL)
	public, err := url.Parse(publicURL)
	if err != nil || public.Scheme != "https" || public.Host == "" || public.User != nil ||
		(public.EscapedPath() != "" && public.EscapedPath() != "/") ||
		public.ForceQuery || public.RawQuery != "" || strings.Contains(publicURL, "#") {
		return HostRoutingConfig{}, invalid
	}
	central, err := NormalizeRegistryHostname(public.Host)
	if err != nil {
		return HostRoutingConfig{}, invalid
	}
	base, err := NormalizeRegistryHostname(proxyBase)
	if err != nil || len(base)+55 > 253 {
		return HostRoutingConfig{}, invalid
	}
	return HostRoutingConfig{centralHost: central, proxyBase: base}, nil
}

func (c HostRoutingConfig) CentralHostname() string { return c.centralHost }
func (c HostRoutingConfig) ProxyBaseDomain() string { return c.proxyBase }

// ClassifyAuthority accepts an HTTP authority, never a URL or a forwarded-header
// list. A nonempty label is only a candidate for exact registry lookup; it is not
// an admitted host or permission to reach either app or vendor handlers.
func (c HostRoutingConfig) ClassifyAuthority(authority string) (central bool, label string, err error) {
	invalid := errors.New("request authority is not admitted")
	if c.centralHost == "" || c.proxyBase == "" || authority == "" {
		return false, "", invalid
	}
	// HTTP authorities must use ASCII DNS names. IDNs from configuration have
	// already been converted to ASCII; do not repair ambiguous request bytes.
	for _, ch := range authority {
		if ch <= ' ' || ch >= 0x7f {
			return false, "", invalid
		}
	}
	host, err := NormalizeRegistryHostname(authority)
	if err != nil {
		return false, "", invalid
	}
	if host == c.centralHost {
		return true, "", nil
	}
	suffix := "." + c.proxyBase
	if !strings.HasSuffix(host, suffix) {
		return false, "", invalid
	}
	label = strings.TrimSuffix(host, suffix)
	if label == "" || strings.Contains(label, ".") {
		return false, "", invalid
	}
	return false, label, nil
}
