package proxy

import (
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"net"
	"strings"

	"golang.org/x/net/idna"
)

var registryIDNA = idna.New(idna.MapForLookup(), idna.BidiRule(), idna.Transitional(false), idna.VerifyDNSLength(true))

// NormalizeRegistryHostname accepts a DNS hostname, optionally with HTTPS port
// 443. It performs no DNS lookup and grants no permission to contact the host.
func NormalizeRegistryHostname(raw string) (string, error) {
	host := strings.TrimSpace(raw)
	if strings.HasSuffix(host, ":443") {
		host = strings.TrimSuffix(host, ":443")
	}
	if strings.ContainsAny(host, ":/\\@?#%[]") {
		return "", errors.New("registry hostname must be a DNS name with no URL components")
	}
	// Strip exactly one root-label dot before IDNA: VerifyDNSLength rejects the
	// empty root label, while "example.com.." must still fail as an empty label.
	ascii, err := registryIDNA.ToASCII(strings.TrimSuffix(host, "."))
	if err != nil {
		return "", errors.New("registry hostname is invalid")
	}
	ascii = strings.ToLower(ascii)
	if ascii == "" || len(ascii) > 253 || net.ParseIP(ascii) != nil {
		return "", errors.New("registry hostname is invalid")
	}
	for _, label := range strings.Split(ascii, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("registry hostname has an invalid DNS label")
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return "", errors.New("registry hostname has an invalid DNS label")
			}
		}
	}
	for _, local := range []string{"localhost", "local", "internal"} {
		if ascii == local || strings.HasSuffix(ascii, "."+local) {
			return "", errors.New("registry hostname must not be local")
		}
	}
	return ascii, nil
}

// RegistryHostname returns the canonical upstream hostname and its single-label
// proxy name. Central and proxy names are explicit inputs, never request headers.
// This only establishes identity; callers must separately apply current resource
// policy and connection-time IP validation before making upstream requests.
func RegistryHostname(raw, centralHost, proxyBase string) (host, label string, err error) {
	host, err = NormalizeRegistryHostname(raw)
	if err != nil {
		return "", "", err
	}
	central, err := NormalizeRegistryHostname(centralHost)
	if err != nil {
		return "", "", errors.New("registry central hostname is invalid")
	}
	base, err := NormalizeRegistryHostname(proxyBase)
	if err != nil {
		return "", "", errors.New("registry proxy base is invalid")
	}
	if host == central || host == base || strings.HasSuffix(host, "."+base) {
		return "", "", errors.New("registry hostname would create a proxy loop")
	}
	label = strings.ReplaceAll(host, ".", "-")
	// Flattening a leading IDN A-label would change its punycode meaning. A
	// readable label that does not fit one DNS label, or whose proxy FQDN would
	// exceed 253 characters under this suffix, uses the fixed-length fallback
	// (deployment validation guarantees the fallback always fits).
	if len(label) > 63 || strings.HasPrefix(label, "xn--") || len(label)+1+len(base) > 253 {
		label = legacyRegistryLabel(host)
	}
	if label+"."+base == central {
		return "", "", errors.New("registry label is reserved for the central application")
	}
	if len(label)+1+len(base) > 253 {
		return "", "", errors.New("registry proxy hostname exceeds DNS length limit")
	}
	return host, label, nil
}

// FallbackRegistryLabel is the hashed label for a canonical host. It is used
// for names that cannot be a readable DNS label (too long, or a leading IDN
// A-label, or an overlong proxy FQDN). Collisions never select this fallback.
// It is never decoded into an upstream.
func FallbackRegistryLabel(host string) string { return legacyRegistryLabel(host) }

// legacyRegistryLabel is the format of the original hashed labels.
func legacyRegistryLabel(host string) string {
	sum := sha256.Sum256([]byte(host))
	return "h-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:]))
}

// ValidateRegistryMapping accepts current defaults and existing legacy hashes.
// This validates identity syntax only: callers must also find the exact mapping
// in the trusted registry and apply live authorization. Arbitrary aliases are
// deliberately unsupported.
func ValidateRegistryMapping(host, label, centralHost, proxyBase string) error {
	canonical, current, err := RegistryHostname(host, centralHost, proxyBase)
	if err != nil {
		return err
	}
	if canonical != host || (label != current && label != legacyRegistryLabel(host)) {
		return errors.New("registry hostname has a conflicting identity")
	}
	central, _ := NormalizeRegistryHostname(centralHost)
	base, _ := NormalizeRegistryHostname(proxyBase)
	if label+"."+base == central || len(label)+1+len(base) > 253 {
		return errors.New("registry proxy hostname is reserved or too long")
	}
	return nil
}
