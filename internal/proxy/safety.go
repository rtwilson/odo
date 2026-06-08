package proxy

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
)

type IPLookupFunc func(ctx context.Context, host string) ([]net.IPAddr, error)

var (
	errMalformedTargetURL = errors.New("target URL is malformed")
	errUnsafeTargetURL    = errors.New("target URL is not allowed")
)

func NormalizeAndValidateTargetURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, errMalformedTargetURL
	}
	if parsed.Scheme != "https" {
		return nil, errors.New("target URL must use HTTPS")
	}
	if parsed.User != nil {
		return nil, errors.New("target URL must not include userinfo")
	}
	if parsed.Fragment != "" {
		return nil, errors.New("target URL must not include a fragment")
	}
	if parsed.Host == "" || parsed.Hostname() == "" {
		return nil, errMalformedTargetURL
	}
	port := parsed.Port()
	if port != "" && port != "443" {
		return nil, errors.New("target URL must not use a non-default port")
	}

	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(parsed.Hostname()), "."))
	if host == "" {
		return nil, errMalformedTargetURL
	}
	if strings.Contains(host, "/") {
		return nil, errors.New("target hostname must not contain path slashes")
	}
	if strings.Contains(host, "*") {
		return nil, errors.New("target hostname must not contain wildcards")
	}
	if net.ParseIP(host) != nil {
		return nil, errors.New("target hostname must not be an IP address")
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return nil, errors.New("target hostname must not be localhost")
	}
	if host == "local" || strings.HasSuffix(host, ".local") {
		return nil, errors.New("target hostname must not use .local")
	}
	if host == "internal" || strings.HasSuffix(host, ".internal") {
		return nil, errors.New("target hostname must not use .internal")
	}

	parsed.Scheme = "https"
	parsed.Host = host
	if port == "443" {
		parsed.Host = host + ":443"
	}
	return parsed, nil
}

func ValidateTargetURL(ctx context.Context, raw string, lookup IPLookupFunc) (*url.URL, error) {
	parsed, err := NormalizeAndValidateTargetURL(raw)
	if err != nil {
		return nil, err
	}
	if lookup == nil {
		return parsed, nil
	}
	addrs, err := lookup(ctx, parsed.Hostname())
	if err != nil {
		return nil, errors.New("target hostname could not be resolved")
	}
	if len(addrs) == 0 {
		return nil, errors.New("target hostname did not resolve")
	}
	for _, addr := range addrs {
		if !isSafeResolvedIP(addr.IP) {
			return nil, errors.New("hostname resolves to private IP")
		}
	}
	return parsed, nil
}

func isSafeResolvedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsGlobalUnicast() &&
		!ip.IsPrivate() &&
		!ip.IsLoopback() &&
		!ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast() &&
		!ip.IsMulticast() &&
		!ip.IsUnspecified()
}
