package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"
)

const (
	SafetyReasonInvalidScheme = "invalid_scheme"
	SafetyReasonPrivateIP     = "private_ip"
	SafetyReasonLoopbackIP    = "loopback_ip"
	SafetyReasonUnsafeIP      = "unsafe_ip"
	SafetyReasonDNSProtection = "dns_rebinding_protection"
)

type SafetyError struct {
	Reason string
	Text   string
}

func (e *SafetyError) Error() string { return e.Text }

func safetyError(reason, text string) error {
	return &SafetyError{Reason: reason, Text: text}
}

func SafetyReason(err error) string {
	var target *SafetyError
	if errors.As(err, &target) {
		return target.Reason
	}
	return ""
}

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
	if parsed.User != nil {
		return nil, errors.New("target URL must not include userinfo")
	}
	if parsed.Fragment != "" {
		return nil, errors.New("target URL must not include a fragment")
	}
	if parsed.Host == "" || parsed.Hostname() == "" {
		return nil, errMalformedTargetURL
	}
	if allowDevelopmentLocalHTTP(parsed) {
		return parsed, nil
	}
	if parsed.Scheme != "https" {
		return nil, safetyError(SafetyReasonInvalidScheme, "target URL must use HTTPS")
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
		return nil, safetyError(classifyUnsafeIP(net.ParseIP(host)), "target hostname must not be an IP address")
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

func allowDevelopmentLocalHTTP(parsed *url.URL) bool {
	if parsed == nil || parsed.Scheme != "http" {
		return false
	}
	if strings.ToLower(strings.TrimSpace(os.Getenv("APP_ENV"))) != "development" {
		return false
	}
	if strings.ToLower(strings.TrimSpace(os.Getenv("APP_PROXY_ALLOW_LOCAL_HTTP"))) != "true" {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(parsed.Hostname()), "."))
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func ValidateTargetURL(ctx context.Context, raw string, lookup IPLookupFunc) (*url.URL, error) {
	parsed, err := NormalizeAndValidateTargetURL(raw)
	if err != nil {
		return nil, err
	}
	if allowDevelopmentLocalHTTP(parsed) {
		return parsed, nil
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
			return nil, safetyError(classifyUnsafeIP(addr.IP), "hostname resolves to private IP")
		}
	}
	return parsed, nil
}

type DialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

func SafeDialContext(lookup IPLookupFunc) DialContextFunc {
	dialer := &net.Dialer{}
	return safeDialContext(lookup, dialer.DialContext)
}

func safeDialContext(lookup IPLookupFunc, dial DialContextFunc) DialContextFunc {
	if lookup == nil {
		lookup = net.DefaultResolver.LookupIPAddr
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, safetyError(SafetyReasonDNSProtection, "outbound address is invalid")
		}
		if ip := net.ParseIP(host); ip != nil {
			if !isSafeResolvedIP(ip) {
				return nil, safetyError(classifyUnsafeIP(ip), "outbound address is unsafe")
			}
			return dial(ctx, network, net.JoinHostPort(ip.String(), port))
		}
		addrs, err := lookup(ctx, host)
		if err != nil || len(addrs) == 0 {
			return nil, safetyError(SafetyReasonDNSProtection, "outbound hostname could not be safely resolved")
		}
		for _, addr := range addrs {
			if !isSafeResolvedIP(addr.IP) {
				return nil, safetyError(classifyUnsafeIP(addr.IP), "outbound hostname resolved to an unsafe IP address")
			}
		}
		var lastErr error
		for _, addr := range addrs {
			conn, err := dial(ctx, network, net.JoinHostPort(addr.IP.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, fmt.Errorf("connect to validated target: %w", lastErr)
	}
}

func classifyUnsafeIP(ip net.IP) string {
	if ip == nil {
		return SafetyReasonUnsafeIP
	}
	if ip.IsLoopback() {
		return SafetyReasonLoopbackIP
	}
	if ip.IsPrivate() {
		return SafetyReasonPrivateIP
	}
	return SafetyReasonUnsafeIP
}

func isSafeResolvedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if !ip.IsGlobalUnicast() {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range blockedAddressPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

var blockedAddressPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
}
