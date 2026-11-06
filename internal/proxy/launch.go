package proxy

import (
	"errors"
	"net/url"
	"strings"
)

// MaxLaunchQueryBytes bounds the complete RawQuery, including the url= envelope.
const MaxLaunchQueryBytes = 16 * 1024

var errInvalidLaunchQuery = errors.New("launch target URL is invalid")

// ParseLaunchQuery parses a launch envelope without DNS or HTTP requests.
// It checks URL syntax only: callers must still apply DNS safety, current
// resource policy, method and session checks before redirecting or fetching.
func ParseLaunchQuery(rawQuery string) (*url.URL, error) {
	if len(rawQuery) > MaxLaunchQueryBytes || !strings.HasPrefix(rawQuery, "url=") {
		return nil, errInvalidLaunchQuery
	}
	raw := strings.TrimPrefix(rawQuery, "url=")
	if !strings.HasPrefix(raw, "https://") {
		if strings.HasSuffix(rawQuery, "&") || strings.Contains(rawQuery, "&&") {
			return nil, errInvalidLaunchQuery
		}
		values, err := url.ParseQuery(rawQuery)
		if err != nil || len(values) != 1 || len(values["url"]) != 1 {
			return nil, errInvalidLaunchQuery
		}
		raw = values["url"][0]
	}
	// Literal fragments (including an empty trailing #) and unescaped ASCII
	// whitespace/control bytes are not a supported launch target. Encoded path
	// data such as %23 remains valid.
	if strings.Contains(raw, "#") {
		return nil, errInvalidLaunchQuery
	}
	for _, ch := range raw {
		if ch <= ' ' || ch == 0x7f {
			return nil, errInvalidLaunchQuery
		}
	}
	target, err := NormalizeAndValidateTargetURL(raw)
	if err != nil || target.Scheme != "https" {
		// HTTPS is mandatory even when local HTTP is enabled for development.
		return nil, errInvalidLaunchQuery
	}
	// net/url validates path escapes during parsing but leaves RawQuery opaque.
	// Check query escapes without replacing or re-encoding the vendor data.
	if _, err := url.QueryUnescape(target.RawQuery); err != nil {
		return nil, errInvalidLaunchQuery
	}
	return target, nil
}
