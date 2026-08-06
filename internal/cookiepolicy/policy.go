package cookiepolicy

import (
	"net/http"
	"net/url"
	"os"
	"strings"
)

// Apply sets the shared transport and site-boundary policy for Odo-owned
// authentication, session, and security cookies. Callers remain responsible
// for purpose-specific values such as HttpOnly and expiry.
func Apply(r *http.Request, cookie *http.Cookie) *http.Cookie {
	cookie.Path = "/"
	cookie.SameSite = http.SameSiteLaxMode
	cookie.Secure = Secure(r)
	return cookie
}

func Secure(r *http.Request) bool {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("APP_ENV")), "production") {
		// Production startup validation requires this to be true. Do not infer
		// production security from request headers or an internal HTTP hop.
		return publicURLIsHTTPS()
	}
	if r != nil && r.TLS != nil {
		return true
	}
	if publicURLIsHTTPS() {
		return true
	}
	return trustProxyHeaders() && r != nil && strings.EqualFold(firstForwardedValue(r.Header.Get("X-Forwarded-Proto")), "https")
}

func publicURLIsHTTPS() bool {
	parsed, err := url.Parse(strings.TrimSpace(os.Getenv("APP_PUBLIC_URL")))
	return err == nil && parsed.Scheme == "https" && parsed.Host != ""
}

func trustProxyHeaders() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("APP_TRUST_PROXY_HEADERS"))) {
	case "true", "1", "yes", "on":
		return true
	default:
		return false
	}
}

func firstForwardedValue(value string) string {
	value, _, _ = strings.Cut(value, ",")
	return strings.TrimSpace(value)
}
