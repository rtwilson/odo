package cookiepolicy

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestApplyUsesSecureProductionPublicURL(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("APP_PUBLIC_URL", "https://access.example.edu")
	req := httptest.NewRequest(http.MethodGet, "http://internal.example/", nil)
	cookie := Apply(req, &http.Cookie{Name: "odo_test", HttpOnly: true})
	if !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("unexpected production cookie policy: %#v", cookie)
	}
}

func TestApplyAllowsInsecureLocalDevelopment(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("APP_PUBLIC_URL", "")
	t.Setenv("APP_TRUST_PROXY_HEADERS", "false")
	req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/", nil)
	if cookie := Apply(req, &http.Cookie{Name: "odo_test"}); cookie.Secure {
		t.Fatalf("local HTTP development cookie should not be Secure: %#v", cookie)
	}
}

func TestProductionDoesNotInferSecurePolicyFromUntrustedRuntimeRequest(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("APP_PUBLIC_URL", "http://access.example.edu")
	t.Setenv("APP_TRUST_PROXY_HEADERS", "true")
	req := httptest.NewRequest(http.MethodGet, "https://internal.example/", nil)
	req.TLS = &tls.ConnectionState{}
	req.Header.Set("X-Forwarded-Proto", "https")
	if cookie := Apply(req, &http.Cookie{Name: "odo_test"}); cookie.Secure {
		t.Fatalf("invalid production config must not be made valid by request metadata: %#v", cookie)
	}
}

func TestApplyUsesDirectTLS(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("APP_PUBLIC_URL", "")
	req := httptest.NewRequest(http.MethodGet, "https://localhost/", nil)
	req.TLS = &tls.ConnectionState{}
	if cookie := Apply(req, &http.Cookie{Name: "odo_test"}); !cookie.Secure {
		t.Fatalf("direct TLS cookie should be Secure: %#v", cookie)
	}
}

func TestApplyTrustsForwardedHTTPSOnlyWhenConfigured(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("APP_PUBLIC_URL", "")
	req := httptest.NewRequest(http.MethodGet, "http://internal.example/", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	if cookie := Apply(req, &http.Cookie{Name: "odo_test"}); cookie.Secure {
		t.Fatal("untrusted forwarded header must not enable Secure policy")
	}
	t.Setenv("APP_TRUST_PROXY_HEADERS", "true")
	if cookie := Apply(req, &http.Cookie{Name: "odo_test"}); !cookie.Secure {
		t.Fatal("trusted forwarded HTTPS should enable Secure policy")
	}
}
