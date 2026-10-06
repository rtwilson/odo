package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"

	"example.org/odo/internal/ui"
)

type responsePolicyKey struct{}

type appResponseWriter struct {
	http.ResponseWriter
	proxy       bool
	wroteHeader bool
	csp         string
}

func (w *appResponseWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	if !w.proxy {
		w.Header().Set("Content-Security-Policy", w.csp)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *appResponseWriter) Write(body []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

func (w *appResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func appSecurityHeaders(next http.Handler) http.Handler {
	// Hash only the trusted, compiled-in admin script, never request data.
	_, script, _ := strings.Cut(ui.AdminHTML(), "<script>")
	script, _, _ = strings.Cut(script, "</script>")
	hash := sha256.Sum256([]byte(script))
	adminScript := "'sha256-" + base64.StdEncoding.EncodeToString(hash[:]) + "'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scriptPolicy := "'none'"
		if r.URL.Path == "/admin" {
			scriptPolicy = adminScript
		}
		writer := &appResponseWriter{ResponseWriter: w, csp: "default-src 'none'; script-src " + scriptPolicy + "; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; font-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'"}
		next.ServeHTTP(writer, r.WithContext(context.WithValue(r.Context(), responsePolicyKey{}, writer)))
		if !writer.wroteHeader {
			writer.WriteHeader(http.StatusOK)
		}
	})
}

// Both explicit proxy routes and missed-rewrite recovery use this boundary.
func vendorResponsePolicy(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if policy, ok := r.Context().Value(responsePolicyKey{}).(*appResponseWriter); ok {
			policy.proxy = true
		}
		next.ServeHTTP(w, r)
	})
}
