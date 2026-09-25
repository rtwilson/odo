// Package httperror writes Odo-generated server errors without exposing their causes.
package httperror

import (
	"encoding/json"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"example.org/odo/internal/accesslog"
)

// Write logs the internal cause and returns a stable public response. Only Odo
// browser pages receive HTML; API and proxy errors always receive JSON.
func Write(w http.ResponseWriter, r *http.Request, logger *slog.Logger, status int, err error) {
	if accesslog.MetadataFrom(r.Context()) == nil {
		ctx, _ := accesslog.WithMetadata(r.Context())
		r = r.WithContext(ctx)
	}
	id := accesslog.RequestID(r)
	w.Header().Set("X-Request-ID", id)
	logError(r, logger, status, err)
	message := "An internal error occurred."
	if r.URL.Path == "/login" || r.URL.Path == "/admin" || r.URL.Path == "/resources" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		_, _ = fmt.Fprintf(w, "<!doctype html><html><body><h1>%s</h1><p>Request ID: %s</p></body></html>", message, html.EscapeString(id))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": "internal_error", "message": message, "request_id": id,
	})
}

// logError uses registered route patterns, never request URLs, headers, or bodies.
func logError(r *http.Request, logger *slog.Logger, status int, err error) {
	if logger == nil {
		logger = slog.Default()
	}
	route := r.Pattern
	if route == "" {
		// Authentication can fail before the mux assigns a route pattern.
		route = "unmatched"
		if strings.HasPrefix(r.URL.Path, "/api/v1") {
			route = "/api/v1/*"
		}
	}
	logger.ErrorContext(r.Context(), "request failed", "request_id", accesslog.RequestID(r),
		"method", r.Method, "route", route, "status", status, "error", logCause(err))
}

// url.Error includes the full target URL (possibly credentials/search terms).
// Preserve operation/wrapper context and the underlying cause, but omit URLs.
func logCause(err error) string {
	if err == nil {
		return "unspecified internal failure"
	}
	if e, ok := err.(interface{ Unwrap() []error }); ok {
		var causes []string
		for _, cause := range e.Unwrap() {
			causes = append(causes, logCause(cause))
		}
		return strings.Join(causes, "; ")
	}
	if e, ok := err.(*url.Error); ok {
		return e.Op + ": " + logCause(e.Err)
	}
	if e, ok := err.(interface{ Unwrap() error }); ok && e.Unwrap() != nil {
		inner := e.Unwrap()
		prefix := strings.TrimSuffix(err.Error(), inner.Error())
		if prefix != err.Error() {
			return prefix + logCause(inner)
		}
		return logCause(inner)
	}
	return err.Error()
}
