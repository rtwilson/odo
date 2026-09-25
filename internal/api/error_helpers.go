package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"example.org/odo/internal/httperror"
)

func writeAdminForbidden(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8"><title>odo admin forbidden</title></head><body><main><h1>Admin access denied</h1><p>%s</p><p><a href="/resources">Go to resources</a></p></main></body></html>`, htmlEscape(message))
}

func htmlEscape(value string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&#34;", "'", "&#39;")
	return replacer.Replace(value)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func (s *Server) internalError(w http.ResponseWriter, r *http.Request, err error) {
	httperror.Write(w, r, s.logger, http.StatusInternalServerError, err)
}

// internalFailure separates operational failures from safe validation errors
// returned by helpers that can encounter either kind.
type internalFailure struct{ err error }

func (e internalFailure) Error() string { return e.err.Error() }
func (e internalFailure) Unwrap() error { return e.err }

func (s *Server) validationError(w http.ResponseWriter, r *http.Request, err error) {
	var internal internalFailure
	if errors.As(err, &internal) {
		s.internalError(w, r, err)
		return
	}
	writeError(w, http.StatusBadRequest, err.Error())
}
