package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
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
