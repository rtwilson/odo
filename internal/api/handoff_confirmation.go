package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"example.org/odo/internal/auth/local"
)

const (
	handoffConfirmPath  = "/launch/handoff/confirm"
	handoffNonceCookie  = "__Host-odo_handoff_nonce"
	maxConfirmationBody = 4096
)

// Standalone wrapper for focused tests; runtime registration requires the
// explicit experimental handoff-only mode.
func (h *handoffSecurity) centralConfirmationHandler() http.Handler {
	return h.server.logging(appSecurityHeaders(http.HandlerFunc(h.serveConfirmation)))
}

func (h *handoffSecurity) serveConfirmation(w http.ResponseWriter, r *http.Request) {
	handoffHeaders(w, r, "handoff_confirmation")
	if !requestOnCentralHost(r, h.config) {
		writeError(w, http.StatusMisdirectedRequest, "request authority is not admitted")
		return
	}
	if r.URL.Path != handoffConfirmPath || r.URL.EscapedPath() != handoffConfirmPath {
		handoffNavigationFailure(w, http.StatusNotFound)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if r.Method == http.MethodPost && !centralRequestOriginAllowed(r, h.config) {
		writeError(w, http.StatusForbidden, "request origin is not allowed")
		return
	}
	fields, status := confirmationFields(w, r)
	if status != 0 {
		writeError(w, status, "invalid confirmation input")
		return
	}
	token, proof := fields.Get("handoff"), fields.Get("proof")
	if !validLaunchToken(token) || !validLaunchToken(proof) {
		handoffNavigationFailure(w, http.StatusNotFound)
		return
	}
	central, ok := uniqueConfirmationCookie(r, "__Host-odo_session")
	if !ok || len(central) > maxHandoffSessionFieldBytes || local.SessionIDFromToken(central) == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login_required", "login_url": "/login", "message": "Authentication could not complete. Allow cookies and sign in again from Resources."})
		return
	}
	nonce, ok := uniqueConfirmationCookie(r, handoffNonceCookie)
	if !ok || !validLaunchToken(nonce) {
		handoffNavigationFailure(w, http.StatusNotFound)
		return
	}
	csrf := csrfTokenForSessionToken(central)
	if r.Method == http.MethodPost && subtle.ConstantTimeCompare([]byte(fields.Get("csrf")), []byte(csrf)) != 1 {
		writeError(w, http.StatusForbidden, "csrf token is invalid or missing")
		return
	}
	pending, err := h.confirmation(r.Context(), token, central, nonce, proof, time.Now().UTC())
	if err != nil {
		h.confirmationError(w, r, err)
		return
	}
	if r.Method == http.MethodGet {
		allowHandoffFormRedirect(r, pending.binding.proxyAuthority)
		if policy, ok := r.Context().Value(responsePolicyKey{}).(*appResponseWriter); ok {
			sum := sha256.Sum256([]byte(handoffContinueScript))
			policy.csp = strings.Replace(policy.csp, "script-src 'none'", "script-src 'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'; connect-src 'self'", 1)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Connecting to resource</title></head><body><main><h1>Continue to %s</h1><p id="status" role="status">Connecting securely…</p><form id="handoff" method="post" action="/launch/handoff/confirm" hidden><input type="hidden" name="handoff" value="%s"><input type="hidden" name="proof" value="%s"><input type="hidden" name="csrf" value="%s"></form><noscript>JavaScript is required to continue automatically. Enable it and launch the resource again.</noscript><p><a href="/resources">Return to Resources</a></p></main><script>%s</script></body></html>`, html.EscapeString(pending.binding.hostname), html.EscapeString(token), html.EscapeString(proof), html.EscapeString(csrf), handoffContinueScript)
		return
	}
	// Refresh the time after live database/DNS checks. An expired/rotated proof
	// cannot pass on the strength of the earlier read-only authorization snapshot.
	ticket, err := h.state.confirm(token, pending.binding, nonce, proof, time.Now().UTC())
	if err != nil {
		h.confirmationError(w, r, err)
		return
	}
	location := url.URL{Scheme: "https", Host: pending.binding.proxyAuthority, Path: handoffVendorPath, RawQuery: url.Values{"ticket": {ticket}}.Encode()}
	if r.Header.Get("Accept") == "application/json" {
		writeJSON(w, http.StatusOK, map[string]string{"next": location.String()})
		return
	}
	http.Redirect(w, r, location.String(), http.StatusSeeOther)
}

// allowHandoffFormRedirect lets this page's confirmation form complete. The
// POST answers with a 303 to the vendor proxy host, and browsers enforce CSP
// form-action on every redirect of a form submission, so 'self' alone blocks
// it. Only the exact registered proxy origin of this pending handoff is added;
// an authority with anything but DNS characters is never interpolated.
func allowHandoffFormRedirect(r *http.Request, proxyAuthority string) {
	policy, ok := r.Context().Value(responsePolicyKey{}).(*appResponseWriter)
	if !ok || proxyAuthority == "" || strings.Trim(proxyAuthority, "abcdefghijklmnopqrstuvwxyz0123456789.-") != "" {
		return
	}
	policy.csp = strings.Replace(policy.csp, "form-action 'self'", "form-action 'self' https://"+proxyAuthority, 1)
}

func uniqueConfirmationCookie(r *http.Request, name string) (string, bool) {
	value, count := "", 0
	for _, cookie := range r.Cookies() {
		if cookie.Name == name {
			value = cookie.Value
			count++
		}
	}
	return value, count == 1 && value != ""
}

func confirmationFields(w http.ResponseWriter, r *http.Request) (url.Values, int) {
	encoded := r.URL.RawQuery
	expected := []string{"handoff", "proof"}
	if r.Method == http.MethodPost {
		if encoded != "" || r.URL.ForceQuery {
			return nil, http.StatusBadRequest
		}
		contentTypes := r.Header.Values("Content-Type")
		if len(contentTypes) != 1 || r.Header.Get("Content-Encoding") != "" {
			return nil, http.StatusUnsupportedMediaType
		}
		media, parameters, err := mime.ParseMediaType(contentTypes[0])
		if err != nil || media != "application/x-www-form-urlencoded" || (len(parameters) != 0 && (len(parameters) != 1 || !strings.EqualFold(parameters["charset"], "utf-8"))) {
			return nil, http.StatusUnsupportedMediaType
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxConfirmationBody))
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				return nil, http.StatusRequestEntityTooLarge
			}
			return nil, http.StatusBadRequest
		}
		encoded = string(body)
		// CSRF absence is an authorization failure (403), not a parsing error.
	} else if len(encoded) > 1024 {
		return nil, http.StatusBadRequest
	}
	values, err := url.ParseQuery(encoded)
	if r.Method == http.MethodPost {
		if _, present := values["csrf"]; present {
			expected = append(expected, "csrf")
		}
	}
	if err != nil || len(values) != len(expected) {
		return nil, http.StatusBadRequest
	}
	for _, key := range expected {
		if len(values[key]) != 1 {
			return nil, http.StatusBadRequest
		}
	}
	return values, 0
}

func (h *handoffSecurity) confirmationError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, errInvalidPendingHandoff), errors.Is(err, errInvalidHandoffTicket):
		handoffNavigationFailure(w, http.StatusNotFound)
	case errors.Is(err, errHandoffDenied):
		writeError(w, http.StatusForbidden, "handoff is not allowed")
	case errors.Is(err, errHandoffTicketsFull), errors.Is(err, errPendingHandoffsFull), errors.Is(err, errHandoffGrantsFull):
		writeError(w, http.StatusServiceUnavailable, "handoff temporarily unavailable")
	default:
		h.server.internalError(w, r, err)
	}
}
