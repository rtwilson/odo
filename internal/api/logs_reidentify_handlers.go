package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"example.org/odo/internal/accesslog"
)

const (
	reidentifyScope   = "logs:reidentify"
	maxReidentifyDays = 731
	maxReidentifyKeys = 2000
)

type patronKeyWindow struct {
	PatronKey string    `json:"patron_key"`
	Mode      string    `json:"mode"`
	From      time.Time `json:"from"`
	To        time.Time `json:"to"`
}

type reidentifyRequest struct {
	Username string `json:"username"`
	From     string `json:"from"`
	To       string `json:"to"`
	Reason   string `json:"reason"`
}

// reidentifyPatron derives the patron keys one named user had so that
// an authorized investigator (security incident, abusive or automated use) can
// find that user's pseudonymous access-log lines. It is a forward lookup only:
// keys are derived from the secret, never looked up from a stored mapping.
//
// It requires the literal logs:reidentify scope; admin alone is not enough. A
// stated reason is required and every lookup is audited with the actor, the
// target account and the date range, before any key is returned.
func (s *Server) reidentifyPatron(w http.ResponseWriter, r *http.Request) {
	auth, ok := r.Context().Value(apiAuthContextKey{}).(AuthContext)
	if !ok || !auth.IsAuthenticated {
		writeError(w, http.StatusUnauthorized, "authentication_required")
		return
	}
	explicit := false
	for _, scope := range auth.Scopes {
		explicit = explicit || scope == reidentifyScope
	}
	if !explicit {
		writeError(w, http.StatusForbidden, "the logs:reidentify scope must be granted explicitly; admin alone is not sufficient")
		return
	}
	defer r.Body.Close()
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	var req reidentifyRequest
	if err := decoder.Decode(&req); err != nil || decoder.Decode(new(any)) != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	req.Username, req.Reason = strings.TrimSpace(req.Username), strings.TrimSpace(req.Reason)
	if req.Username == "" {
		writeError(w, http.StatusBadRequest, "username is required")
		return
	}
	if n := utf8.RuneCountInString(req.Reason); n < 10 || n > 500 {
		writeError(w, http.StatusBadRequest, "reason must be 10 to 500 characters")
		return
	}
	from, fromErr := time.Parse("2006-01-02", strings.TrimSpace(req.From))
	to, toErr := time.Parse("2006-01-02", strings.TrimSpace(req.To))
	if fromErr != nil || toErr != nil || to.Before(from) || to.Sub(from) > maxReidentifyDays*24*time.Hour {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("from and to must be YYYY-MM-DD dates, from not after to, spanning at most %d days", maxReidentifyDays))
		return
	}
	end := to.AddDate(0, 0, 1) // inclusive of the whole "to" day
	user, found, err := s.store.GetUserByUsername(req.Username)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	pseudonymizer := s.accessLog.Pseudonymizer()
	if pseudonymizer == nil {
		writeError(w, http.StatusServiceUnavailable, "access logging is not configured")
		return
	}
	history, err := s.store.LogPseudonymPolicies()
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	keys, err := s.patronKeyWindows(pseudonymizer, history, user.ID, from, end)
	if errors.Is(err, errTooManyPatronKeys) {
		writeError(w, http.StatusBadRequest, "the range covers too many keys; narrow from/to")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	detail, _ := json.Marshal(map[string]any{
		"subject_type": auth.SubjectType, "subject_id": auth.SubjectID,
		"target_user_id": user.ID, "from": req.From, "to": req.To, "keys": len(keys), "reason": req.Reason,
	})
	// Audit before disclosing: if the audit record cannot be written, refuse.
	if err := s.store.Audit("patron_log_reidentified", string(detail)); err != nil {
		s.internalError(w, r, err)
		return
	}
	wanted := map[string]bool{}
	for _, key := range keys {
		wanted[key.PatronKey] = true
	}
	matches := []accesslog.Entry{}
	for _, entry := range s.accessLog.Recent() {
		if wanted[entry.PatronKey] {
			matches = append(matches, entry)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"user_id": user.ID, "keys": keys, "recent_entries": matches})
}

var errTooManyPatronKeys = errors.New("too many patron keys")

// patronKeyWindows derives every key userID had between from and end under
// each policy in history (oldest first), clipped to when each policy applied.
func (s *Server) patronKeyWindows(p *accesslog.Pseudonymizer, history []accesslog.RotationPolicy, userID string, from, end time.Time) ([]patronKeyWindow, error) {
	var keys []patronKeyWindow
	add := func(window patronKeyWindow) error {
		if len(keys) >= maxReidentifyKeys {
			return errTooManyPatronKeys
		}
		keys = append(keys, window)
		return nil
	}
	for i, policy := range history {
		start, stop := policy.EffectiveFrom, end
		if i+1 < len(history) {
			stop = history[i+1].EffectiveFrom
		}
		if start.Before(from) {
			start = from
		}
		if stop.After(end) {
			stop = end
		}
		if !start.Before(stop) {
			continue
		}
		switch policy.Mode {
		case accesslog.RotationNever:
			if err := add(patronKeyWindow{p.KeyUnder(policy, userID, "", start), policy.Mode, start, stop}); err != nil {
				return nil, err
			}
		case accesslog.RotationSession:
			sessions, err := s.store.UserSessionIDsBetween(userID, start, stop)
			if err != nil {
				return nil, err
			}
			// Lines written without a session fall back to the user-stable key.
			if err := add(patronKeyWindow{p.KeyUnder(policy, userID, "", start), policy.Mode, start, stop}); err != nil {
				return nil, err
			}
			for _, session := range sessions {
				if err := add(patronKeyWindow{p.KeyUnder(policy, userID, session, start), policy.Mode, start, stop}); err != nil {
					return nil, err
				}
			}
		default:
			for at := start; at.Before(stop); {
				_, windowEnd, _ := policy.Window(at)
				clipped := windowEnd
				if clipped.After(stop) {
					clipped = stop
				}
				if err := add(patronKeyWindow{p.KeyUnder(policy, userID, "", at), policy.Mode, at, clipped}); err != nil {
					return nil, err
				}
				at = windowEnd
			}
		}
	}
	return keys, nil
}
