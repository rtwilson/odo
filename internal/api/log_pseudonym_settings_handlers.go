package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"example.org/odo/internal/accesslog"
)

type pseudonymPolicyRequest struct {
	Mode   string `json:"mode"`
	Unit   string `json:"unit"`
	Count  int    `json:"count"`
	Reason string `json:"reason"`
}

// getLogPseudonymPolicy reports the patron-key rotation policy for new access
// log lines and its full history. It never reveals the secret or any key.
func (s *Server) getLogPseudonymPolicy(w http.ResponseWriter, r *http.Request) {
	history, err := s.store.LogPseudonymPolicies()
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"current": history[len(history)-1], "history": history})
}

// setLogPseudonymPolicy changes how long patron keys stay the same. It needs
// admin scope and a stated reason; the change and its audit event commit
// together and apply to new log lines immediately. Earlier lines keep their
// keys, and re-identification uses the policy in force when they were written.
func (s *Server) setLogPseudonymPolicy(w http.ResponseWriter, r *http.Request) {
	auth, ok := r.Context().Value(apiAuthContextKey{}).(AuthContext)
	if !ok || !auth.IsAuthenticated {
		writeError(w, http.StatusUnauthorized, "authentication_required")
		return
	}
	defer r.Body.Close()
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	var req pseudonymPolicyRequest
	if err := decoder.Decode(&req); err != nil || decoder.Decode(new(any)) != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if n := utf8.RuneCountInString(req.Reason); n < 10 || n > 500 {
		writeError(w, http.StatusBadRequest, "reason must be 10 to 500 characters")
		return
	}
	policy, err := (accesslog.RotationPolicy{Mode: req.Mode, Unit: req.Unit, Count: req.Count}).Normalize()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	previous, err := s.store.CurrentLogPseudonymPolicy()
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	detail, _ := json.Marshal(map[string]any{
		"subject_type": auth.SubjectType, "subject_id": auth.SubjectID,
		"previous": map[string]any{"mode": previous.Mode, "unit": previous.Unit, "count": previous.Count},
		"policy":   map[string]any{"mode": policy.Mode, "unit": policy.Unit, "count": policy.Count},
		"reason":   req.Reason,
	})
	saved, err := s.store.SetLogPseudonymPolicy(policy, time.Now(), string(detail))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if pseudonymizer := s.accessLog.Pseudonymizer(); pseudonymizer != nil {
		pseudonymizer.SetPolicy(saved)
	}
	writeJSON(w, http.StatusOK, map[string]any{"current": saved})
}
