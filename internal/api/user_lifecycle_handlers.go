package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"example.org/odo/internal/auth/local"
	"example.org/odo/internal/db"
)

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	// Authentication middleware supplies this identity. Never accept actor IDs
	// from request bodies or use an API-key ID as a browser user's account ID.
	auth, ok := r.Context().Value(apiAuthContextKey{}).(AuthContext)
	if !ok || !auth.IsAuthenticated {
		writeError(w, http.StatusUnauthorized, "authentication_required")
		return
	}
	actorID := ""
	if auth.SubjectType == "user" {
		actorID = auth.SubjectID
	}
	id := strings.TrimSpace(r.PathValue("id"))
	// Deleting a privileged account must not be easier than demoting it:
	// changing or restoring non-default roles already requires admin scope.
	target, exists, err := s.store.GetUser(id)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if exists && !hasRequiredScope(auth.Scopes, []string{"admin"}) {
		for _, role := range target.Roles {
			if role != "user" {
				writeError(w, http.StatusForbidden, "admin scope is required to delete accounts with non-default roles")
				return
			}
		}
	}
	found, err := s.store.DeleteUser(id, actorID)
	if errors.Is(err, db.ErrDeleteSelf) {
		writeError(w, http.StatusForbidden, "cannot delete own account")
		return
	}
	if errors.Is(err, db.ErrLastAdministrator) {
		writeError(w, http.StatusConflict, "cannot delete the last active administrator")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "id": id})
}

func (s *Server) restoreUser(w http.ResponseWriter, r *http.Request) {
	auth, ok := r.Context().Value(apiAuthContextKey{}).(AuthContext)
	if !ok || !auth.IsAuthenticated {
		writeError(w, http.StatusUnauthorized, "authentication_required")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	user, found, err := s.store.GetUser(id)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	// Restoring retained roles must not bypass the permission needed to assign
	// them at creation. Deleted accounts cannot have their roles edited.
	for _, role := range user.Roles {
		if role != "user" && !hasRequiredScope(auth.Scopes, []string{"admin"}) {
			writeError(w, http.StatusForbidden, "admin scope is required to restore non-default roles")
			return
		}
	}
	if user.Status != "deleted" {
		writeError(w, http.StatusConflict, "user is not deleted")
		return
	}
	defer r.Body.Close()
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var req userPasswordRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(req.Password) < 8 || len(req.Password) > 72 {
		writeError(w, http.StatusBadRequest, "password must be between 8 and 72 bytes")
		return
	}
	hash, err := local.HashPassword(req.Password)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	actorID := ""
	if auth.SubjectType == "user" {
		actorID = auth.SubjectID
	}
	found, err = s.store.RestoreUser(id, actorID, hash)
	if errors.Is(err, db.ErrUserNotDeleted) {
		writeError(w, http.StatusConflict, "user is not deleted")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"restored": true, "id": id, "status": "disabled"})
}
