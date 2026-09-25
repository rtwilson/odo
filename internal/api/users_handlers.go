package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"example.org/odo/internal/auth/local"
	"example.org/odo/internal/db"
)

type userCreateRequest struct {
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	DisplayName string   `json:"display_name"`
	Password    string   `json:"password"`
	Roles       []string `json:"roles"`
	Status      string   `json:"status"`
}

type userPatchRequest struct {
	Email       *string  `json:"email"`
	DisplayName *string  `json:"display_name"`
	Roles       []string `json:"roles"`
	Status      string   `json:"status"`
}

type userPasswordRequest struct {
	Password string `json:"password"`
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers()
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var req userCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(req.Roles) > 0 && !s.requestHasAdminScope(r) {
		writeError(w, http.StatusForbidden, "admin scope is required to set roles")
		return
	}
	user, err := s.newStoredUser(req)
	if err != nil {
		s.validationError(w, r, err)
		return
	}
	if err := s.store.CreateUser(user); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			writeError(w, http.StatusConflict, "user already exists")
		} else {
			s.internalError(w, r, err)
		}
		return
	}
	writeJSON(w, http.StatusCreated, user)
}

func (s *Server) getUser(w http.ResponseWriter, r *http.Request) {
	user, found, err := s.store.GetUser(strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) patchUser(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	id := strings.TrimSpace(r.PathValue("id"))
	existing, found, err := s.store.GetUser(id)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	var req userPatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Email != nil {
		existing.Email = strings.TrimSpace(*req.Email)
	}
	if req.DisplayName != nil {
		existing.DisplayName = strings.TrimSpace(*req.DisplayName)
	}
	if len(req.Roles) > 0 {
		if !s.requestHasAdminScope(r) {
			writeError(w, http.StatusForbidden, "admin scope is required to change roles")
			return
		}
		roles, err := validateUserRoles(req.Roles)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if hasSuperAdminRole(existing.Roles) && !hasSuperAdminRole(roles) && s.activeSuperAdminCount() <= 1 {
			writeError(w, http.StatusBadRequest, "cannot remove the last admin account")
			return
		}
		existing.Roles = roles
	}
	if strings.TrimSpace(req.Status) != "" {
		status, err := validateUserStatus(req.Status)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		existing.Status = status
	}
	user, found, err := s.store.UpdateUser(existing)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	_ = s.store.Audit("user_updated", fmt.Sprintf(`{"id":%q,"username":%q}`, user.ID, user.Username))
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) setUserPassword(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var req userPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}
	if len(req.Password) > 72 {
		writeError(w, http.StatusBadRequest, "password must be at most 72 bytes")
		return
	}
	hash, err := local.HashPassword(req.Password)
	if err != nil {
		s.internalError(w, r, fmt.Errorf("password hashing failed: %w", err))
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	updated, err := s.store.SetUserPassword(id, hash)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !updated {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	_ = s.store.RevokeUserSessions(id)
	_ = s.store.Audit("user_password_set", fmt.Sprintf(`{"id":%q}`, id))
	writeJSON(w, http.StatusOK, map[string]any{"password_set": true, "id": id})
}

func (s *Server) disableUser(w http.ResponseWriter, r *http.Request) {
	s.setUserStatus(w, r, "disabled")
}

func (s *Server) enableUser(w http.ResponseWriter, r *http.Request) {
	s.setUserStatus(w, r, "active")
}

func (s *Server) lockUser(w http.ResponseWriter, r *http.Request) {
	s.setUserStatus(w, r, "locked")
}

func (s *Server) unlockUser(w http.ResponseWriter, r *http.Request) {
	s.setUserStatus(w, r, "active")
}

func (s *Server) revokeUserSessions(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if _, found, err := s.store.GetUser(id); err != nil {
		s.internalError(w, r, err)
		return
	} else if !found {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	if err := s.store.RevokeUserSessions(id); err != nil {
		s.internalError(w, r, err)
		return
	}
	_ = s.store.Audit("user_sessions_revoked", fmt.Sprintf(`{"id":%q}`, id))
	writeJSON(w, http.StatusOK, map[string]any{"sessions_revoked": true, "id": id})
}

func (s *Server) setUserStatus(w http.ResponseWriter, r *http.Request, status string) {
	id := strings.TrimSpace(r.PathValue("id"))
	if status == "disabled" || status == "locked" {
		existing, found, err := s.store.GetUser(id)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		if hasSuperAdminRole(existing.Roles) && s.activeSuperAdminCount() <= 1 {
			writeError(w, http.StatusBadRequest, "cannot disable or lock the last admin account")
			return
		}
	}
	user, found, err := s.store.SetUserStatus(id, status)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	_ = s.store.Audit("user_status_set", fmt.Sprintf(`{"id":%q,"status":%q}`, user.ID, status))
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) requestHasAdminScope(r *http.Request) bool {
	auth, status, _, _ := s.authorizeRequest(r, "admin")
	return status == 0 && auth.IsAuthenticated
}

func (s *Server) activeSuperAdminCount() int {
	users, err := s.store.ListUsers()
	if err != nil {
		return 0
	}
	count := 0
	for _, user := range users {
		if user.Status == "active" && hasSuperAdminRole(user.Roles) {
			count++
		}
	}
	return count
}

func hasSuperAdminRole(roles []string) bool {
	for _, role := range roles {
		switch strings.ToLower(strings.TrimSpace(role)) {
		case "admin", "super_admin":
			return true
		}
	}
	return false
}

func (s *Server) newStoredUser(req userCreateRequest) (db.User, error) {
	username := strings.TrimSpace(req.Username)
	if username == "" {
		return db.User{}, fmt.Errorf("username is required")
	}
	if strings.ContainsAny(username, " \t\r\n") {
		return db.User{}, fmt.Errorf("username must not contain whitespace")
	}
	if len(req.Password) < 8 {
		return db.User{}, fmt.Errorf("password must be at least 8 characters")
	}
	if len(req.Password) > 72 {
		return db.User{}, fmt.Errorf("password must be at most 72 bytes")
	}
	status, err := validateUserStatus(req.Status)
	if err != nil {
		return db.User{}, err
	}
	roles, err := validateUserRoles(req.Roles)
	if err != nil {
		return db.User{}, err
	}
	hash, err := local.HashPassword(req.Password)
	if err != nil {
		return db.User{}, internalFailure{err}
	}
	id, err := randomID("user_", 12)
	if err != nil {
		return db.User{}, internalFailure{err}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	return db.User{
		ID:           id,
		Username:     username,
		Email:        strings.TrimSpace(req.Email),
		DisplayName:  strings.TrimSpace(req.DisplayName),
		PasswordHash: hash,
		Status:       status,
		Roles:        roles,
		CreatedAt:    now,
		UpdatedAt:    now,
	}, nil
}

var validUserRoles = map[string]bool{
	"admin":          true,
	"super_admin":    true,
	"systems_admin":  true,
	"resource_admin": true,
	"support_staff":  true,
	"security_admin": true,
	"viewer":         true,
	"user":           true,
	"staff":          true,
	"test":           true,
}

func validateUserRoles(roles []string) ([]string, error) {
	if len(roles) == 0 {
		return []string{"user"}, nil
	}
	seen := map[string]bool{}
	var out []string
	for _, role := range roles {
		role = strings.TrimSpace(strings.ToLower(role))
		if !validUserRoles[role] {
			return nil, fmt.Errorf("unknown role %q", role)
		}
		if !seen[role] {
			out = append(out, role)
			seen[role] = true
		}
	}
	return out, nil
}

func validateUserStatus(status string) (string, error) {
	status = strings.TrimSpace(strings.ToLower(status))
	if status == "" {
		return "active", nil
	}
	switch status {
	case "active", "disabled", "locked":
		return status, nil
	default:
		return "", fmt.Errorf("unknown user status %q", status)
	}
}
