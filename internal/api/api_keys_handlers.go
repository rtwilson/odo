package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"example.org/odo/internal/db"
)

type apiKeyCreateRequest struct {
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes"`
	ExpiresAt string   `json:"expires_at"`
}

type apiKeyResponse struct {
	db.APIKey
	Token string `json:"token,omitempty"`
}

func (s *Server) createAPIKey(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var req apiKeyCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	key, token, err := s.newStoredAPIKey(req)
	if err != nil {
		s.validationError(w, r, err)
		return
	}
	if err := s.store.CreateAPIKey(key); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, apiKeyResponse{APIKey: key, Token: token})
}

func (s *Server) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.store.ListAPIKeys()
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"api_keys": keys})
}

func (s *Server) getAPIKey(w http.ResponseWriter, r *http.Request) {
	key, found, err := s.store.GetAPIKey(strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "api key not found")
		return
	}
	writeJSON(w, http.StatusOK, key)
}

func (s *Server) rotateAPIKey(w http.ResponseWriter, r *http.Request) {
	token, err := generateAPIToken("odo_live_")
	if err != nil {
		s.internalError(w, r, fmt.Errorf("token generation failed: %w", err))
		return
	}
	key, found, err := s.store.RotateAPIKey(strings.TrimSpace(r.PathValue("id")), s.hashAPIToken(token), keyPrefix(token))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "api key not found")
		return
	}
	writeJSON(w, http.StatusOK, apiKeyResponse{APIKey: key, Token: token})
}

func (s *Server) revokeAPIKey(w http.ResponseWriter, r *http.Request) {
	key, found, err := s.store.RevokeAPIKey(strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "api key not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": true, "api_key": key})
}

func (s *Server) deleteAPIKey(w http.ResponseWriter, r *http.Request) {
	key, found, err := s.store.DeleteAPIKey(strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "api key not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "api_key": key})
}

func (s *Server) newStoredAPIKey(req apiKeyCreateRequest) (db.APIKey, string, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return db.APIKey{}, "", fmt.Errorf("api key name is required")
	}
	scopes, err := validateAPIKeyScopes(req.Scopes)
	if err != nil {
		return db.APIKey{}, "", err
	}
	if req.ExpiresAt != "" {
		if _, err := time.Parse(time.RFC3339, req.ExpiresAt); err != nil {
			return db.APIKey{}, "", fmt.Errorf("expires_at must be RFC3339")
		}
	}
	token, err := generateAPIToken("odo_live_")
	if err != nil {
		return db.APIKey{}, "", internalFailure{err}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	id, err := randomID("key_", 12)
	if err != nil {
		return db.APIKey{}, "", internalFailure{err}
	}
	return db.APIKey{
		ID:        id,
		Name:      name,
		KeyHash:   s.hashAPIToken(token),
		KeyPrefix: keyPrefix(token),
		Scopes:    scopes,
		Status:    "active",
		ExpiresAt: strings.TrimSpace(req.ExpiresAt),
		CreatedAt: now,
		UpdatedAt: now,
	}, token, nil
}

func (s *Server) hashAPIToken(token string) string {
	secret := os.Getenv("APP_KEY_HASH_SECRET")
	if secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write([]byte(token))
		return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil))
	}
	sum := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func generateAPIToken(prefix string) (string, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(random), nil
}

func keyPrefix(token string) string {
	if len(token) <= len("odo_live_")+8 {
		return token
	}
	return token[:len("odo_live_")+8]
}

var validAPIKeyScopes = map[string]bool{
	"admin":            true,
	"api_keys:read":    true,
	"api_keys:write":   true,
	"resources:read":   true,
	"resources:write":  true,
	"config:read":      true,
	"config:write":     true,
	"diagnostics:read": true,
	"logs:read":        true,
	"auth:read":        true,
	"auth:write":       true,
	"system:read":      true,
	"users:read":       true,
	"users:write":      true,
}

func validateAPIKeyScopes(scopes []string) ([]string, error) {
	if len(scopes) == 0 {
		return []string{"admin"}, nil
	}
	seen := map[string]bool{}
	var out []string
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if !validAPIKeyScopes[scope] {
			return nil, fmt.Errorf("unknown scope %q", scope)
		}
		if !seen[scope] {
			out = append(out, scope)
			seen[scope] = true
		}
	}
	return out, nil
}
