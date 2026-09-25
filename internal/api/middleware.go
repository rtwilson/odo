package api

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
	"time"

	"example.org/odo/internal/accesslog"
	"example.org/odo/internal/db"
)

type AuthContext struct {
	SubjectType     string   `json:"subject_type"`
	SubjectID       string   `json:"id,omitempty"`
	Name            string   `json:"name,omitempty"`
	DisplayName     string   `json:"display_name,omitempty"`
	Username        string   `json:"username,omitempty"`
	Scopes          []string `json:"scopes,omitempty"`
	Roles           []string `json:"roles,omitempty"`
	IsAuthenticated bool     `json:"authenticated"`
	IsAdminLike     bool     `json:"is_admin_like,omitempty"`
	csrfToken       string
}

func (s *Server) optionalAPIAuthentication(r *http.Request) (AuthContext, bool, error) {
	if token := bearerToken(r.Header.Get("Authorization")); token != "" {
		auth, status, _, err := s.authenticateBearerToken(token)
		return auth, status == 0 && auth.IsAuthenticated, err
	}
	auth, ok, err := s.currentUserAuth(r)
	return auth, ok && auth.IsAuthenticated, err
}

func (s *Server) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, metadata := accesslog.WithMetadata(r.Context())
		r = r.WithContext(ctx)
		metadata.RequestID = accesslog.RequestID(r)
		w.Header().Set("X-Request-ID", metadata.RequestID)

		start := time.Now()
		recorder := &responseRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		s.accessLog.Log(r, recorder.status, recorder.bytes, time.Since(start))
	})
}

type responseRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

type apiAuthContextKey struct{}

func (s *Server) requireAPIAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (r.URL.Path != "/api/v1" && !strings.HasPrefix(r.URL.Path, "/api/v1/")) || publicAPIRoute(r) {
			next.ServeHTTP(w, r)
			return
		}

		var auth AuthContext
		var status int
		var err error
		if token := bearerToken(r.Header.Get("Authorization")); token != "" {
			auth, status, _, err = s.authenticateBearerToken(token)
		} else {
			var ok bool
			auth, ok, err = s.currentUserAuth(r)
			if !ok {
				status = http.StatusUnauthorized
			}
		}
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		if status != 0 || !auth.IsAuthenticated {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication_required"})
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), apiAuthContextKey{}, auth)))
	})
}

func publicAPIRoute(r *http.Request) bool {
	return r.Method == http.MethodGet && (r.URL.Path == "/api/v1" || r.URL.Path == "/api/v1/health")
}

func (r *responseRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *responseRecorder) Write(data []byte) (int, error) {
	n, err := r.ResponseWriter.Write(data)
	r.bytes += n
	return n, err
}

func (s *Server) requireAdminAPIKey(next http.HandlerFunc) http.HandlerFunc {
	return s.requireScopes(next)
}

func (s *Server) requireScopes(next http.HandlerFunc, scopes ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth, status, message, err := s.authorizeRequest(r, scopes...)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		if status != 0 {
			if status == http.StatusForbidden && auth.SubjectType == "user" && unsafeMethod(r.Method) && message == "csrf token is invalid or missing" {
				_ = s.store.Audit("csrf_failure", fmt.Sprintf(`{"subject_type":"user","subject_id":%q,"path":%q}`, auth.SubjectID, r.URL.Path))
			}
			if status == http.StatusForbidden {
				writeError(w, status, "forbidden")
			} else {
				writeError(w, status, message)
			}
			return
		}
		if !auth.IsAuthenticated {
			next(w, r)
			return
		}
		if auth.SubjectType == "user" {
			_ = s.store.Audit("admin_api_call_by_user", fmt.Sprintf(`{"subject_id":%q,"path":%q,"method":%q}`, auth.SubjectID, r.URL.Path, r.Method))
		} else if auth.SubjectType == "api_key" {
			_ = s.store.Audit("admin_api_call_by_api_key", fmt.Sprintf(`{"subject_id":%q,"path":%q,"method":%q}`, auth.SubjectID, r.URL.Path, r.Method))
		}
		next(w, r)
	}
}

func (s *Server) authorizeRequest(r *http.Request, requiredScopes ...string) (AuthContext, int, string, error) {
	if auth, ok := r.Context().Value(apiAuthContextKey{}).(AuthContext); ok && auth.IsAuthenticated {
		if !hasRequiredScope(auth.Scopes, requiredScopes) {
			return auth, http.StatusForbidden, "insufficient scope", nil
		}
		if auth.SubjectType == "user" && unsafeMethod(r.Method) && r.Header.Get("X-Odo-CSRF") != auth.csrfToken {
			return auth, http.StatusForbidden, "csrf token is invalid or missing", nil
		}
		return auth, 0, "", nil
	}
	if token := bearerToken(r.Header.Get("Authorization")); token != "" {
		return s.authenticateBearerToken(token, requiredScopes...)
	}
	auth, ok, err := s.currentUserAuth(r)
	if err != nil {
		return anonymousAuthContext(), http.StatusInternalServerError, "", err
	}
	if ok {
		if !hasRequiredScope(auth.Scopes, requiredScopes) {
			return auth, http.StatusForbidden, "insufficient scope", nil
		}
		if unsafeMethod(r.Method) && r.Header.Get("X-Odo-CSRF") != auth.csrfToken {
			return auth, http.StatusForbidden, "csrf token is invalid or missing", nil
		}
		return auth, 0, "", nil
	}
	storedCount, err := s.store.CountAPIKeys()
	if err != nil {
		return anonymousAuthContext(), http.StatusInternalServerError, "", err
	}
	if storedCount == 0 && s.adminKey == "" {
		return anonymousAuthContext(), 0, "", nil
	}
	return anonymousAuthContext(), http.StatusUnauthorized, "missing bearer token", nil
}

func (s *Server) authenticateBearerToken(token string, requiredScopes ...string) (AuthContext, int, string, error) {
	if s.adminKey != "" && subtle.ConstantTimeCompare([]byte(token), []byte(s.adminKey)) == 1 {
		auth := AuthContext{
			SubjectType:     "api_key",
			SubjectID:       "bootstrap",
			Name:            "Bootstrap admin API key",
			Scopes:          []string{"admin"},
			IsAuthenticated: true,
			IsAdminLike:     true,
		}
		return auth, 0, "", nil
	}
	key, found, err := s.store.GetAPIKeyByHash(s.hashAPIToken(token))
	if err != nil {
		return anonymousAuthContext(), http.StatusInternalServerError, "", err
	}
	if !found {
		return anonymousAuthContext(), http.StatusForbidden, "invalid bearer token", nil
	}
	if key.Status != "active" || key.RevokedAt != "" {
		return anonymousAuthContext(), http.StatusForbidden, "invalid bearer token", nil
	}
	if key.ExpiresAt != "" {
		expiresAt, err := time.Parse(time.RFC3339, key.ExpiresAt)
		if err != nil || time.Now().UTC().After(expiresAt) {
			return anonymousAuthContext(), http.StatusForbidden, "invalid bearer token", nil
		}
	}
	auth := AuthContext{
		SubjectType:     "api_key",
		SubjectID:       key.ID,
		Name:            key.Name,
		Scopes:          key.Scopes,
		IsAuthenticated: true,
		IsAdminLike:     hasRequiredScope(key.Scopes, nil),
	}
	if !hasRequiredScope(auth.Scopes, requiredScopes) {
		return auth, http.StatusForbidden, "insufficient scope", nil
	}
	if err := s.store.MarkAPIKeyUsed(key.ID); err != nil {
		return auth, http.StatusInternalServerError, "", err
	}
	return auth, 0, "", nil
}

func anonymousAuthContext() AuthContext {
	return AuthContext{SubjectType: "anonymous", IsAuthenticated: false}
}

func unsafeMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func bearerToken(header string) string {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, prefix))
}

func authContextForUser(user db.User, csrfToken string) AuthContext {
	scopes := scopesForRoles(user.Roles)
	return AuthContext{
		SubjectType:     "user",
		SubjectID:       user.ID,
		DisplayName:     displayUser(user),
		Username:        user.Username,
		Roles:           user.Roles,
		Scopes:          scopes,
		IsAuthenticated: true,
		IsAdminLike:     hasRequiredScope(scopes, []string{"resources:read", "config:read", "diagnostics:read", "logs:read", "system:read", "api_keys:read", "api_keys:write", "users:read", "users:write", "auth:read", "auth:write"}),
		csrfToken:       csrfToken,
	}
}

func scopesForRoles(roles []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(scopes ...string) {
		for _, scope := range scopes {
			if !seen[scope] {
				out = append(out, scope)
				seen[scope] = true
			}
		}
	}
	for _, role := range roles {
		switch strings.ToLower(strings.TrimSpace(role)) {
		case "admin", "super_admin":
			add("admin")
		case "systems_admin":
			add("resources:read", "resources:write", "config:read", "config:write", "diagnostics:read", "logs:read", "system:read")
		case "resource_admin":
			add("resources:read", "resources:write", "config:read", "config:write", "diagnostics:read")
		case "support_staff":
			add("resources:read", "diagnostics:read", "logs:read")
		case "security_admin":
			add("users:read", "users:write", "logs:read", "diagnostics:read")
		case "viewer":
			add("resources:read", "config:read", "diagnostics:read", "system:read")
		}
	}
	return out
}

func hasRequiredScope(granted, required []string) bool {
	for _, scope := range granted {
		if scope == "admin" {
			return true
		}
	}
	if len(required) == 0 {
		return true
	}
	grantedSet := map[string]bool{}
	for _, scope := range granted {
		grantedSet[scope] = true
	}
	for _, scope := range required {
		if grantedSet[scope] {
			return true
		}
	}
	return false
}
