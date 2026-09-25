package api

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"example.org/odo/internal/proxy"
	"example.org/odo/internal/ui"
	"example.org/odo/openapi"
)

func (s *Server) root(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		s.handleUnknownPath(w, r)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusFound)
}

func (s *Server) admin(w http.ResponseWriter, r *http.Request) {
	auth, status, message := s.authorizeRequest(r, "resources:read", "config:read", "diagnostics:read", "logs:read", "system:read", "api_keys:read", "api_keys:write", "users:read", "users:write", "auth:read", "auth:write")
	if status != 0 {
		if status == http.StatusUnauthorized {
			http.Redirect(w, r, "/login?next="+url.QueryEscape("/admin"), http.StatusFound)
			return
		}
		writeAdminForbidden(w, message)
		return
	}
	if !auth.IsAuthenticated {
		http.Redirect(w, r, "/login?next="+url.QueryEscape("/admin"), http.StatusFound)
		return
	}
	if !auth.IsAdminLike {
		_ = s.store.Audit("admin_ui_login_denied_insufficient_role", fmt.Sprintf(`{"subject_type":%q,"subject_id":%q}`, auth.SubjectType, auth.SubjectID))
		writeAdminForbidden(w, "admin access requires an admin or staff role")
		return
	}
	if auth.SubjectType == "user" {
		http.SetCookie(w, csrfCookie(r, auth.csrfToken))
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(ui.AdminHTML()))
}

func (s *Server) openapi(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	_, _ = w.Write(openapi.Spec)
}

func (s *Server) userResources(w http.ResponseWriter, r *http.Request) {
	user, _, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		return
	}
	items, err := s.store.ListResources()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var b strings.Builder
	b.WriteString(`<!doctype html><html><head><meta charset="utf-8"><title>odo resources</title><style>:root{color-scheme:dark;font-family:system-ui;background:#101316;color:#f2f4f7}main{max-width:920px;margin:0 auto;padding:28px}a{color:#8cc7ff}li{margin:12px 0}button{padding:8px 10px}</style></head><body><main>`)
	b.WriteString("<h1>Resources</h1><p>Signed in as " + htmlEscape(displayUser(user)) + `</p><form method="post" action="/logout"><button>Logout</button></form><ul>`)
	for _, resource := range items {
		if resource.Status != "active" {
			continue
		}
		entry := ""
		if len(resource.EntryURLs) > 0 {
			entry = resource.EntryURLs[0]
		} else if len(resource.SampleURLs) > 0 {
			entry = resource.SampleURLs[0]
		}
		if entry == "" {
			continue
		}
		parsed, _ := url.Parse(entry)
		b.WriteString(`<li><a href="` + htmlEscape(proxy.BuildProxyURL(parsed)) + `">` + htmlEscape(resource.Title) + `</a></li>`)
	}
	b.WriteString("</ul></main></body></html>")
	_, _ = w.Write([]byte(b.String()))
}

func (s *Server) apiIndex(w http.ResponseWriter, r *http.Request) {
	links := map[string]string{
		"health":    "/api/v1/health",
		"openapi":   "/openapi.yaml",
		"resources": "/api/v1/resources",
	}
	auth, authenticated := s.optionalAPIAuthentication(r)
	response := map[string]any{
		"name":          "Odo API",
		"version":       "v1",
		"status":        "ok",
		"authenticated": authenticated,
		"links":         links,
	}
	if authenticated {
		response["subject_type"] = auth.SubjectType
		links = map[string]string{
			"health":  "/api/v1/health",
			"openapi": "/openapi.yaml",
			"session": "/api/v1/session/me",
		}
		addScopedAPILink(links, auth.Scopes, "resources", "/api/v1/resources", "resources:read")
		addScopedAPILink(links, auth.Scopes, "api_keys", "/api/v1/api-keys", "api_keys:read", "api_keys:write")
		addScopedAPILink(links, auth.Scopes, "users", "/api/v1/users", "users:read", "users:write")
		addScopedAPILink(links, auth.Scopes, "config", "/api/v1/config/revisions", "config:read")
		addScopedAPILink(links, auth.Scopes, "diagnostics", "/api/v1/diagnostics/proxy/recent", "diagnostics:read")
		addScopedAPILink(links, auth.Scopes, "logs", "/api/v1/logs/access/recent", "logs:read")
		addScopedAPILink(links, auth.Scopes, "system", "/api/v1/system", "system:read")
		addScopedAPILink(links, auth.Scopes, "saml_providers", "/api/v1/auth/saml/providers", "auth:read")
		response["links"] = links
	}
	writeJSON(w, http.StatusOK, response)
}

func addScopedAPILink(links map[string]string, scopes []string, name, path string, requiredScopes ...string) {
	if hasRequiredScope(scopes, requiredScopes) {
		links[name] = path
	}
}
