package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"example.org/odo/internal/accesslog"
	"example.org/odo/internal/auth/local"
)

// browse /resources as the fixture patron so a pseudonymous line is logged.
func patronVisit(t *testing.T, server *Server, cookie *http.Cookie) accesslog.Entry {
	t.Helper()
	req := httptest.NewRequest("GET", "/resources", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("patron visit: %d", rec.Code)
	}
	entry := server.accessLog.Recent()[0]
	if entry.PatronKey == "" {
		t.Fatal("patron visit was not pseudonymously keyed")
	}
	return entry
}

func TestLogPseudonymPolicySettingsAPI(t *testing.T) {
	server, control, cookie, _ := newLogoutTestServer(t, false)
	reader, _ := createTestAPIKey(t, server, "secret", []string{"logs:read"})
	writer, _ := createTestAPIKey(t, server, "secret", []string{"users:write", "logs:read", "system:read"})
	path := "/api/v1/settings/log-pseudonymization"

	rec := userLifecycleRequest(server, "GET", path, "", reader, nil, "")
	var got struct {
		Current accesslog.RotationPolicy   `json:"current"`
		History []accesslog.RotationPolicy `json:"history"`
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &got) != nil || got.Current.Mode != "time" || got.Current.Unit != "month" || got.Current.Count != 1 {
		t.Fatalf("default policy: %d %s", rec.Code, rec.Body.String())
	}
	monthly := patronVisit(t, server, cookie)

	for _, tc := range []struct {
		token, body string
		want        int
	}{
		{"", `{"mode":"never","reason":"incident investigation"}`, 401},
		{writer, `{"mode":"never","reason":"incident investigation"}`, 403},
		{"secret", `{"mode":"never"}`, 400},
		{"secret", `{"mode":"hourly","reason":"incident investigation"}`, 400},
		{"secret", `{"mode":"time","unit":"month","count":25,"reason":"incident investigation"}`, 400},
		{"secret", `{"mode":"never","reason":"incident investigation","extra":1}`, 400},
	} {
		if rec := userLifecycleRequest(server, "PUT", path, tc.body, tc.token, nil, ""); rec.Code != tc.want {
			t.Fatalf("PUT %s: got %d want %d: %s", tc.body, rec.Code, tc.want, rec.Body.String())
		}
	}
	if current, _ := server.store.CurrentLogPseudonymPolicy(); current.Mode != "time" {
		t.Fatal("refused change was stored")
	}

	rec = userLifecycleRequest(server, "PUT", path, `{"mode":"time","unit":"day","count":7,"reason":"shorter linkage window per policy review"}`, "secret", nil, "")
	if rec.Code != 200 {
		t.Fatalf("valid change: %d %s", rec.Code, rec.Body.String())
	}
	if p := server.accessLog.Pseudonymizer().Policy(); p.Unit != "day" || p.Count != 7 {
		t.Fatalf("change not applied to new lines: %+v", p)
	}
	if next := patronVisit(t, server, cookie); next.PatronKey == monthly.PatronKey {
		t.Fatal("new lines still use the old policy's key")
	}
	rec = userLifecycleRequest(server, "GET", path, "", reader, nil, "")
	if json.Unmarshal(rec.Body.Bytes(), &got) != nil || len(got.History) != 2 || got.Current.Unit != "day" {
		t.Fatalf("history: %s", rec.Body.String())
	}
	var audits int
	if err := control.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event = 'log_pseudonym_policy_changed' AND detail LIKE '%shorter linkage window%'`).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("policy change audit: %d %v", audits, err)
	}
	// History is append-only, so re-identification can always reconstruct it.
	for _, statement := range []string{`UPDATE log_pseudonym_policies SET mode = 'never'`, `DELETE FROM log_pseudonym_policies`} {
		if _, err := control.Exec(statement); err == nil {
			t.Fatalf("policy history allowed %q", statement)
		}
	}
}

func TestReidentifyPatronAcrossPolicyChanges(t *testing.T) {
	server, control, cookie, _ := newLogoutTestServer(t, false)
	investigator, _ := createTestAPIKey(t, server, "secret", []string{"logs:reidentify"})
	path := "/api/v1/logs/access/reidentify"
	today := time.Now().UTC().Format("2006-01-02")
	body := func(username, from, to, reason string) string {
		payload, _ := json.Marshal(map[string]string{"username": username, "from": from, "to": to, "reason": reason})
		return string(payload)
	}

	monthly := patronVisit(t, server, cookie)
	if rec := userLifecycleRequest(server, "PUT", "/api/v1/settings/log-pseudonymization", `{"mode":"session","reason":"per-session keys for this term"}`, "secret", nil, ""); rec.Code != 200 {
		t.Fatalf("policy change: %d", rec.Code)
	}
	perSession := patronVisit(t, server, cookie)
	if rec := userLifecycleRequest(server, "PUT", "/api/v1/settings/log-pseudonymization", `{"mode":"never","reason":"stable keys during bot investigation"}`, "secret", nil, ""); rec.Code != 200 {
		t.Fatalf("policy change: %d", rec.Code)
	}
	stable := patronVisit(t, server, cookie)
	if monthly.PatronKey == perSession.PatronKey || perSession.PatronKey == stable.PatronKey {
		t.Fatal("policies produced the same key")
	}

	for _, tc := range []struct {
		token, body string
		want        int
	}{
		{"", body("alice", today, today, "suspected credential sharing"), 401},
		// admin alone is not enough: the scope must be granted explicitly.
		{"secret", body("alice", today, today, "suspected credential sharing"), 403},
		{investigator, body("alice", today, today, "short"), 400},
		{investigator, body("alice", "2026-13-01", today, "suspected credential sharing"), 400},
		{investigator, body("alice", "2020-01-01", "2026-01-01", "suspected credential sharing"), 400},
		{investigator, body("nobody", today, today, "suspected credential sharing"), 404},
	} {
		if rec := userLifecycleRequest(server, "POST", path, tc.body, tc.token, nil, ""); rec.Code != tc.want {
			t.Fatalf("got %d want %d: %s", rec.Code, tc.want, rec.Body.String())
		}
	}

	rec := userLifecycleRequest(server, "POST", path, body("alice", today, today, "suspected credential sharing"), investigator, nil, "")
	var result struct {
		UserID string `json:"user_id"`
		Keys   []struct {
			PatronKey string `json:"patron_key"`
			Mode      string `json:"mode"`
		} `json:"keys"`
		RecentEntries []accesslog.Entry `json:"recent_entries"`
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &result) != nil {
		t.Fatalf("reidentify: %d %s", rec.Code, rec.Body.String())
	}
	keys := map[string]string{}
	for _, key := range result.Keys {
		keys[key.PatronKey] = key.Mode
	}
	if keys[monthly.PatronKey] != "time" || keys[perSession.PatronKey] != "session" || keys[stable.PatronKey] != "never" {
		t.Fatalf("keys under each policy not derived: %v", keys)
	}
	if len(result.RecentEntries) != 3 {
		t.Fatalf("recent entries: %d", len(result.RecentEntries))
	}
	var audits int
	if err := control.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event = 'patron_log_reidentified' AND detail LIKE '%suspected credential sharing%' AND detail LIKE ?`, "%"+result.UserID+"%").Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("reidentification audit: %d %v", audits, err)
	}
	// Another patron's lines never match.
	other := createLocalTestUser(t, server, "bob", "correct horse battery")
	otherToken, otherSession, _ := server.newBrowserSession(other.ID, httptest.NewRequest("POST", "/login", nil))
	if err := server.store.CreateSession(otherSession); err != nil {
		t.Fatal(err)
	}
	if bob := patronVisit(t, server, server.sessionCookie(httptest.NewRequest("GET", "/", nil), otherToken, otherSession.ExpiresAt)); keys[bob.PatronKey] != "" {
		t.Fatal("another patron's key matched")
	}
	if strings.Contains(rec.Body.String(), local.SessionIDFromToken(cookie.Value)) {
		t.Fatal("response disclosed a raw session identifier")
	}
}
