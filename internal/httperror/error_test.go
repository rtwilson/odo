package httperror

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestServerErrorPreservesCauseWithoutRequestData(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	r := httptest.NewRequest("GET", "/api/v1/resources/private-id?search=private-search", strings.NewReader("private-body"))
	r.Pattern = "GET /api/v1/resources/{id}"
	r.Header.Set("Authorization", "Bearer private-token")
	r.Header.Set("Cookie", "private-cookie")
	r.Header.Set("X-Request-ID", "<bad-id>")
	err := fmt.Errorf("wrapped operation: %w", errors.Join(
		errors.New("SQL driver failure at /private/database.db"),
		&url.Error{Op: "Get", URL: "https://user:private-password@vendor/search?term=private-search", Err: errors.New("upstream connection failed")},
	))
	rec := httptest.NewRecorder()
	Write(rec, r, logger, 500, err)
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	var event map[string]any
	if err := json.Unmarshal(logs.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	id := rec.Header().Get("X-Request-ID")
	if rec.Code != 500 || id == "" || body["request_id"] != id || event["request_id"] != id {
		t.Fatalf("response/log mismatch: %s %s", rec.Body.String(), logs.String())
	}
	for _, cause := range []string{"wrapped operation", "SQL driver failure", "/private/database.db", "upstream connection failed"} {
		if !strings.Contains(logs.String(), cause) || strings.Contains(rec.Body.String(), cause) {
			t.Errorf("cause must appear only in log: %q", cause)
		}
	}
	for _, secret := range []string{"private-id", "private-search", "private-body", "private-token", "private-cookie", "private-password", "<bad-id>", "https://"} {
		if strings.Contains(logs.String()+rec.Body.String(), secret) {
			t.Errorf("leaked %q", secret)
		}
	}
}
