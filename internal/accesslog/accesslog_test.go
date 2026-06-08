package accesslog

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDefaultFormatIsPrivacy(t *testing.T) {
	var out bytes.Buffer
	logger, err := New("", &out)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	req := requestWithMetadata(t, "GET", "/odo?url=https://www.jstor.org/stable/example")
	logger.Log(req, http.StatusOK, 123, 2*time.Millisecond)

	line := out.String()
	if !strings.Contains(line, "method=GET") || !strings.Contains(line, "route=/odo") {
		t.Fatalf("expected privacy key/value line, got %q", line)
	}
	if strings.Contains(line, "https://www.jstor.org/stable/example") || strings.Contains(line, "?url=") {
		t.Fatalf("privacy log leaked full target URL: %q", line)
	}
}

func TestJSONFormatEmitsValidJSON(t *testing.T) {
	var out bytes.Buffer
	logger, err := New(FormatJSON, &out)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	req := requestWithMetadata(t, "GET", "/api/v1/health")
	req.Header.Set("User-Agent", "odo-test")
	logger.Log(req, http.StatusOK, 42, time.Millisecond)

	var payload map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &payload); err != nil {
		t.Fatalf("expected valid JSON log, got %q: %v", out.String(), err)
	}
	if payload["method"] != "GET" || payload["route"] != "/api/v1/health" || payload["status"].(float64) != 200 {
		t.Fatalf("unexpected JSON log payload: %#v", payload)
	}
}

func TestCommonFormatIncludesMethodPathStatus(t *testing.T) {
	var out bytes.Buffer
	logger, err := New(FormatCommon, &out)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	req := requestWithMetadata(t, "GET", "/api/v1/health?token=secret")
	logger.Log(req, http.StatusOK, 12, time.Millisecond)

	line := out.String()
	if !strings.Contains(line, `"GET /api/v1/health HTTP/1.1" 200 12`) {
		t.Fatalf("expected common log method/path/status, got %q", line)
	}
	if strings.Contains(line, "token=secret") {
		t.Fatalf("common log leaked query string: %q", line)
	}
}

func requestWithMetadata(t *testing.T, method, target string) *http.Request {
	t.Helper()

	req := httptest.NewRequest(method, target, nil)
	ctx, metadata := WithMetadata(req.Context())
	metadata.RequestID = "req_test"
	return req.WithContext(ctx)
}
