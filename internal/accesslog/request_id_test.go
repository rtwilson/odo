package accesslog

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestIDValidationAndReuse(t *testing.T) {
	for _, tc := range []struct {
		name   string
		values []string
		valid  bool
	}{
		{"X-Request-ID", []string{"abc_123-Z"}, true},
		{"Request-ID", []string{strings.Repeat("a", 64)}, true},
		{"X-Request-ID", []string{strings.Repeat("a", 65)}, false},
		{"X-Request-ID", []string{"a\nb"}, false},
		{"X-Request-ID", []string{"a\rb"}, false},
		{"X-Request-ID", []string{"a b"}, false},
		{"X-Request-ID", []string{"<script>"}, false},
		{"X-Request-ID", []string{"café"}, false},
		{"X-Request-ID", []string{"abc", "def"}, false},
		{"X-Request-ID", nil, false},
	} {
		t.Run(tc.name+strings.Join(tc.values, ","), func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			for _, value := range tc.values {
				r.Header.Add(tc.name, value)
			}
			ctx, _ := WithMetadata(r.Context())
			r = r.WithContext(ctx)
			got := RequestID(r)
			if !validRequestID(got) {
				t.Fatalf("invalid output ID: %q", got)
			}
			if tc.valid && got != tc.values[0] {
				t.Fatalf("safe ID not reused: %q", got)
			}
			if !tc.valid && !strings.HasPrefix(got, "req_") {
				t.Fatalf("unsafe ID reused: %q", got)
			}
			// Once assigned, downstream requests retain the same ID.
			r.Header.Set("X-Request-ID", "replacement")
			if RequestID(r) != got {
				t.Fatal("request ID changed within a request")
			}
		})
	}
}
