package proxy

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"example.org/odo/internal/accesslog"
	"example.org/odo/internal/resources"
)

func StubHandler(test func(string) resources.TestResult) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rawURL := r.URL.Query().Get("url")
		result := test(rawURL)
		setAccessLogMetadata(r, rawURL, result)
		w.Header().Set("Content-Type", "application/json")
		if !result.Allowed {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":   "target URL is not allowed",
				"allowed": result.Allowed,
				"reason":  result.Reason,
			})
			return
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"allowed":      true,
			"resource_id":  result.ResourceID,
			"matched_rule": result.Matched,
			"message":      "URL is allowed. Full upstream proxy fetch and rewrite are future work.",
		})
	}
}

func setAccessLogMetadata(r *http.Request, rawURL string, result resources.TestResult) {
	metadata := accesslog.MetadataFrom(r.Context())
	if metadata == nil {
		return
	}
	if parsed, err := url.Parse(strings.TrimSpace(rawURL)); err == nil {
		metadata.TargetHost = strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	}
	metadata.ResourceID = result.ResourceID
	if result.Allowed {
		metadata.Decision = "allowed"
	} else {
		metadata.Decision = "denied"
		metadata.DenialReason = result.Reason
	}
	if result.Matched != nil {
		metadata.RuleHost = result.Matched.Host
		metadata.RuleMatch = result.Matched.Match
	}
}
