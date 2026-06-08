package proxy

import (
	"encoding/json"
	"net/http"

	"example.org/odo/internal/resources"
)

func StubHandler(test func(string) resources.TestResult) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result := test(r.URL.Query().Get("url"))
		w.Header().Set("Content-Type", "application/json")
		if !result.Allowed {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"allowed": result.Allowed,
				"reason":  result.Reason,
			})
			return
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"allowed":     true,
			"resource_id": result.ResourceID,
			"matched_rule": result.Matched,
			"message":     "URL is allowed. Full upstream proxy fetch and rewrite are future work.",
		})
	}
}
