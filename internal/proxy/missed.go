package proxy

import (
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type MissedRewriteEvent struct {
	TS                  string `json:"ts"`
	Method              string `json:"method"`
	Path                string `json:"path"`
	RefererRoute        string `json:"referer_route,omitempty"`
	Recovered           bool   `json:"recovered"`
	RecoveredTargetHost string `json:"recovered_target_host,omitempty"`
	Reason              string `json:"reason"`
}

type MissedRewriteStore struct {
	mu     sync.Mutex
	events []MissedRewriteEvent
	limit  int
}

func NewMissedRewriteStore(limit int) *MissedRewriteStore {
	if limit <= 0 {
		limit = 200
	}
	return &MissedRewriteStore{limit: limit}
}

func RefererRecoveryEnabled() bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv("APP_PROXY_REFERER_RECOVERY")))
	switch value {
	case "", "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	default:
		return true
	}
}

func (s *MissedRewriteStore) Add(event MissedRewriteEvent) {
	if s == nil {
		return
	}
	if event.TS == "" {
		event.TS = time.Now().UTC().Format(time.RFC3339)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	if overflow := len(s.events) - s.limit; overflow > 0 {
		copy(s.events, s.events[overflow:])
		s.events = s.events[:s.limit]
	}
}

func (s *MissedRewriteStore) Recent() []MissedRewriteEvent {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	events := make([]MissedRewriteEvent, len(s.events))
	copy(events, s.events)
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}
	return events
}

func ProtectedAppPath(path string) bool {
	return path == "/admin" ||
		strings.HasPrefix(path, "/admin/") ||
		path == "/openapi.yaml" ||
		path == "/odo" ||
		strings.HasPrefix(path, "/odo/") ||
		strings.HasPrefix(path, "/api/")
}

func RecoverTargetFromReferer(r *http.Request) (*url.URL, string, error) {
	referer := strings.TrimSpace(r.Header.Get("Referer"))
	if referer == "" {
		return nil, "", errMissedRewrite("missing proxied referer")
	}
	refURL, err := url.Parse(referer)
	if err != nil {
		return nil, "", errMissedRewrite("referer is invalid")
	}
	proxyReq := &http.Request{URL: refURL}
	base, err := ParseProxyRequest(proxyReq)
	if err != nil {
		return nil, "", errMissedRewrite("referer is not proxied")
	}
	target := &url.URL{
		Scheme:   "https",
		Host:     base.Host,
		Path:     r.URL.EscapedPath(),
		RawQuery: r.URL.RawQuery,
	}
	return target, PublicProxyPath, nil
}

type missedRewriteError string

func errMissedRewrite(reason string) error {
	return missedRewriteError(reason)
}

func (e missedRewriteError) Error() string {
	return string(e)
}
