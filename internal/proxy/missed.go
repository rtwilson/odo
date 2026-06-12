package proxy

import (
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"
)

const (
	RequestKindDocument = "document"
	RequestKindAsset    = "asset"
	RequestKindAPI      = "api"
	RequestKindAppData  = "app_data"
	RequestKindUnknown  = "unknown"

	RecoveryActionRedirectedToCanonical = "redirected_to_canonical"
	RecoveryActionSilentlyProxied       = "silently_proxied"
	RecoveryActionDenied                = "denied"
	RecoveryActionNotRecovered          = "not_recovered"
)

type MissedRewriteEvent struct {
	TS                  string `json:"ts"`
	Method              string `json:"method"`
	Path                string `json:"path"`
	RequestKind         string `json:"request_kind,omitempty"`
	RecoveryAction      string `json:"recovery_action,omitempty"`
	AcceptHeaderSummary string `json:"accept_header_summary,omitempty"`
	SecFetchDest        string `json:"sec_fetch_dest,omitempty"`
	SecFetchMode        string `json:"sec_fetch_mode,omitempty"`
	CanonicalProxyPath  string `json:"canonical_proxy_path,omitempty"`
	RefererRoute        string `json:"referer_route,omitempty"`
	Recovered           bool   `json:"recovered"`
	RecoveredTargetHost string `json:"recovered_target_host,omitempty"`
	RecoveredPathPrefix string `json:"recovered_path_prefix,omitempty"`
	ContentType         string `json:"content_type,omitempty"`
	UpstreamStatus      int    `json:"upstream_status,omitempty"`
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
		path == "/api/v1" ||
		strings.HasPrefix(path, "/api/v1/")
}

func MissedRewriteRequestKind(r *http.Request) string {
	if r == nil || r.URL == nil {
		return RequestKindUnknown
	}
	if IsDocumentNavigation(r) {
		return RequestKindDocument
	}
	if IsAPIRequest(r) {
		return RequestKindAPI
	}
	if LooksLikeStaticAssetPath(r.URL.Path) {
		return RequestKindAsset
	}
	if IsAppDataRequest(r) {
		return RequestKindAppData
	}
	if strings.Contains(strings.ToLower(r.Header.Get("Accept")), "application/json") {
		return RequestKindAPI
	}
	return RequestKindUnknown
}

func IsDocumentNavigation(r *http.Request) bool {
	if r == nil || r.URL == nil || r.Method != http.MethodGet || LooksLikeStaticAssetPath(r.URL.Path) {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Dest")), "document") {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Mode")), "navigate") {
		return true
	}
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html")
}

func LooksLikeStaticAssetPath(rawPath string) bool {
	switch strings.ToLower(path.Ext(rawPath)) {
	case ".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".otf", ".map":
		return true
	default:
		return false
	}
}

func IsAPIRequest(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	p := strings.ToLower(r.URL.Path)
	if strings.HasPrefix(p, "/api/") || strings.Contains(p, "/api/") || strings.Contains(p, "/graphql") {
		return true
	}
	return false
}

func IsAppDataRequest(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	p := strings.ToLower(r.URL.Path)
	if strings.HasSuffix(p, ".json") ||
		strings.Contains(p, "/_next/") ||
		strings.Contains(p, "/manifest") ||
		strings.Contains(p, "/mfe-") ||
		strings.Contains(p, "/remoteentry.js") ||
		strings.Contains(p, "/static/") ||
		strings.Contains(p, "/assets/") {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Dest"))) {
	case "script", "style", "empty", "manifest", "worker":
		return true
	default:
		return false
	}
}

func AcceptHeaderSummary(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	parts := strings.Split(value, ",")
	summary := strings.TrimSpace(parts[0])
	if len(summary) > 80 {
		summary = summary[:80]
	}
	return summary
}

func CanonicalProxyPathWithoutQuery(target *url.URL) string {
	if target == nil {
		return ""
	}
	clone := *target
	clone.RawQuery = ""
	clone.ForceQuery = false
	clone.Fragment = ""
	return BuildProxyURL(&clone)
}

func SafePathPrefix(rawPath string) string {
	rawPath = strings.TrimSpace(rawPath)
	if rawPath == "" || rawPath == "/" {
		return "/"
	}
	segments := strings.Split(strings.Trim(rawPath, "/"), "/")
	if len(segments) > 2 {
		segments = segments[:2]
	}
	return "/" + strings.Join(segments, "/")
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
	base, _, ok, err := ParseProxyRequest(proxyReq)
	if err != nil {
		return nil, "", errMissedRewrite("referer is not proxied")
	}
	if !ok {
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
