package accesslog

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	FormatPrivacy  = "privacy"
	FormatCommon   = "common"
	FormatCombined = "combined"
	FormatJSON     = "json"
)

type Metadata struct {
	RequestID      string
	Route          string
	TargetHost     string
	ResourceID     string
	RuleHost       string
	RuleMatch      string
	Decision       string
	DenialReason   string
	UpstreamStatus int
	Recovered      bool
}

type Logger struct {
	format string
	out    io.Writer
	mu     sync.Mutex
	recent []Entry
}

type Entry struct {
	TS             string `json:"ts"`
	RequestID      string `json:"request_id"`
	RemoteIP       string `json:"remote_ip"`
	Method         string `json:"method"`
	Route          string `json:"route"`
	Status         int    `json:"status"`
	Bytes          int    `json:"bytes"`
	DurationMS     int64  `json:"duration_ms"`
	UserAgent      string `json:"user_agent,omitempty"`
	Referer        string `json:"referer,omitempty"`
	TargetHost     string `json:"target_host,omitempty"`
	ResourceID     string `json:"resource_id,omitempty"`
	RuleHost       string `json:"rule_host,omitempty"`
	RuleMatch      string `json:"rule_match,omitempty"`
	Decision       string `json:"decision,omitempty"`
	DenialReason   string `json:"denial_reason,omitempty"`
	UpstreamStatus int    `json:"upstream_status,omitempty"`
	Recovered      bool   `json:"recovered_from_referer,omitempty"`
}

type contextKey struct{}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

func New(format string, out io.Writer) (*Logger, error) {
	normalized, err := NormalizeFormat(format)
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = os.Stdout
	}
	return &Logger{format: normalized, out: out}, nil
}

func Open(format, path string) (*Logger, io.Closer, error) {
	out := io.Writer(os.Stdout)
	closer := io.Closer(nopCloser{})
	if path != "" {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, nil, err
		}
		out = file
		closer = file
	}
	logger, err := New(format, out)
	if err != nil {
		_ = closer.Close()
		return nil, nil, err
	}
	return logger, closer, nil
}

func NormalizeFormat(format string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", FormatPrivacy:
		return FormatPrivacy, nil
	case FormatCommon:
		return FormatCommon, nil
	case FormatCombined:
		return FormatCombined, nil
	case FormatJSON:
		return FormatJSON, nil
	default:
		return "", fmt.Errorf("unsupported access log format %q", format)
	}
}

func WithMetadata(ctx context.Context) (context.Context, *Metadata) {
	metadata := &Metadata{}
	return context.WithValue(ctx, contextKey{}, metadata), metadata
}

func MetadataFrom(ctx context.Context) *Metadata {
	metadata, _ := ctx.Value(contextKey{}).(*Metadata)
	return metadata
}

func RequestID(r *http.Request) string {
	for _, name := range []string{"X-Request-ID", "X-Request-Id", "Request-ID"} {
		if value := strings.TrimSpace(r.Header.Get(name)); value != "" {
			return value
		}
	}
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return "req_" + strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return "req_" + hex.EncodeToString(buf)
}

func (l *Logger) Log(r *http.Request, status, bytes int, duration time.Duration) {
	if l == nil {
		return
	}
	metadata := MetadataFrom(r.Context())
	if metadata == nil {
		metadata = &Metadata{}
	}
	if metadata.RequestID == "" {
		metadata.RequestID = RequestID(r)
	}

	e := Entry{
		TS:             time.Now().UTC().Format(time.RFC3339),
		RequestID:      metadata.RequestID,
		RemoteIP:       remoteIP(r.RemoteAddr),
		Method:         r.Method,
		Route:          metadataRoute(metadata.Route, r.URL.Path),
		Status:         status,
		Bytes:          bytes,
		DurationMS:     duration.Milliseconds(),
		TargetHost:     metadata.TargetHost,
		ResourceID:     metadata.ResourceID,
		RuleHost:       metadata.RuleHost,
		RuleMatch:      metadata.RuleMatch,
		Decision:       metadata.Decision,
		DenialReason:   metadata.DenialReason,
		UpstreamStatus: metadata.UpstreamStatus,
		Recovered:      metadata.Recovered,
	}
	if l.format == FormatCombined || l.format == FormatJSON {
		e.UserAgent = r.UserAgent()
		e.Referer = r.Referer()
	}

	var line string
	switch l.format {
	case FormatCommon:
		line = commonLine(e, r, false)
	case FormatCombined:
		line = commonLine(e, r, true)
	case FormatJSON:
		payload, err := json.Marshal(e)
		if err != nil {
			return
		}
		line = string(payload)
	default:
		line = privacyLine(e)
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	l.recent = append(l.recent, e)
	if overflow := len(l.recent) - 200; overflow > 0 {
		copy(l.recent, l.recent[overflow:])
		l.recent = l.recent[:200]
	}
	_, _ = fmt.Fprintln(l.out, line)
}

func (l *Logger) Recent() []Entry {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	entries := make([]Entry, len(l.recent))
	copy(entries, l.recent)
	for i := range entries {
		entries[i].UserAgent = ""
		entries[i].Referer = ""
	}
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}
	return entries
}

func privacyLine(e Entry) string {
	parts := []string{
		"ts=" + e.TS,
		"request_id=" + e.RequestID,
		"remote_ip=" + e.RemoteIP,
		"method=" + e.Method,
		"route=" + e.Route,
		"status=" + strconv.Itoa(e.Status),
		"bytes=" + strconv.Itoa(e.Bytes),
		"duration_ms=" + strconv.FormatInt(e.DurationMS, 10),
	}
	parts = appendIf(parts, "target_host", e.TargetHost)
	parts = appendIf(parts, "resource_id", e.ResourceID)
	parts = appendIf(parts, "rule_host", e.RuleHost)
	parts = appendIf(parts, "rule_match", e.RuleMatch)
	parts = appendIf(parts, "decision", e.Decision)
	parts = appendIf(parts, "denial_reason", e.DenialReason)
	if e.Recovered {
		parts = append(parts, "recovered_from_referer=true")
	}
	if e.UpstreamStatus != 0 {
		parts = append(parts, "upstream_status="+strconv.Itoa(e.UpstreamStatus))
	}
	return strings.Join(parts, " ")
}

func appendIf(parts []string, key, value string) []string {
	if value == "" {
		return parts
	}
	if strings.ContainsAny(value, " \t\n\"") {
		value = strconv.Quote(value)
	}
	return append(parts, key+"="+value)
}

func commonLine(e Entry, r *http.Request, combined bool) string {
	line := fmt.Sprintf(
		`%s - - [%s] "%s %s %s" %d %d`,
		e.RemoteIP,
		time.Now().Format("02/Jan/2006:15:04:05 -0700"),
		r.Method,
		e.Route,
		r.Proto,
		e.Status,
		e.Bytes,
	)
	if combined {
		line += fmt.Sprintf(` "%s" "%s"`, dash(e.Referer), dash(e.UserAgent))
	}
	return line + " request_id=" + e.RequestID
}

func dash(value string) string {
	if value == "" {
		return "-"
	}
	return strings.ReplaceAll(value, `"`, `'`)
}

func remoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}
	return remoteAddr
}

func routePath(path string) string {
	if path == "/odo" || strings.HasPrefix(path, "/odo/") {
		return "/odo"
	}
	return path
}

func metadataRoute(route, path string) string {
	if route != "" {
		return route
	}
	return routePath(path)
}
