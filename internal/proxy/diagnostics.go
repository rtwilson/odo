package proxy

import (
	"context"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Diagnostics struct {
	RedirectTargetHost            string `json:"redirect_target_host,omitempty"`
	RedirectBlockReason           string `json:"redirect_block_reason,omitempty"`
	FrameDestination              string `json:"frame_destination,omitempty"`
	UpstreamXFrameOptionsPresent  bool   `json:"upstream_x_frame_options_present,omitempty"`
	UpstreamFrameAncestorsPresent bool   `json:"upstream_frame_ancestors_present,omitempty"`
	XFrameOptionsRemoved          bool   `json:"x_frame_options_removed,omitempty"`
	FrameAncestorsRemoved         bool   `json:"frame_ancestors_removed,omitempty"`
	PathKind                      string `json:"path_kind,omitempty"`
	ContentEncodingPresent        bool   `json:"content_encoding_present,omitempty"`
	ContentLengthStripped         bool   `json:"content_length_stripped,omitempty"`
	ReferringIntegrity            string `json:"referring_integrity,omitempty"`
	ContentDisposition            string `json:"content_disposition,omitempty"`
	AcceptRanges                  string `json:"accept_ranges,omitempty"`
	ContentRangePresent           bool   `json:"content_range_present,omitempty"`
	RangeRequested                bool   `json:"range_requested,omitempty"`
	PartialContent                bool   `json:"partial_content,omitempty"`
	ContentTypeMissing            bool   `json:"content_type_missing,omitempty"`
	ContentTypeCorrected          bool   `json:"content_type_corrected,omitempty"`
	DeliveryHeadersPreserved      bool   `json:"delivery_headers_preserved,omitempty"`
	RemovedCSPMetaCount           int    `json:"removed_csp_meta_count,omitempty"`
	Header                        string `json:"header,omitempty"`
	Action                        string `json:"action,omitempty"`
	ContentType                   string `json:"content_type,omitempty"`
	UpstreamCSPPresent            bool   `json:"upstream_csp_present"`
	UpstreamCSPReportOnlyPresent  bool   `json:"upstream_csp_report_only_present"`
	CSPRemoved                    bool   `json:"csp_removed"`
	ChallengePathRequested        bool   `json:"challenge_path_requested"`
	Type                          string `json:"type,omitempty"`
	Reason                        string `json:"reason,omitempty"`
	TS                            string `json:"ts"`
	Method                        string `json:"method,omitempty"`
	TargetHost                    string `json:"target_host,omitempty"`
	ResourceID                    string `json:"resource_id,omitempty"`
	MatchedDomain                 string `json:"matched_domain,omitempty"`
	DomainBehavior                string `json:"domain_behavior,omitempty"`
	DomainRole                    string `json:"domain_role,omitempty"`
	ProxyURLMode                  string `json:"proxy_url_mode,omitempty"`
	UpstreamStatus                int    `json:"upstream_status,omitempty"`
	MethodAllowed                 bool   `json:"method_allowed,omitempty"`
	HeaderRulesApplied            int    `json:"header_rules_applied,omitempty"`
	ContentRewriteRulesApplied    int    `json:"content_rewrite_rules_applied,omitempty"`
	AnonymousRuleMatched          bool   `json:"anonymous_rule_matched,omitempty"`
	AnonymousRulePattern          string `json:"anonymous_rule_pattern,omitempty"`
	JavaScriptTextRewriteEnabled  bool   `json:"javascript_text_rewrite_enabled,omitempty"`
	RequestBodyLimited            bool   `json:"request_body_limited,omitempty"`
	ProxiedPostCount              int    `json:"proxied_post_count,omitempty"`
	RedirectedAfterPost           bool   `json:"redirected_after_post,omitempty"`
	JSShimInjected                bool   `json:"js_shim_injected"`
	JSFetchShimEnabled            bool   `json:"js_fetch_shim_enabled"`
	JSXHRShimEnabled              bool   `json:"js_xhr_shim_enabled"`
	RewrittenNavigationCount      int    `json:"rewritten_navigation_count"`
	RewrittenAssetCount           int    `json:"rewritten_asset_count"`
	RewrittenFormCount            int    `json:"rewritten_form_count"`
	RewrittenRedirectCount        int    `json:"rewritten_redirect_count"`
	NonProxyableAllowedCount      int    `json:"non_proxyable_allowed_count"`
	BlockedURLCount               int    `json:"blocked_url_count"`
	RemovedIntegrityCount         int    `json:"removed_integrity_count"`
}

func hasFrameAncestors(headers http.Header) bool {
	for _, name := range []string{"Content-Security-Policy", "Content-Security-Policy-Report-Only"} {
		for _, policy := range headers.Values(name) {
			// Commas separate multiple policies combined in one header field.
			for _, directive := range strings.FieldsFunc(policy, func(r rune) bool { return r == ';' || r == ',' }) {
				fields := strings.Fields(directive)
				if len(fields) > 0 && strings.EqualFold(fields[0], "frame-ancestors") {
					return true
				}
			}
		}
	}
	return false
}

func recordFrameContent(store *DiagnosticsStore, diagnostic *Diagnostics, request *http.Request, upstream, delivered http.Header) {
	destination := FrameDestination(request)
	xfo := len(upstream.Values("X-Frame-Options")) > 0
	ancestors := hasFrameAncestors(upstream)
	if destination == "" && !xfo && !ancestors {
		return
	}
	event := Diagnostics{
		Type: "proxy_frame_content", TS: diagnostic.TS, TargetHost: diagnostic.TargetHost,
		FrameDestination: destination, UpstreamStatus: diagnostic.UpstreamStatus,
		ContentType:                  diagnosticContentType(delivered.Get("Content-Type")),
		UpstreamXFrameOptionsPresent: xfo, UpstreamFrameAncestorsPresent: ancestors,
		XFrameOptionsRemoved:  xfo && len(delivered.Values("X-Frame-Options")) == 0,
		FrameAncestorsRemoved: ancestors && !hasFrameAncestors(delivered),
	}
	if event.XFrameOptionsRemoved || event.FrameAncestorsRemoved {
		event.Action = "removed_for_proxy_compatibility"
	}
	store.Add(event)
}

// Report categories, never arbitrary upstream MIME tokens or their parameters.
func diagnosticContentType(value string) string {
	mediaType, _, _ := strings.Cut(value, ";")
	switch mediaType = strings.ToLower(strings.TrimSpace(mediaType)); mediaType {
	case "application/x-javascript", "application/pdf", "text/html", "application/xhtml+xml", "text/css", "text/javascript", "application/javascript", "application/json", "text/plain", "application/octet-stream", "font/woff", "font/woff2", "image/png", "image/jpeg", "image/svg+xml":
		return mediaType
	case "":
		return "missing"
	default:
		return "other"
	}
}

func scriptPathKind(path string) string {
	path = strings.ToLower(path)
	for _, extension := range []string{".js", ".mjs"} {
		if strings.HasSuffix(path, extension) {
			return extension
		}
	}
	return "other"
}

func recordScriptAsset(store *DiagnosticsStore, diagnostic *Diagnostics, path string, upstream, delivered http.Header) {
	store.Add(Diagnostics{
		Type: "proxy_script_asset", TS: diagnostic.TS, TargetHost: diagnostic.TargetHost,
		PathKind: scriptPathKind(path), UpstreamStatus: diagnostic.UpstreamStatus,
		ContentType:                  diagnosticContentType(delivered.Get("Content-Type")),
		ContentTypeMissing:           upstream.Get("Content-Type") == "",
		ContentTypeCorrected:         upstream.Get("Content-Type") != delivered.Get("Content-Type"),
		ContentEncodingPresent:       len(upstream.Values("Content-Encoding")) > 0,
		ContentLengthStripped:        len(upstream.Values("Content-Length")) > 0 && len(delivered.Values("Content-Length")) == 0,
		UpstreamCSPPresent:           diagnostic.UpstreamCSPPresent,
		UpstreamCSPReportOnlyPresent: diagnostic.UpstreamCSPReportOnlyPresent,
		CSPRemoved:                   diagnostic.CSPRemoved, ReferringIntegrity: "unknown",
	})
}

// Only fixed labels and header presence enter PDF events. In particular,
// Content-Disposition filenames and arbitrary Content-Range values stay private.
func recordPDFResponse(store *DiagnosticsStore, diagnostic *Diagnostics, request *http.Request, upstream, delivered http.Header) {
	disposition := "missing"
	if value := upstream.Get("Content-Disposition"); value != "" {
		kind, _, err := mime.ParseMediaType(value)
		disposition = "other"
		if err == nil && (kind == "inline" || kind == "attachment") {
			disposition = kind
		}
	}
	acceptRanges := "missing"
	if value := upstream.Get("Accept-Ranges"); value != "" {
		acceptRanges = "other"
		if strings.EqualFold(strings.TrimSpace(value), "bytes") {
			acceptRanges = "bytes"
		} else if strings.EqualFold(strings.TrimSpace(value), "none") {
			acceptRanges = "none"
		}
	}
	preserved := true
	for _, name := range []string{"Content-Disposition", "Accept-Ranges", "Content-Range", "Content-Length", "Content-Encoding", "ETag", "Last-Modified", "Cache-Control"} {
		if strings.Join(upstream.Values(name), "\n") != strings.Join(delivered.Values(name), "\n") {
			preserved = false
		}
	}
	store.Add(Diagnostics{
		Type: "proxy_pdf_response", TS: diagnostic.TS, TargetHost: diagnostic.TargetHost,
		UpstreamStatus: diagnostic.UpstreamStatus, ContentType: diagnosticContentType(delivered.Get("Content-Type")),
		ContentDisposition: disposition, AcceptRanges: acceptRanges,
		ContentRangePresent:      len(upstream.Values("Content-Range")) > 0,
		RangeRequested:           len(request.Header.Values("Range")) > 0,
		PartialContent:           diagnostic.UpstreamStatus == http.StatusPartialContent,
		ContentTypeMissing:       upstream.Get("Content-Type") == "",
		ContentTypeCorrected:     upstream.Get("Content-Type") != delivered.Get("Content-Type"),
		DeliveryHeadersPreserved: preserved,
	})
}

// The proxy allowlist suppresses both CSP headers for all response types.
// Construct fresh events so rewrite patterns and other request-derived fields
// from the aggregate diagnostic cannot enter response-header events.
func recordResponsePolicy(store *DiagnosticsStore, diagnostic *Diagnostics, headers http.Header) {
	diagnostic.ContentType = diagnosticContentType(headers.Get("Content-Type"))
	diagnostic.UpstreamCSPPresent = len(headers.Values("Content-Security-Policy")) > 0
	diagnostic.UpstreamCSPReportOnlyPresent = len(headers.Values("Content-Security-Policy-Report-Only")) > 0
	diagnostic.CSPRemoved = diagnostic.UpstreamCSPPresent || diagnostic.UpstreamCSPReportOnlyPresent
	for _, name := range []string{"Content-Security-Policy", "Content-Security-Policy-Report-Only"} {
		if len(headers.Values(name)) == 0 {
			continue
		}
		store.Add(Diagnostics{
			Type: "response_header_modified", Header: name, Action: "removed_for_proxy_compatibility",
			TS: diagnostic.TS, TargetHost: diagnostic.TargetHost, ResourceID: diagnostic.ResourceID,
			ContentType: diagnostic.ContentType, UpstreamCSPPresent: diagnostic.UpstreamCSPPresent,
			UpstreamCSPReportOnlyPresent: diagnostic.UpstreamCSPReportOnlyPresent,
			CSPRemoved:                   true, ChallengePathRequested: diagnostic.ChallengePathRequested,
		})
	}
}

type DiagnosticsStore struct {
	mu      sync.Mutex
	entries []Diagnostics
	limit   int
}

type diagnosticsContextKey struct{}

func NewDiagnosticsStore(limit int) *DiagnosticsStore {
	if limit <= 0 {
		limit = 200
	}
	return &DiagnosticsStore{limit: limit}
}

func WithDiagnostics(ctx context.Context) (context.Context, *Diagnostics) {
	diagnostics := &Diagnostics{TS: time.Now().UTC().Format(time.RFC3339)}
	return context.WithValue(ctx, diagnosticsContextKey{}, diagnostics), diagnostics
}

func DiagnosticsFrom(ctx context.Context) *Diagnostics {
	diagnostics, _ := ctx.Value(diagnosticsContextKey{}).(*Diagnostics)
	return diagnostics
}

func (s *DiagnosticsStore) Add(diagnostics Diagnostics) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, diagnostics)
	if overflow := len(s.entries) - s.limit; overflow > 0 {
		copy(s.entries, s.entries[overflow:])
		s.entries = s.entries[:s.limit]
	}
}

func (s *DiagnosticsStore) Recent() []Diagnostics {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entries := make([]Diagnostics, len(s.entries))
	copy(entries, s.entries)
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}
	return entries
}
