package proxy

import (
	"context"
	"sync"
	"time"
)

type Diagnostics struct {
	Type                         string `json:"type,omitempty"`
	Reason                       string `json:"reason,omitempty"`
	TS                           string `json:"ts"`
	Method                       string `json:"method,omitempty"`
	TargetHost                   string `json:"target_host,omitempty"`
	ResourceID                   string `json:"resource_id,omitempty"`
	MatchedDomain                string `json:"matched_domain,omitempty"`
	DomainBehavior               string `json:"domain_behavior,omitempty"`
	DomainRole                   string `json:"domain_role,omitempty"`
	ProxyURLMode                 string `json:"proxy_url_mode,omitempty"`
	UpstreamStatus               int    `json:"upstream_status,omitempty"`
	MethodAllowed                bool   `json:"method_allowed,omitempty"`
	HeaderRulesApplied           int    `json:"header_rules_applied,omitempty"`
	ContentRewriteRulesApplied   int    `json:"content_rewrite_rules_applied,omitempty"`
	AnonymousRuleMatched         bool   `json:"anonymous_rule_matched,omitempty"`
	AnonymousRulePattern         string `json:"anonymous_rule_pattern,omitempty"`
	JavaScriptTextRewriteEnabled bool   `json:"javascript_text_rewrite_enabled,omitempty"`
	RequestBodyLimited           bool   `json:"request_body_limited,omitempty"`
	ProxiedPostCount             int    `json:"proxied_post_count,omitempty"`
	RedirectedAfterPost          bool   `json:"redirected_after_post,omitempty"`
	JSShimInjected               bool   `json:"js_shim_injected"`
	JSFetchShimEnabled           bool   `json:"js_fetch_shim_enabled"`
	JSXHRShimEnabled             bool   `json:"js_xhr_shim_enabled"`
	RewrittenNavigationCount     int    `json:"rewritten_navigation_count"`
	RewrittenAssetCount          int    `json:"rewritten_asset_count"`
	RewrittenFormCount           int    `json:"rewritten_form_count"`
	RewrittenRedirectCount       int    `json:"rewritten_redirect_count"`
	NonProxyableAllowedCount     int    `json:"non_proxyable_allowed_count"`
	BlockedURLCount              int    `json:"blocked_url_count"`
	RemovedIntegrityCount        int    `json:"removed_integrity_count"`
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
