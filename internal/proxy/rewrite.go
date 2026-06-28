package proxy

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"example.org/odo/internal/resources"
)

var (
	htmlURLAttrRE   = regexp.MustCompile(`(?i)\b(data-src|data-href|href|src|action|poster)\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)`)
	htmlSrcsetRE    = regexp.MustCompile(`(?i)\bsrcset\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)`)
	htmlStyleAttrRE = regexp.MustCompile(`(?i)\bstyle\s*=\s*("[^"]*"|'[^']*')`)
	htmlIntegrityRE = regexp.MustCompile(`(?i)\s+integrity\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)`)
	htmlFormTagRE   = regexp.MustCompile(`(?i)<form\b[^>]*>`)
	cssURLRE        = regexp.MustCompile(`(?i)url\(\s*("[^"]*"|'[^']*'|[^)]*)\s*\)`)
)

func RewriteHTML(ctx context.Context, body string, base *url.URL, check TargetCheck) string {
	original := body
	body = rewriteMissingFormActions(ctx, body, base, check)

	body = htmlURLAttrRE.ReplaceAllStringFunc(body, func(match string) string {
		name, rawValue, ok := splitAttr(match)
		if !ok {
			return match
		}
		rewritten := rewriteOneURL(ctx, unquoteAttr(rawValue), base, check, rewriteCategory(name))
		return name + "=" + quoteLike(rawValue, rewritten)
	})

	body = htmlSrcsetRE.ReplaceAllStringFunc(body, func(match string) string {
		name, rawValue, ok := splitAttr(match)
		if !ok {
			return match
		}
		rewritten := rewriteSrcset(ctx, unquoteAttr(rawValue), base, check)
		return name + "=" + quoteLike(rawValue, rewritten)
	})

	body = htmlStyleAttrRE.ReplaceAllStringFunc(body, func(match string) string {
		name, rawValue, ok := splitAttr(match)
		if !ok {
			return match
		}
		rewritten := RewriteCSS(ctx, unquoteAttr(rawValue), base, check)
		return name + "=" + quoteLike(rawValue, rewritten)
	})

	if body != original {
		removed := 0
		body = htmlIntegrityRE.ReplaceAllStringFunc(body, func(match string) string {
			removed++
			return ""
		})
		if diagnostics := DiagnosticsFrom(ctx); diagnostics != nil {
			diagnostics.RemovedIntegrityCount += removed
		}
	}

	return body
}

func rewriteMissingFormActions(ctx context.Context, body string, base *url.URL, check TargetCheck) string {
	return htmlFormTagRE.ReplaceAllStringFunc(body, func(tag string) string {
		if strings.Contains(strings.ToLower(tag), " action=") {
			return tag
		}
		rewritten := rewriteOneURL(ctx, base.String(), base, check, "form")
		if rewritten == base.String() {
			return tag
		}
		return strings.TrimSuffix(tag, ">") + ` action="` + rewritten + `">`
	})
}

func RewriteCSS(ctx context.Context, body string, base *url.URL, check TargetCheck) string {
	return cssURLRE.ReplaceAllStringFunc(body, func(match string) string {
		start := strings.Index(match, "(")
		end := strings.LastIndex(match, ")")
		if start < 0 || end <= start {
			return match
		}
		rawValue := strings.TrimSpace(match[start+1 : end])
		value := unquoteAttr(rawValue)
		rewritten := rewriteOneURL(ctx, value, base, check, "asset")
		if rewritten == value {
			return match
		}
		return "url(" + quoteLike(rawValue, rewritten) + ")"
	})
}

func ApplyContentRewriteRules(ctx context.Context, body, contentType string, base *url.URL, result resources.TestResult) string {
	if len(result.ContentRewriteRules) == 0 || base == nil || !contentRewriteAllowed(contentType, result) {
		return body
	}
	applied := 0
	for _, rule := range result.ContentRewriteRules {
		if !rewriteRuleMatchesContentType(rule, contentType) || rule.Find == "" {
			continue
		}
		replacement, err := expandRewriteTemplate(rule.Replace, base)
		if err != nil {
			continue
		}
		count := strings.Count(body, rule.Find)
		if count == 0 {
			continue
		}
		body = strings.ReplaceAll(body, rule.Find, replacement)
		applied += count
	}
	if applied > 0 {
		if diagnostics := DiagnosticsFrom(ctx); diagnostics != nil {
			diagnostics.ContentRewriteRulesApplied += applied
		}
	}
	return body
}

func contentRewriteAllowed(contentType string, result resources.TestResult) bool {
	contentType = strings.ToLower(contentType)
	if strings.Contains(contentType, "application/javascript") || strings.Contains(contentType, "text/javascript") {
		return result.JavaScriptTextRewriteEnabled
	}
	return textLikeContentType(contentType)
}

func rewriteRuleMatchesContentType(rule resources.ContentRewriteRule, contentType string) bool {
	contentType = strings.ToLower(strings.Split(contentType, ";")[0])
	for _, allowed := range rule.ContentTypes {
		allowed = strings.ToLower(strings.TrimSpace(allowed))
		if allowed != "" && strings.Contains(contentType, allowed) {
			return true
		}
	}
	return false
}

func textLikeContentType(contentType string) bool {
	for _, allowed := range []string{"text/html", "text/css", "application/json", "application/xml", "text/xml"} {
		if strings.Contains(contentType, allowed) {
			return true
		}
	}
	return false
}

func expandRewriteTemplate(template string, base *url.URL) (string, error) {
	out := template
	out = strings.ReplaceAll(out, "{proxy_host_suffix}", "")
	out = strings.ReplaceAll(out, "{proxy_base_url}", BuildProxyURL(base))
	out = strings.ReplaceAll(out, "{target_origin}", base.Scheme+"://"+base.Host)
	tokenRE := regexp.MustCompile(`\{proxy_(?:http_)?url:([^}]+)\}`)
	out = tokenRE.ReplaceAllStringFunc(out, func(match string) string {
		parts := tokenRE.FindStringSubmatch(match)
		if len(parts) != 2 {
			return match
		}
		parsed, err := url.Parse(parts[1])
		if err != nil || parsed.Hostname() == "" {
			return match
		}
		return BuildProxyURL(parsed)
	})
	encodedTokenRE := regexp.MustCompile(`\{urlencoded_proxy_url:([^}]+)\}`)
	out = encodedTokenRE.ReplaceAllStringFunc(out, func(match string) string {
		parts := encodedTokenRE.FindStringSubmatch(match)
		if len(parts) != 2 {
			return match
		}
		parsed, err := url.Parse(parts[1])
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
			return match
		}
		return url.QueryEscape(BuildProxyURL(parsed))
	})
	prefixTokenRE := regexp.MustCompile(`\{proxy_prefix_url:([^}]+)\}`)
	var prefixErr error
	out = prefixTokenRE.ReplaceAllStringFunc(out, func(match string) string {
		parts := prefixTokenRE.FindStringSubmatch(match)
		if len(parts) != 2 {
			return match
		}
		prefix, err := BuildProxyURLPrefix(parts[1], ProxyURLMode())
		if err != nil {
			prefixErr = fmt.Errorf("render %s: %w", match, err)
			return match
		}
		return prefix
	})
	if prefixErr != nil {
		return "", prefixErr
	}
	return out, nil
}

func splitAttr(match string) (string, string, bool) {
	parts := strings.SplitN(match, "=", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return strings.TrimRight(parts[0], " \t\r\n"), strings.TrimSpace(parts[1]), true
}

func unquoteAttr(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 {
		first := value[0]
		last := value[len(value)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			return value[1 : len(value)-1]
		}
	}
	return value
}

func quoteLike(original, value string) string {
	original = strings.TrimSpace(original)
	if strings.HasPrefix(original, "'") && strings.HasSuffix(original, "'") {
		return "'" + value + "'"
	}
	if strings.HasPrefix(original, `"`) && strings.HasSuffix(original, `"`) {
		return `"` + value + `"`
	}
	return value
}

func rewriteSrcset(ctx context.Context, value string, base *url.URL, check TargetCheck) string {
	candidates := strings.Split(value, ",")
	for i, candidate := range candidates {
		leading := leadingSpace(candidate)
		trimmed := strings.TrimSpace(candidate)
		if trimmed == "" {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) == 0 {
			continue
		}
		fields[0] = rewriteOneURL(ctx, fields[0], base, check, "asset")
		candidates[i] = leading + strings.Join(fields, " ")
	}
	return strings.Join(candidates, ", ")
}

func leadingSpace(value string) string {
	return value[:len(value)-len(strings.TrimLeft(value, " \t\r\n"))]
}

func rewriteOneURL(ctx context.Context, raw string, base *url.URL, check TargetCheck, category string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "#") {
		return raw
	}
	if raw == PublicProxyPath || strings.HasPrefix(raw, PublicProxyPath+"/") || strings.HasPrefix(raw, PublicProxyPath+"?") {
		return raw
	}
	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, "data:") || strings.HasPrefix(lower, "about:") ||
		strings.HasPrefix(lower, "javascript:") || strings.HasPrefix(lower, "mailto:") {
		return raw
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	resolved := base.ResolveReference(parsed)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return raw
	}
	target, result := check(ctx, resolved.String())
	diagnostics := DiagnosticsFrom(ctx)
	if result.Blocked || result.Action == "block" {
		if diagnostics != nil {
			diagnostics.BlockedURLCount++
		}
		return raw
	}
	if result.Action != "" && result.Action != "proxy" && result.Action != "block" {
		if diagnostics != nil {
			diagnostics.NonProxyableAllowedCount++
		}
		return raw
	}
	if !result.Allowed || target == nil {
		return raw
	}
	if diagnostics != nil {
		switch category {
		case "form":
			diagnostics.RewrittenFormCount++
		case "navigation":
			diagnostics.RewrittenNavigationCount++
		default:
			diagnostics.RewrittenAssetCount++
		}
	}
	return BuildProxyURL(target)
}

func rewriteCategory(attr string) string {
	switch strings.ToLower(strings.TrimSpace(attr)) {
	case "action":
		return "form"
	case "href", "data-href":
		return "navigation"
	default:
		return "asset"
	}
}
