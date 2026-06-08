package proxy

import (
	"context"
	"net/url"
	"regexp"
	"strings"
)

var (
	htmlURLAttrRE   = regexp.MustCompile(`(?i)\b(data-src|data-href|href|src|action|poster)\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)`)
	htmlSrcsetRE    = regexp.MustCompile(`(?i)\bsrcset\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)`)
	htmlStyleAttrRE = regexp.MustCompile(`(?i)\bstyle\s*=\s*("[^"]*"|'[^']*')`)
	cssURLRE        = regexp.MustCompile(`(?i)url\(\s*("[^"]*"|'[^']*'|[^)]*)\s*\)`)
)

func RewriteHTML(ctx context.Context, body string, base *url.URL, check TargetCheck) string {
	body = htmlURLAttrRE.ReplaceAllStringFunc(body, func(match string) string {
		name, rawValue, ok := splitAttr(match)
		if !ok {
			return match
		}
		rewritten := rewriteOneURL(ctx, unquoteAttr(rawValue), base, check)
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

	return body
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
		rewritten := rewriteOneURL(ctx, value, base, check)
		if rewritten == value {
			return match
		}
		return "url(" + quoteLike(rawValue, rewritten) + ")"
	})
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
		fields[0] = rewriteOneURL(ctx, fields[0], base, check)
		candidates[i] = leading + strings.Join(fields, " ")
	}
	return strings.Join(candidates, ", ")
}

func leadingSpace(value string) string {
	return value[:len(value)-len(strings.TrimLeft(value, " \t\r\n"))]
}

func rewriteOneURL(ctx context.Context, raw string, base *url.URL, check TargetCheck) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "#") {
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
	if !result.Allowed || target == nil {
		return raw
	}
	return "/p?url=" + url.QueryEscape(target.String())
}
