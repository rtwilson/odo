package proxy

import (
	"bytes"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html"
)

// sameHostURLAttributes are the HTML attributes whose values the browser
// resolves as URLs for navigation or subresources. Only these are examined;
// data-*, style (CSS), inline scripts, meta refresh and text are never changed.
var sameHostURLAttributes = map[string]bool{
	"href": true, "src": true, "srcset": true, "poster": true,
	"action": true, "formaction": true, "data": true,
}

// RewriteSameHostHTML re-expresses absolute or scheme-relative URLs that point
// at upstreamHost (http or https, default port, no userinfo) as https URLs on
// proxyAuthority, in recognized URL-bearing attributes only. The scheme and
// authority are replaced; every byte after the authority (escaped path, query,
// fragment) is kept. Relative URLs and other hosts are left to the browser's
// native resolution. Unchanged tokens are copied byte-for-byte; a changed tag
// is re-serialized with non-ASCII characters as numeric character references,
// so the document's character encoding is preserved. It reports whether
// anything changed; on malformed input it returns body unchanged.
func RewriteSameHostHTML(body []byte, upstreamHost, proxyAuthority string) ([]byte, bool) {
	tokenizer := html.NewTokenizer(bytes.NewReader(body))
	var out bytes.Buffer
	out.Grow(len(body))
	changed := false
	for {
		kind := tokenizer.Next()
		raw := tokenizer.Raw()
		if kind == html.ErrorToken {
			if tokenizer.Err() != io.EOF {
				return body, false
			}
			out.Write(raw)
			break
		}
		if kind != html.StartTagToken && kind != html.SelfClosingTagToken {
			out.Write(raw)
			continue
		}
		// Token lower-cases the tag name in the tokenizer's buffer, which Raw
		// aliases: copy the original bytes first.
		raw = bytes.Clone(raw)
		token := tokenizer.Token()
		tagChanged := false
		for i := range token.Attr {
			attr := &token.Attr[i]
			if attr.Namespace != "" || !sameHostURLAttributes[attr.Key] {
				continue
			}
			var next string
			var ok bool
			if attr.Key == "srcset" {
				next, ok = rewriteSameHostSrcset(attr.Val, upstreamHost, proxyAuthority)
			} else {
				next, ok = rewriteSameHostURL(attr.Val, upstreamHost, proxyAuthority)
			}
			if ok {
				attr.Val = next
				tagChanged = true
			}
		}
		if !tagChanged {
			out.Write(raw)
			continue
		}
		changed = true
		writeTag(&out, token, kind == html.SelfClosingTagToken)
	}
	if !changed {
		return body, false
	}
	return out.Bytes(), true
}

// rewriteSameHostURL returns the proxy form of raw when raw is an absolute or
// scheme-relative URL for upstreamHost. Browsers strip surrounding ASCII
// whitespace from URL attributes, so the comparison ignores it too.
func rewriteSameHostURL(raw, upstreamHost, proxyAuthority string) (string, bool) {
	value := strings.Trim(raw, " \t\n\f\r")
	rest, defaultPort, ok := "", "", false
	lower := strings.ToLower(value)
	switch {
	case strings.HasPrefix(lower, "https://"):
		rest, defaultPort, ok = value[len("https://"):], "443", true
	case strings.HasPrefix(lower, "http://"):
		rest, defaultPort, ok = value[len("http://"):], "80", true
	case strings.HasPrefix(value, "//"):
		// Scheme-relative: the page is served over https on the proxy host.
		rest, defaultPort, ok = value[len("//"):], "443", true
	}
	if !ok {
		return raw, false
	}
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	authority, suffix := rest[:end], rest[end:]
	if strings.ContainsAny(authority, "@\\%") {
		return raw, false
	}
	host, port := authority, ""
	if i := strings.LastIndexByte(authority, ':'); i >= 0 {
		host, port = authority[:i], authority[i+1:]
		if port != defaultPort {
			return raw, false
		}
	}
	if !strings.EqualFold(host, upstreamHost) {
		return raw, false
	}
	return "https://" + proxyAuthority + suffix, true
}

// rewriteSameHostSrcset rewrites the URL of each comma-separated candidate,
// keeping its descriptors and spacing.
func rewriteSameHostSrcset(value, upstreamHost, proxyAuthority string) (string, bool) {
	candidates := strings.Split(value, ",")
	changed := false
	for i, candidate := range candidates {
		trimmed := strings.TrimLeft(candidate, " \t\n\f\r")
		leading := candidate[:len(candidate)-len(trimmed)]
		end := strings.IndexAny(trimmed, " \t\n\f\r")
		if end < 0 {
			end = len(trimmed)
		}
		if next, ok := rewriteSameHostURL(trimmed[:end], upstreamHost, proxyAuthority); ok {
			candidates[i] = leading + next + trimmed[end:]
			changed = true
		}
	}
	return strings.Join(candidates, ","), changed
}

func writeTag(out *bytes.Buffer, token html.Token, selfClosing bool) {
	out.WriteByte('<')
	out.WriteString(token.Data)
	for _, attr := range token.Attr {
		out.WriteByte(' ')
		if attr.Namespace != "" {
			out.WriteString(attr.Namespace)
			out.WriteByte(':')
		}
		out.WriteString(attr.Key)
		out.WriteString(`="`)
		writeAttributeValue(out, attr.Val)
		out.WriteByte('"')
	}
	if selfClosing {
		out.WriteString(" /")
	}
	out.WriteByte('>')
}

// writeAttributeValue escapes markup characters, writes decoded non-ASCII
// characters as numeric references (valid in any document encoding) and keeps
// bytes that are not valid UTF-8 exactly as the document supplied them.
func writeAttributeValue(out *bytes.Buffer, value string) {
	for i := 0; i < len(value); {
		r, size := utf8.DecodeRuneInString(value[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			out.WriteByte(value[i])
		case r == '&':
			out.WriteString("&amp;")
		case r == '"':
			out.WriteString("&quot;")
		case r == '<':
			out.WriteString("&lt;")
		case r == '>':
			out.WriteString("&gt;")
		case r < utf8.RuneSelf:
			out.WriteByte(byte(r))
		default:
			out.WriteString("&#" + strconv.Itoa(int(r)) + ";")
		}
		i += size
	}
}
