package proxy

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"example.org/odo/internal/resources"
	"golang.org/x/net/publicsuffix"
)

type upstreamCookie struct {
	cookie  http.Cookie
	origin  url.URL // Only scheme and host; never a patron URL/query.
	expires time.Time
}

func (m *UpstreamCookieJars) normalizePolicy(input resources.CookiePolicy) (upstreamCookiePolicy, error) {
	scope := strings.ToLower(strings.TrimSpace(input.JarScope))
	if (scope != "" && scope != "resource") || len(input.AllowedCookieDomains) > UpstreamMaxCookieDomains {
		return upstreamCookiePolicy{}, ErrCookiePolicy
	}
	policy := upstreamCookiePolicy{enabled: input.Enabled}
	for _, raw := range input.AllowedCookieDomains {
		domain, ok := cookieDNSName(strings.TrimPrefix(strings.TrimSpace(raw), "."))
		if !ok || m.deploymentDomain(domain) {
			return upstreamCookiePolicy{}, ErrCookiePolicy
		}
		policy.domains = append(policy.domains, strings.Clone(domain))
	}
	slices.Sort(policy.domains)
	policy.domains = slices.Compact(policy.domains)
	return policy, nil
}

func cookieDNSName(raw string) (string, bool) {
	// Use the same IDNA/DNS validation as registry identities, but do not accept
	// ports or trailing-dot Domain attributes that Go would reject.
	if raw == "" || len(raw) > 253 || strings.ContainsAny(raw, ":*") || strings.HasSuffix(raw, ".") {
		return "", false
	}
	host, err := NormalizeRegistryHostname(raw)
	if err != nil {
		return "", false
	}
	if _, err := publicsuffix.EffectiveTLDPlusOne(host); err != nil {
		return "", false
	}
	return host, true
}

func domainContains(domain, host string) bool {
	return domain == host || strings.HasSuffix(host, "."+domain)
}

func (m *UpstreamCookieJars) deploymentDomain(domain string) bool {
	for _, host := range m.deployment {
		if domainContains(domain, host) || domainContains(host, domain) {
			return true
		}
	}
	return false
}

func (m *UpstreamCookieJars) validTarget(target *url.URL) bool {
	if target == nil || (target.Scheme != "https" && target.Scheme != "http") || len(target.Host) > 259 || target.User != nil || target.Opaque != "" || target.Fragment != "" {
		return false
	}
	host, ok := cookieDNSName(target.Hostname())
	return ok && host == target.Hostname() && !m.deploymentDomain(host)
}

func (m *UpstreamCookieJars) permittedCookie(policy upstreamCookiePolicy, origin *url.URL, cookie *http.Cookie) bool {
	if !policy.enabled || !m.validTarget(origin) {
		return false
	}
	if cookie.Domain == "" {
		return true
	}
	domain, ok := cookieDNSName(strings.TrimPrefix(cookie.Domain, "."))
	return ok && !m.deploymentDomain(domain) && slices.Contains(policy.domains, domain) && domainContains(domain, origin.Hostname())
}

func (m *UpstreamCookieJars) storeCookie(jar *upstreamResourceJar, policy upstreamCookiePolicy, target *url.URL, incoming *http.Cookie, now time.Time) {
	if incoming.Valid() != nil || len(incoming.Name)+len(incoming.Value) > UpstreamMaxCookieSize || len(incoming.Path) > UpstreamMaxCookieSize || !m.permittedCookie(policy, target, incoming) {
		return
	}
	// Retain only fields used by the standard jar, not Raw, RawExpires,
	// Unparsed extensions or an arbitrary response/request object graph.
	cookie := http.Cookie{Name: incoming.Name, Value: incoming.Value, Quoted: incoming.Quoted, Domain: strings.ToLower(strings.TrimPrefix(incoming.Domain, ".")), Path: incoming.Path, Secure: incoming.Secure, HttpOnly: incoming.HttpOnly, SameSite: incoming.SameSite}
	if cookie.Path == "" || cookie.Path[0] != '/' {
		// RFC 6265 default-path; matching/ordering remains Go cookiejar's job.
		path := target.Path
		if last := strings.LastIndex(path, "/"); last > 0 && strings.HasPrefix(path, "/") {
			cookie.Path = path[:last]
		} else {
			cookie.Path = "/"
		}
	}
	if len(cookie.Path) > UpstreamMaxCookieSize {
		return
	}
	// Parsed fields can be substrings of a larger raw header or patron URL.
	// Detach them so retained memory contains only the bounded cookie fields.
	cookie.Name, cookie.Value = strings.Clone(cookie.Name), strings.Clone(cookie.Value)
	cookie.Domain, cookie.Path = strings.Clone(cookie.Domain), strings.Clone(cookie.Path)
	expires := incoming.Expires
	if incoming.MaxAge > 0 {
		// Clamp before converting seconds to a Duration (which could overflow).
		expires = jar.expires
		if int64(incoming.MaxAge) < int64(jar.expires.Sub(now)/time.Second) {
			expires = now.Add(time.Duration(incoming.MaxAge) * time.Second)
		}
	}
	remove := incoming.MaxAge < 0 || (!expires.IsZero() && !now.Before(expires))
	// Manager owns expiry, including the injected clock in tests. Go handles
	// all matching with session cookies rebuilt from these bounded records.
	origin := url.URL{Scheme: strings.Clone(target.Scheme), Host: strings.Clone(target.Host)}
	stored := upstreamCookie{cookie: cookie, origin: origin, expires: expires}
	index, total := -1, 0
	for i, old := range jar.cookies {
		total += len(old.cookie.Name) + len(old.cookie.Value)
		if cookieStorageKey(old) == cookieStorageKey(stored) {
			index = i
		}
	}
	if remove {
		if index >= 0 {
			jar.cookies = slices.Delete(jar.cookies, index, index+1)
		}
		return
	}
	// Ask Go to validate acceptance too, including its public-suffix checks.
	probe := origin
	probe.Scheme, probe.Path = "https", cookie.Path
	if len(cookieJarFor([]upstreamCookie{stored}).Cookies(&probe)) == 0 {
		return
	}
	if index >= 0 {
		total -= len(jar.cookies[index].cookie.Name) + len(jar.cookies[index].cookie.Value)
	}
	if (index < 0 && len(jar.cookies) >= UpstreamMaxCookies) || total+len(cookie.Name)+len(cookie.Value) > UpstreamMaxCookieBytes {
		return
	}
	if index >= 0 {
		jar.cookies[index] = stored
	} else {
		jar.cookies = append(jar.cookies, stored)
	}
}

func cookieStorageKey(stored upstreamCookie) string {
	domain := stored.cookie.Domain
	if domain == "" {
		domain = stored.origin.Hostname()
	}
	// Domain and host-only cookies with the same name/domain/path replace
	// each other, as in Go's jar. Scheme and port do not create a new identity.
	return domain + "\x00" + stored.cookie.Path + "\x00" + stored.cookie.Name
}
