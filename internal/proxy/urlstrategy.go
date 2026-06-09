package proxy

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const (
	PublicProxyPath = "/odo"

	ProxyURLModePath  = "path"
	ProxyURLModeQuery = "query"
)

func ProxyURLMode() string {
	return NormalizeProxyURLMode(os.Getenv("APP_PROXY_URL_MODE"))
}

func NormalizeProxyURLMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", ProxyURLModePath:
		return ProxyURLModePath
	case ProxyURLModeQuery:
		return ProxyURLModeQuery
	default:
		return ProxyURLModePath
	}
}

func BuildProxyURL(target *url.URL) string {
	return BuildProxyURLWithMode(target, ProxyURLMode())
}

func BuildProxyURLWithMode(target *url.URL, mode string) string {
	if target == nil {
		return PublicProxyPath
	}
	switch NormalizeProxyURLMode(mode) {
	case ProxyURLModeQuery:
		return PublicProxyPath + "?url=" + url.QueryEscape(target.String())
	default:
		// Path mode is the local/MVP-friendly strategy. Virtual-host mode can
		// be added beside this switch later without changing rewrite callers.
		path := target.EscapedPath()
		if path == "" {
			path = "/"
		}
		proxyURL := PublicProxyPath + "/https/" + target.Host + path
		if target.RawQuery != "" {
			proxyURL += "?" + target.RawQuery
		}
		return proxyURL
	}
}

func ParseProxyRequest(r *http.Request) (*url.URL, error) {
	if r == nil || r.URL == nil {
		return nil, errors.New("proxy request is invalid")
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("url")); raw != "" {
		target, err := url.Parse(raw)
		if err != nil {
			return nil, errors.New("target URL is invalid")
		}
		return target, nil
	}

	rest := strings.TrimPrefix(r.URL.Path, PublicProxyPath)
	rest = strings.TrimPrefix(rest, "/")
	if rest == "" {
		return nil, errors.New("target URL is required")
	}
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) < 2 {
		return nil, errors.New("proxy path is invalid")
	}
	if strings.ToLower(parts[0]) != "https" {
		return nil, errors.New("only HTTPS proxy paths are supported")
	}
	host := strings.TrimSpace(parts[1])
	if host == "" {
		return nil, errors.New("target host is required")
	}
	targetPath := "/"
	if len(parts) == 3 {
		targetPath += parts[2]
	}
	target := &url.URL{
		Scheme:   "https",
		Host:     host,
		Path:     targetPath,
		RawQuery: r.URL.RawQuery,
	}
	return target, nil
}
