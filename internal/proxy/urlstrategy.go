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

	ProxyURLModePath        = "path"
	ProxyURLModeQuery       = "query"
	ProxyURLModeDual        = "dual"
	ProxyURLModeVirtualHost = "virtual_host"
)

type URLStrategy interface {
	BuildProxyURL(target *url.URL) string
	ParseProxyRequest(r *http.Request) (*url.URL, string, bool, error)
}

type envURLStrategy struct{}

func ProxyURLMode() string {
	return NormalizeProxyURLMode(os.Getenv("APP_PROXY_URL_MODE"))
}

func NormalizeProxyURLMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", ProxyURLModePath:
		return ProxyURLModePath
	case ProxyURLModeQuery:
		return ProxyURLModeQuery
	case ProxyURLModeDual:
		return ProxyURLModeDual
	case ProxyURLModeVirtualHost:
		return ProxyURLModePath
	default:
		return ProxyURLModePath
	}
}

func ProxyURLModeWarning(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case ProxyURLModeVirtualHost:
		return "virtual_host proxy URL mode is planned but not implemented; using path mode"
	default:
		return ""
	}
}

func BuildProxyURL(target *url.URL) string {
	return envURLStrategy{}.BuildProxyURL(target)
}

func BuildProxyURLWithMode(target *url.URL, mode string) string {
	if target == nil {
		return PublicProxyPath
	}
	switch NormalizeProxyURLMode(mode) {
	case ProxyURLModeQuery:
		return PublicProxyPath + "?url=" + url.QueryEscape(target.String())
	default:
		return buildPathProxyURL(target)
	}
}

func (envURLStrategy) BuildProxyURL(target *url.URL) string {
	return BuildProxyURLWithMode(target, ProxyURLMode())
}

func ParseProxyRequest(r *http.Request) (*url.URL, string, bool, error) {
	return envURLStrategy{}.ParseProxyRequest(r)
}

func (envURLStrategy) ParseProxyRequest(r *http.Request) (*url.URL, string, bool, error) {
	if r == nil || r.URL == nil {
		return nil, "", false, errors.New("proxy request is invalid")
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("url")); raw != "" {
		target, err := url.Parse(raw)
		if err != nil {
			return nil, ProxyURLModeQuery, true, errors.New("target URL is invalid")
		}
		return target, ProxyURLModeQuery, true, nil
	}

	rest := strings.TrimPrefix(r.URL.Path, PublicProxyPath)
	rest = strings.TrimPrefix(rest, "/")
	if rest == "" {
		return nil, "", false, errors.New("target URL is required")
	}
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) < 2 {
		return nil, ProxyURLModePath, true, errors.New("proxy path is invalid")
	}
	if strings.ToLower(parts[0]) != "https" {
		return nil, ProxyURLModePath, true, errors.New("only HTTPS proxy paths are supported")
	}
	host := strings.TrimSpace(parts[1])
	if host == "" {
		return nil, ProxyURLModePath, true, errors.New("target host is required")
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
	return target, ProxyURLModePath, true, nil
}

func buildPathProxyURL(target *url.URL) string {
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
