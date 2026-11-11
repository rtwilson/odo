package api

import (
	"errors"
	"net/http"
	"os"
	"strings"

	"example.org/odo/internal/accesslog"
	"example.org/odo/internal/proxy"
)

func hostGuardConfigFromEnv() (bool, proxy.HostRoutingConfig, error) {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("APP_HOST_GUARD"))) {
	case "", "false", "0", "no", "off":
		return false, proxy.HostRoutingConfig{}, nil
	case "true", "1", "yes", "on":
		config, err := proxy.NewHostRoutingConfig(os.Getenv("APP_PUBLIC_URL"), os.Getenv("APP_PROXY_BASE_DOMAIN"))
		return true, config, err
	default:
		return true, proxy.HostRoutingConfig{}, errors.New("APP_HOST_GUARD must be true or false")
	}
}

// ValidateHostGuardConfig validates the opt-in boundary in all environments.
// It does not enable virtual-host routing or perform DNS/HTTP requests.
func ValidateHostGuardConfig() error {
	_, _, err := hostGuardConfigFromEnv()
	if err != nil {
		return err
	}
	enabled, config, err := experimentalHandoffConfig()
	if err != nil || !enabled {
		return err
	}
	// Fail startup if the runtime's cookie manager could not be constructed.
	if _, err := proxy.NewUpstreamCookieJars(config); err != nil {
		return errors.New("experimental handoff cookie coordinator configuration is invalid")
	}
	return nil
}

func (s *Server) guardHost(next http.Handler) http.Handler {
	enabled, config, configErr := hostGuardConfigFromEnv()
	if !enabled && s.handoffErr == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.handoff != nil || s.handoffErr != nil {
			if metadata := accesslog.MetadataFrom(r.Context()); metadata != nil {
				metadata.SuppressBrowserHeaders = true
			}
		}
		reject := func(status int, message string) {
			// Do not record arbitrary paths submitted to a rejected authority.
			if metadata := accesslog.MetadataFrom(r.Context()); metadata != nil {
				metadata.Route = "host_rejected"
			}
			w.Header().Set("Cache-Control", "no-store")
			writeError(w, status, message)
		}
		if configErr != nil || s.handoffErr != nil {
			reject(http.StatusServiceUnavailable, "host guard configuration is invalid")
			return
		}
		if !requestOnCentralHost(r, config) {
			if s.handoff != nil && s.handoff.vendorRequest(r) {
				s.handoff.serveVendor(w, r)
				return
			}
			// Everything else on a proxy hostname is experimental vendor content.
			// The central mux (admin, login, API, resources, session routes) is
			// never reachable here; unregistered names are rejected inside.
			if s.handoff != nil && s.handoff.vendorContentAuthority(r) != "" {
				s.handoff.serveVendorContent(w, r)
				return
			}
			reject(http.StatusMisdirectedRequest, "request authority is not admitted")
			return
		}
		// Forwarded and X-Forwarded-Host never influence this decision.
		next.ServeHTTP(w, r)
	})
}

// Shared by the current host guard and the unregistered confirmation handler.
// Forwarded headers never supply authority; absolute-form requests must agree.
func requestOnCentralHost(r *http.Request, config proxy.HostRoutingConfig) bool {
	central, _, err := config.ClassifyAuthority(r.Host)
	if err != nil || !central || r.URL == nil || r.URL.User != nil || r.URL.Opaque != "" {
		return false
	}
	if r.URL.Host != "" || r.URL.Scheme != "" {
		absoluteCentral, _, err := config.ClassifyAuthority(r.URL.Host)
		return err == nil && absoluteCentral && r.URL.Scheme == "https"
	}
	return true
}
