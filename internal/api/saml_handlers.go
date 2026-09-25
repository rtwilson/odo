package api

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"os"
	"strings"

	"example.org/odo/internal/auth/saml"
)

func (s *Server) listSAMLProviders(w http.ResponseWriter, r *http.Request) {
	providers, err := s.store.ListSAMLProviders()
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"providers": providers})
}

func (s *Server) upsertSAMLProvider(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var provider saml.Provider
	if err := json.NewDecoder(r.Body).Decode(&provider); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	provider, err := saml.Validate(provider, publicBaseURL(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.UpsertSAMLProvider(provider); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, provider)
}

func (s *Server) getSAMLProvider(w http.ResponseWriter, r *http.Request) {
	provider, found, err := s.store.GetSAMLProvider(strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "saml provider not found")
		return
	}
	writeJSON(w, http.StatusOK, provider)
}

func (s *Server) deleteSAMLProvider(w http.ResponseWriter, r *http.Request) {
	deleted, err := s.store.DeleteSAMLProvider(strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !deleted {
		writeError(w, http.StatusNotFound, "saml provider not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "id": strings.TrimSpace(r.PathValue("id"))})
}

func (s *Server) samlMetadata(w http.ResponseWriter, r *http.Request) {
	provider, found, err := s.store.ActiveSAMLProvider()
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "no active SAML provider configured")
		return
	}
	provider, err = saml.Validate(provider, publicBaseURL(r))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := s.store.Audit("saml_metadata_served", fmt.Sprintf(`{"provider_id":%q}`, provider.ID)); err != nil {
		s.internalError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml; charset=utf-8")
	_, _ = w.Write([]byte(spMetadataXML(provider)))
}

func (s *Server) samlLogin(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error": "SAML login initiation is not implemented yet",
	})
}

func (s *Server) samlACS(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error": "SAML assertion validation is not implemented yet",
	})
}

func publicBaseURL(r *http.Request) string {
	if value := configuredPublicURL(); value != "" {
		return value
	}
	scheme := ""
	host := r.Host
	if trustProxyHeaders() {
		scheme = firstForwardedValue(r.Header.Get("X-Forwarded-Proto"))
		if forwardedHost := firstForwardedValue(r.Header.Get("X-Forwarded-Host")); forwardedHost != "" {
			host = forwardedHost
		}
	}
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	if host == "" {
		host = "127.0.0.1:8080"
	}
	return scheme + "://" + host
}

func configuredPublicURL() string {
	return strings.TrimRight(strings.TrimSpace(os.Getenv("APP_PUBLIC_URL")), "/")
}

func trustProxyHeaders() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("APP_TRUST_PROXY_HEADERS"))) {
	case "true", "1", "yes", "on":
		return true
	default:
		return false
	}
}

func firstForwardedValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if idx := strings.Index(value, ","); idx >= 0 {
		value = value[:idx]
	}
	return strings.TrimSpace(value)
}

func spMetadataXML(provider saml.Provider) string {
	return `<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
		`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + xmlEscape(provider.EntityID) + `">` + "\n" +
		`  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="` + boolXML(provider.SignAuthnRequests) + `" WantAssertionsSigned="` + boolXML(provider.RequireSignedAssertions) + `">` + "\n" +
		`    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>` + "\n" +
		`    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="` + xmlEscape(provider.ACSURL) + `" index="1" isDefault="true"/>` + "\n" +
		`  </md:SPSSODescriptor>` + "\n" +
		`</md:EntityDescriptor>` + "\n"
}

func xmlEscape(value string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(value))
	return buf.String()
}

func boolXML(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
