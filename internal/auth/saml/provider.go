package saml

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Provider struct {
	ID                      string            `json:"id"`
	Name                    string            `json:"name"`
	Status                  string            `json:"status"`
	EntityID                string            `json:"entity_id"`
	ACSURL                  string            `json:"acs_url"`
	MetadataURL             string            `json:"metadata_url,omitempty"`
	MetadataXML             string            `json:"metadata_xml,omitempty"`
	SignAuthnRequests       bool              `json:"sign_authn_requests"`
	RequireSignedAssertions bool              `json:"require_signed_assertions"`
	RequireSignedResponses  bool              `json:"require_signed_responses"`
	AttributeMappings       map[string]string `json:"attribute_mappings,omitempty"`
	RoleMappings            map[string]string `json:"role_mappings,omitempty"`
	SessionTTLMinutes       int               `json:"session_ttl_minutes"`
	IdleTimeoutMinutes      int               `json:"idle_timeout_minutes"`
}

func Decode(data []byte) (Provider, error) {
	var provider Provider
	if err := json.Unmarshal(data, &provider); err != nil {
		return Provider{}, err
	}
	return Validate(provider, "")
}

func Validate(provider Provider, publicURL string) (Provider, error) {
	provider.ID = strings.TrimSpace(provider.ID)
	provider.Name = strings.TrimSpace(provider.Name)
	provider.Status = strings.TrimSpace(provider.Status)
	provider.EntityID = strings.TrimSpace(provider.EntityID)
	provider.ACSURL = strings.TrimSpace(provider.ACSURL)
	provider.MetadataURL = strings.TrimSpace(provider.MetadataURL)
	provider.MetadataXML = strings.TrimSpace(provider.MetadataXML)
	publicURL = strings.TrimRight(strings.TrimSpace(publicURL), "/")

	if provider.ID == "" {
		return Provider{}, fmt.Errorf("saml provider id is required")
	}
	if provider.Name == "" {
		return Provider{}, fmt.Errorf("saml provider name is required")
	}
	if provider.Status == "" {
		provider.Status = "active"
	}
	if provider.Status != "active" && provider.Status != "disabled" {
		return Provider{}, fmt.Errorf("saml provider status must be active or disabled")
	}
	if provider.EntityID == "" && publicURL != "" {
		provider.EntityID = publicURL + "/auth/saml/metadata"
	}
	if provider.ACSURL == "" && publicURL != "" {
		provider.ACSURL = publicURL + "/auth/saml/acs"
	}
	if provider.EntityID == "" {
		return Provider{}, fmt.Errorf("saml provider entity_id is required")
	}
	if provider.ACSURL == "" {
		return Provider{}, fmt.Errorf("saml provider acs_url is required")
	}
	if provider.SessionTTLMinutes <= 0 {
		provider.SessionTTLMinutes = 480
	}
	if provider.IdleTimeoutMinutes <= 0 {
		provider.IdleTimeoutMinutes = 60
	}
	for key, value := range provider.AttributeMappings {
		if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
			return Provider{}, fmt.Errorf("saml provider attribute_mappings keys and values must be non-empty")
		}
	}
	return provider, nil
}
