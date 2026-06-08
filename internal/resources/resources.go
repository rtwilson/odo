package resources

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

type Resource struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Status      string       `json:"status"`
	Description string       `json:"description,omitempty"`
	Domains     []DomainRule `json:"domains"`
	SampleURLs  []string     `json:"sample_urls,omitempty"`
}

type DomainRule struct {
	Host  string `json:"host"`
	Match string `json:"match"`
	Role  string `json:"role,omitempty"`
}

type TestResult struct {
	Allowed    bool        `json:"allowed"`
	ResourceID string      `json:"resource_id,omitempty"`
	Matched    *DomainRule `json:"matched_rule,omitempty"`
	Reason     string      `json:"reason"`
}

func Decode(data []byte) (Resource, error) {
	var resource Resource
	if err := json.Unmarshal(data, &resource); err != nil {
		return Resource{}, err
	}
	return Validate(resource)
}

func Validate(resource Resource) (Resource, error) {
	resource.ID = strings.TrimSpace(resource.ID)
	resource.Name = strings.TrimSpace(resource.Name)
	resource.Status = strings.ToLower(strings.TrimSpace(resource.Status))
	if resource.Status == "" {
		resource.Status = "active"
	}

	if resource.ID == "" {
		return Resource{}, errors.New("resource id is required")
	}
	if resource.Name == "" {
		return Resource{}, errors.New("resource name is required")
	}

	for i := range resource.Domains {
		resource.Domains[i].Host = normalizeHost(resource.Domains[i].Host)
		resource.Domains[i].Match = strings.ToLower(strings.TrimSpace(resource.Domains[i].Match))
		if resource.Domains[i].Match == "" {
			resource.Domains[i].Match = "exact"
		}
		if resource.Domains[i].Host == "" {
			return Resource{}, fmt.Errorf("domains[%d].host is required", i)
		}
		if resource.Domains[i].Match != "exact" && resource.Domains[i].Match != "subdomain" {
			return Resource{}, fmt.Errorf("domains[%d].match must be exact or subdomain", i)
		}
	}

	for i, sample := range resource.SampleURLs {
		parsed, err := url.Parse(sample)
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
			return Resource{}, fmt.Errorf("sample_urls[%d] must be a valid HTTPS URL", i)
		}
	}

	return resource, nil
}

func TestURL(raw string, activeResources []Resource) TestResult {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Hostname() == "" {
		return TestResult{Allowed: false, Reason: "url is invalid"}
	}
	if parsed.Scheme != "https" {
		return TestResult{Allowed: false, Reason: "only HTTPS URLs are allowed"}
	}

	host := normalizeHost(parsed.Hostname())
	for _, resource := range activeResources {
		if resource.Status != "active" {
			continue
		}
		for _, rule := range resource.Domains {
			if matches(host, rule) {
				matched := rule
				return TestResult{
					Allowed:    true,
					ResourceID: resource.ID,
					Matched:    &matched,
					Reason:     "matched active resource domain rule",
				}
			}
		}
	}

	return TestResult{Allowed: false, Reason: "no active resource domain rule matched"}
}

func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func matches(host string, rule DomainRule) bool {
	ruleHost := normalizeHost(rule.Host)
	switch rule.Match {
	case "exact":
		return host == ruleHost
	case "subdomain":
		return host == ruleHost || strings.HasSuffix(host, "."+ruleHost)
	default:
		return false
	}
}
