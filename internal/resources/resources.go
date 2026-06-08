package resources

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
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

func DecodeAll(data []byte) (Resource, []string) {
	var resource Resource
	if err := json.Unmarshal(data, &resource); err != nil {
		return Resource{}, []string{err.Error()}
	}
	return ValidateAll(resource)
}

func Validate(resource Resource) (Resource, error) {
	resource, errs := ValidateAll(resource)
	if len(errs) > 0 {
		return Resource{}, errors.New(errs[0])
	}
	return resource, nil
}

func ValidateAll(resource Resource) (Resource, []string) {
	var errs []string

	resource.ID = strings.TrimSpace(resource.ID)
	resource.Name = strings.TrimSpace(resource.Name)
	resource.Status = strings.ToLower(strings.TrimSpace(resource.Status))
	if resource.Status == "" {
		resource.Status = "active"
	}

	if resource.ID == "" {
		errs = append(errs, "resource id is required")
	}
	if resource.Name == "" {
		errs = append(errs, "resource name is required")
	}
	if len(resource.Domains) == 0 {
		errs = append(errs, "at least one domain is required")
	}

	for i := range resource.Domains {
		resource.Domains[i].Host = normalizeHost(resource.Domains[i].Host)
		resource.Domains[i].Match = strings.ToLower(strings.TrimSpace(resource.Domains[i].Match))
		if resource.Domains[i].Match == "" {
			resource.Domains[i].Match = "exact"
		}
		errs = append(errs, validateDomainRule(i, resource.Domains[i])...)
	}

	for i, sample := range resource.SampleURLs {
		parsed, err := url.Parse(sample)
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
			errs = append(errs, fmt.Sprintf("sample_urls[%d] must be a valid HTTPS URL", i))
		}
	}

	return resource, errs
}

func validateDomainRule(i int, rule DomainRule) []string {
	var errs []string
	if rule.Host == "" {
		errs = append(errs, fmt.Sprintf("domains[%d].host is required", i))
	}
	if strings.Contains(rule.Host, "://") {
		errs = append(errs, fmt.Sprintf("domains[%d].host must not contain a scheme", i))
	}
	if strings.Contains(rule.Host, "/") {
		errs = append(errs, fmt.Sprintf("domains[%d].host must not contain path slashes", i))
	}
	if strings.Contains(rule.Host, "*") {
		errs = append(errs, fmt.Sprintf("domains[%d].host must not contain wildcards", i))
	}
	if rule.Host == "localhost" {
		errs = append(errs, fmt.Sprintf("domains[%d].host must not be localhost", i))
	}
	if net.ParseIP(rule.Host) != nil {
		errs = append(errs, fmt.Sprintf("domains[%d].host must not be an IP address", i))
	}
	if rule.Match != "exact" && rule.Match != "subdomain" {
		errs = append(errs, fmt.Sprintf("domains[%d].match must be exact or subdomain", i))
	}
	return errs
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
