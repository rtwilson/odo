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
	Host   string `json:"host"`
	Match  string `json:"match"`
	Role   string `json:"role,omitempty"`
	Action string `json:"action,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type TestResult struct {
	Allowed    bool        `json:"allowed"`
	Blocked    bool        `json:"blocked,omitempty"`
	Host       string      `json:"host,omitempty"`
	ResourceID string      `json:"resource_id,omitempty"`
	RuleHost   string      `json:"rule_host,omitempty"`
	RuleMatch  string      `json:"rule_match,omitempty"`
	Role       string      `json:"role,omitempty"`
	Action     string      `json:"action,omitempty"`
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
		resource.Domains[i].Role = strings.ToLower(strings.TrimSpace(resource.Domains[i].Role))
		if resource.Domains[i].Role == "" {
			resource.Domains[i].Role = "content"
		}
		resource.Domains[i].Action = strings.ToLower(strings.TrimSpace(resource.Domains[i].Action))
		if resource.Domains[i].Action == "" {
			resource.Domains[i].Action = defaultActionForRole(resource.Domains[i].Role)
		}
		resource.Domains[i].Reason = strings.TrimSpace(resource.Domains[i].Reason)
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
	if rule.Host == "local" || strings.HasSuffix(rule.Host, ".local") {
		errs = append(errs, fmt.Sprintf("domains[%d].host must not use .local", i))
	}
	if rule.Host == "internal" || strings.HasSuffix(rule.Host, ".internal") {
		errs = append(errs, fmt.Sprintf("domains[%d].host must not use .internal", i))
	}
	if net.ParseIP(rule.Host) != nil {
		errs = append(errs, fmt.Sprintf("domains[%d].host must not be an IP address", i))
	}
	if rule.Match != "exact" && rule.Match != "subdomain" {
		errs = append(errs, fmt.Sprintf("domains[%d].match must be exact or subdomain", i))
	}
	if !validRole(rule.Role) {
		errs = append(errs, fmt.Sprintf("domains[%d].role must be content, asset, api, auth, redirect, external, or blocked", i))
	}
	if !validAction(rule.Action) {
		errs = append(errs, fmt.Sprintf("domains[%d].action must be proxy, allow, or block", i))
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
	var best *matchCandidate
	for _, resource := range activeResources {
		if resource.Status != "active" {
			continue
		}
		for _, rule := range resource.Domains {
			rule = normalizeDomainRule(rule)
			if matches(host, rule) {
				matched := rule
				candidate := matchCandidate{resourceID: resource.ID, rule: matched}
				if best == nil || candidate.beats(*best) {
					best = &candidate
				}
			}
		}
	}

	if best != nil {
		return best.result(host)
	}

	return TestResult{Allowed: false, Reason: "no active resource domain rule matched"}
}

type matchCandidate struct {
	resourceID string
	rule       DomainRule
}

func (c matchCandidate) beats(other matchCandidate) bool {
	cExact := c.rule.Match == "exact"
	oExact := other.rule.Match == "exact"
	if cExact != oExact {
		return cExact
	}
	if len(c.rule.Host) != len(other.rule.Host) {
		return len(c.rule.Host) > len(other.rule.Host)
	}
	cBlock := c.rule.Action == "block"
	oBlock := other.rule.Action == "block"
	if cBlock != oBlock {
		return cBlock
	}
	return c.rule.Host < other.rule.Host
}

func (c matchCandidate) result(host string) TestResult {
	matched := c.rule
	blocked := matched.Action == "block"
	reason := "matched"
	if blocked {
		reason = "explicitly_blocked"
		if matched.Reason != "" {
			reason = matched.Reason
		}
	}
	return TestResult{
		Allowed:    !blocked,
		Blocked:    blocked,
		Host:       host,
		ResourceID: c.resourceID,
		RuleHost:   matched.Host,
		RuleMatch:  matched.Match,
		Role:       matched.Role,
		Action:     matched.Action,
		Matched:    &matched,
		Reason:     reason,
	}
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

func normalizeDomainRule(rule DomainRule) DomainRule {
	rule.Host = normalizeHost(rule.Host)
	rule.Match = strings.ToLower(strings.TrimSpace(rule.Match))
	if rule.Match == "" {
		rule.Match = "exact"
	}
	rule.Role = strings.ToLower(strings.TrimSpace(rule.Role))
	if rule.Role == "" {
		rule.Role = "content"
	}
	rule.Action = strings.ToLower(strings.TrimSpace(rule.Action))
	if rule.Action == "" {
		rule.Action = defaultActionForRole(rule.Role)
	}
	rule.Reason = strings.TrimSpace(rule.Reason)
	return rule
}

func defaultActionForRole(role string) string {
	switch role {
	case "blocked":
		return "block"
	case "external":
		return "allow"
	default:
		return "proxy"
	}
}

func validRole(role string) bool {
	switch role {
	case "content", "asset", "api", "auth", "redirect", "external", "blocked":
		return true
	default:
		return false
	}
}

func validAction(action string) bool {
	switch action {
	case "proxy", "allow", "block":
		return true
	default:
		return false
	}
}
