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
	ID                 string              `json:"id"`
	Name               string              `json:"name,omitempty"`
	Title              string              `json:"title,omitempty"`
	Status             string              `json:"status"`
	Description        string              `json:"description,omitempty"`
	EntryURLs          []string            `json:"entry_urls,omitempty"`
	HTTPMethods        []string            `json:"http_methods,omitempty"`
	CookiePolicy       CookiePolicy        `json:"cookie_policy,omitempty"`
	RequestHeaderRules []RequestHeaderRule `json:"request_header_rules,omitempty"`
	Domains            []DomainRule        `json:"domains"`
	Compatibility      Compatibility       `json:"compatibility,omitempty"`
	SampleURLs         []string            `json:"sample_urls,omitempty"`
}

type DomainRule struct {
	Host              string `json:"host"`
	Match             string `json:"match,omitempty"`
	Role              string `json:"role,omitempty"`
	Action            string `json:"action,omitempty"`
	Reason            string `json:"reason,omitempty"`
	Behavior          string `json:"behavior,omitempty"`
	IncludeSubdomains bool   `json:"include_subdomains,omitempty"`
	Notes             string `json:"notes,omitempty"`
}

type CookiePolicy struct {
	Enabled              bool     `json:"enabled"`
	JarScope             string   `json:"jar_scope,omitempty"`
	AllowedCookieDomains []string `json:"allowed_cookie_domains,omitempty"`
}

type RequestHeaderRule struct {
	Name   string `json:"name"`
	Action string `json:"action"`
	Phase  string `json:"phase"`
}

type Compatibility struct {
	RefererRecovery *bool `json:"referer_recovery,omitempty"`
	JSShim          *bool `json:"js_shim,omitempty"`
	AppDataRecovery *bool `json:"app_data_recovery,omitempty"`
}

type TestResult struct {
	Allowed            bool                `json:"allowed"`
	Blocked            bool                `json:"blocked,omitempty"`
	Host               string              `json:"host,omitempty"`
	ResourceID         string              `json:"resource_id,omitempty"`
	RuleHost           string              `json:"rule_host,omitempty"`
	RuleMatch          string              `json:"rule_match,omitempty"`
	Role               string              `json:"role,omitempty"`
	Action             string              `json:"action,omitempty"`
	Behavior           string              `json:"domain_behavior,omitempty"`
	Matched            *DomainRule         `json:"matched_rule,omitempty"`
	Reason             string              `json:"reason"`
	HTTPMethods        []string            `json:"-"`
	RequestHeaderRules []RequestHeaderRule `json:"-"`
	MethodAllowed      bool                `json:"method_allowed,omitempty"`
}

type ValidationResult struct {
	Valid      bool     `json:"valid"`
	Warnings   []string `json:"warnings"`
	Errors     []string `json:"errors"`
	Normalized Resource `json:"normalized"`
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
	resource, errs, _ := Normalize(resource)
	return resource, errs
}

func ValidateDetailed(resource Resource) ValidationResult {
	normalized, errs, warnings := Normalize(resource)
	return ValidationResult{
		Valid:      len(errs) == 0,
		Warnings:   warnings,
		Errors:     errs,
		Normalized: normalized,
	}
}

func Normalize(resource Resource) (Resource, []string, []string) {
	var errs []string
	var warnings []string

	resource.ID = strings.TrimSpace(resource.ID)
	resource.Name = strings.TrimSpace(resource.Name)
	resource.Title = strings.TrimSpace(resource.Title)
	if resource.Title == "" {
		resource.Title = resource.Name
	}
	if resource.Name == "" {
		resource.Name = resource.Title
	}
	resource.Status = strings.ToLower(strings.TrimSpace(resource.Status))
	if resource.Status == "" {
		resource.Status = "active"
	}
	if resource.Status != "active" && resource.Status != "disabled" && resource.Status != "inactive" {
		errs = append(errs, "resource status must be active or disabled")
	}

	if resource.ID == "" {
		errs = append(errs, "resource id is required")
	}
	if resource.Title == "" {
		errs = append(errs, "resource title is required")
		errs = append(errs, "resource name is required")
	}
	if len(resource.Domains) == 0 {
		errs = append(errs, "at least one domain is required")
	}
	if len(resource.EntryURLs) == 0 {
		resource.EntryURLs = append(resource.EntryURLs, resource.SampleURLs...)
	}
	if len(resource.EntryURLs) == 0 && len(resource.SampleURLs) > 0 {
		resource.EntryURLs = append(resource.EntryURLs, resource.SampleURLs...)
	}
	if len(resource.SampleURLs) == 0 {
		resource.SampleURLs = append(resource.SampleURLs, resource.EntryURLs...)
	}
	legacyShape := len(resource.EntryURLs) == 0 && len(resource.SampleURLs) == 0 && resource.Title == resource.Name

	resource.HTTPMethods, errs = normalizeHTTPMethods(resource.HTTPMethods, errs)
	resource.CookiePolicy = normalizeCookiePolicy(resource.CookiePolicy)

	seenDomains := map[string]bool{}
	for i := range resource.Domains {
		resource.Domains[i].Host = normalizeHost(resource.Domains[i].Host)
		resource.Domains[i].Behavior = strings.ToLower(strings.TrimSpace(resource.Domains[i].Behavior))
		if resource.Domains[i].Behavior != "" {
			resource.Domains[i].Action = actionForBehavior(resource.Domains[i].Behavior)
			resource.Domains[i].Match = "exact"
			if resource.Domains[i].IncludeSubdomains {
				resource.Domains[i].Match = "subdomain"
			}
		}
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
		if resource.Domains[i].Behavior == "" {
			resource.Domains[i].Behavior = behaviorForActionRole(resource.Domains[i].Action, resource.Domains[i].Role)
		}
		resource.Domains[i].IncludeSubdomains = resource.Domains[i].Match == "subdomain"
		resource.Domains[i].Reason = strings.TrimSpace(resource.Domains[i].Reason)
		resource.Domains[i].Notes = strings.TrimSpace(resource.Domains[i].Notes)
		key := resource.Domains[i].Host + "|" + resource.Domains[i].Match
		if seenDomains[key] {
			warnings = append(warnings, fmt.Sprintf("domains[%d] duplicates an earlier domain rule", i))
		}
		seenDomains[key] = true
		errs = append(errs, validateDomainRule(i, resource.Domains[i])...)
	}

	for i, entry := range resource.EntryURLs {
		parsed, err := url.Parse(entry)
		if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
			errs = append(errs, fmt.Sprintf("entry_urls[%d] must be a valid HTTP or HTTPS URL", i))
		} else if parsed.Scheme == "http" {
			warnings = append(warnings, fmt.Sprintf("entry_urls[%d] uses HTTP; HTTPS is preferred", i))
		}
	}
	if len(resource.EntryURLs) == 0 && !legacyShape {
		errs = append(errs, "at least one entry_url is required")
	}
	for i := range resource.RequestHeaderRules {
		resource.RequestHeaderRules[i].Name = strings.TrimSpace(resource.RequestHeaderRules[i].Name)
		resource.RequestHeaderRules[i].Action = strings.ToLower(strings.TrimSpace(resource.RequestHeaderRules[i].Action))
		resource.RequestHeaderRules[i].Phase = strings.ToLower(strings.TrimSpace(resource.RequestHeaderRules[i].Phase))
		if resource.RequestHeaderRules[i].Phase == "" {
			resource.RequestHeaderRules[i].Phase = "request"
		}
		if resource.RequestHeaderRules[i].Name == "" {
			errs = append(errs, fmt.Sprintf("request_header_rules[%d].name is required", i))
		}
		if resource.RequestHeaderRules[i].Action != "remove" && resource.RequestHeaderRules[i].Action != "preserve" {
			errs = append(errs, fmt.Sprintf("request_header_rules[%d].action must be remove or preserve", i))
		}
		if resource.RequestHeaderRules[i].Phase != "request" && resource.RequestHeaderRules[i].Phase != "response" {
			errs = append(errs, fmt.Sprintf("request_header_rules[%d].phase must be request or response", i))
		}
	}

	return resource, errs, warnings
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
		errs = append(errs, fmt.Sprintf("domains[%d].role must be content, asset, api, auth, redirect, cookie, external, blocked, or unknown", i))
	}
	if !validAction(rule.Action) {
		errs = append(errs, fmt.Sprintf("domains[%d].action must be proxy, allow, or block", i))
	}
	if !validBehavior(rule.Behavior) {
		errs = append(errs, fmt.Sprintf("domains[%d].behavior must be proxy, cookie_domain, redirect_only, block, or external_allow", i))
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
		resource, _ = Validate(resource)
		for _, rule := range resource.Domains {
			rule = normalizeDomainRule(rule)
			if matches(host, rule) {
				matched := rule
				candidate := matchCandidate{resourceID: resource.ID, rule: matched, methods: resource.HTTPMethods, headerRules: resource.RequestHeaderRules}
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
	resourceID  string
	rule        DomainRule
	methods     []string
	headerRules []RequestHeaderRule
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
		Allowed:            !blocked,
		Blocked:            blocked,
		Host:               host,
		ResourceID:         c.resourceID,
		RuleHost:           matched.Host,
		RuleMatch:          matched.Match,
		Role:               matched.Role,
		Action:             matched.Action,
		Behavior:           matched.Behavior,
		Matched:            &matched,
		Reason:             reason,
		HTTPMethods:        c.methods,
		RequestHeaderRules: c.headerRules,
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
	rule.Behavior = strings.ToLower(strings.TrimSpace(rule.Behavior))
	if rule.Behavior != "" {
		rule.Action = actionForBehavior(rule.Behavior)
		if rule.IncludeSubdomains {
			rule.Match = "subdomain"
		}
	}
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
	if rule.Behavior == "" {
		rule.Behavior = behaviorForActionRole(rule.Action, rule.Role)
	}
	rule.IncludeSubdomains = rule.Match == "subdomain"
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
	case "content", "asset", "api", "auth", "redirect", "cookie", "unknown", "external", "blocked":
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

func validBehavior(behavior string) bool {
	switch behavior {
	case "proxy", "cookie_domain", "redirect_only", "block", "external_allow":
		return true
	default:
		return false
	}
}

func actionForBehavior(behavior string) string {
	switch behavior {
	case "proxy":
		return "proxy"
	case "block":
		return "block"
	case "redirect_only", "external_allow", "cookie_domain":
		return "allow"
	default:
		return ""
	}
}

func behaviorForActionRole(action, role string) string {
	switch {
	case action == "block" || role == "blocked":
		return "block"
	case role == "external":
		return "external_allow"
	case role == "redirect":
		return "redirect_only"
	case role == "cookie":
		return "cookie_domain"
	default:
		return "proxy"
	}
}

func normalizeHTTPMethods(methods []string, errs []string) ([]string, []string) {
	if len(methods) == 0 {
		methods = []string{"GET", "HEAD", "POST"}
	}
	valid := map[string]bool{"GET": true, "HEAD": true, "POST": true, "PUT": true, "PATCH": true, "OPTIONS": true, "DELETE": true}
	seen := map[string]bool{}
	var out []string
	for _, method := range methods {
		method = strings.ToUpper(strings.TrimSpace(method))
		if !valid[method] {
			errs = append(errs, fmt.Sprintf("http_methods contains unsupported method %q", method))
			continue
		}
		if !seen[method] {
			out = append(out, method)
			seen[method] = true
		}
	}
	return out, errs
}

func normalizeCookiePolicy(policy CookiePolicy) CookiePolicy {
	policy.JarScope = strings.ToLower(strings.TrimSpace(policy.JarScope))
	if policy.JarScope == "" {
		policy.JarScope = "resource"
	}
	for i := range policy.AllowedCookieDomains {
		policy.AllowedCookieDomains[i] = normalizeHost(policy.AllowedCookieDomains[i])
	}
	return policy
}

func MethodAllowed(result TestResult, method string) bool {
	method = strings.ToUpper(strings.TrimSpace(method))
	methods := result.HTTPMethods
	if len(methods) == 0 {
		methods = []string{"GET", "HEAD", "POST"}
	}
	for _, allowed := range methods {
		if allowed == method {
			return true
		}
	}
	return false
}

func RequestHeaderRemovals(rules []RequestHeaderRule) []string {
	var out []string
	for _, rule := range rules {
		if strings.EqualFold(rule.Phase, "request") && strings.EqualFold(rule.Action, "remove") && strings.TrimSpace(rule.Name) != "" {
			out = append(out, strings.TrimSpace(rule.Name))
		}
	}
	return out
}
