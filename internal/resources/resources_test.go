package resources

import "testing"

func TestValidateDefaultsAndNormalizesResource(t *testing.T) {
	resource, err := Validate(Resource{
		ID:   " jstor ",
		Name: " JSTOR ",
		Domains: []DomainRule{
			{Host: "WWW.JSTOR.ORG.", Role: "content"},
			{Host: "JSTOR.ORG", Match: " SUBDOMAIN "},
		},
		SampleURLs: []string{"https://www.jstor.org/stable/example"},
	})
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}

	if resource.ID != "jstor" {
		t.Fatalf("expected trimmed id, got %q", resource.ID)
	}
	if resource.Name != "JSTOR" {
		t.Fatalf("expected trimmed name, got %q", resource.Name)
	}
	if resource.Status != "active" {
		t.Fatalf("expected default active status, got %q", resource.Status)
	}
	if resource.Domains[0].Host != "www.jstor.org" {
		t.Fatalf("expected normalized exact host, got %q", resource.Domains[0].Host)
	}
	if resource.Domains[0].Match != "exact" {
		t.Fatalf("expected default exact match, got %q", resource.Domains[0].Match)
	}
	if resource.Domains[1].Match != "subdomain" {
		t.Fatalf("expected normalized subdomain match, got %q", resource.Domains[1].Match)
	}
	if resource.Domains[0].Role != "content" || resource.Domains[0].Action != "proxy" {
		t.Fatalf("expected default content/proxy rule, got %#v", resource.Domains[0])
	}
}

func TestValidateExpandedJSTORLikeConfig(t *testing.T) {
	resource, err := Validate(Resource{
		ID:                 "jstor",
		Title:              "JSTOR",
		EntryURLs:          []string{"https://www.jstor.org/"},
		HTTPMethods:        []string{"GET", "HEAD", "POST", "PUT", "PATCH", "OPTIONS", "DELETE"},
		CookiePolicy:       CookiePolicy{Enabled: true, AllowedCookieDomains: []string{"JSTOR.ORG"}},
		RequestHeaderRules: []RequestHeaderRule{{Name: "X-Requested-With", Action: "remove", Phase: "request"}},
		Domains: []DomainRule{
			{Host: "www.jstor.org", Behavior: "proxy", Role: "content"},
			{Host: "jstor.org", Behavior: "proxy", IncludeSubdomains: true, Role: "content"},
		},
	})
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	if resource.Name != "JSTOR" || resource.Title != "JSTOR" {
		t.Fatalf("expected title/name normalization, got %#v", resource)
	}
	if resource.Domains[1].Match != "subdomain" || resource.Domains[1].Action != "proxy" {
		t.Fatalf("expected behavior/subdomain normalization, got %#v", resource.Domains[1])
	}
	if resource.CookiePolicy.JarScope != "resource" || resource.CookiePolicy.AllowedCookieDomains[0] != "jstor.org" {
		t.Fatalf("expected cookie policy normalization, got %#v", resource.CookiePolicy)
	}
}

func TestValidateDetailedDuplicateDomainWarning(t *testing.T) {
	result := ValidateDetailed(Resource{
		ID:        "dup",
		Title:     "Duplicate",
		EntryURLs: []string{"https://example.org/"},
		Domains: []DomainRule{
			{Host: "example.org", Behavior: "proxy"},
			{Host: "example.org", Behavior: "proxy"},
		},
	})
	if !result.Valid || len(result.Warnings) == 0 {
		t.Fatalf("expected valid resource with duplicate warning, got %#v", result)
	}
}

func TestValidateDefaultsActionBasedOnRole(t *testing.T) {
	resource, err := Validate(Resource{
		ID:   "roles",
		Name: "Roles",
		Domains: []DomainRule{
			{Host: "content.example.org"},
			{Host: "external.example.org", Role: "external"},
			{Host: "blocked.example.org", Role: "blocked"},
		},
	})
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}

	if resource.Domains[0].Action != "proxy" {
		t.Fatalf("expected content default action proxy, got %#v", resource.Domains[0])
	}
	if resource.Domains[1].Action != "allow" {
		t.Fatalf("expected external default action allow, got %#v", resource.Domains[1])
	}
	if resource.Domains[2].Action != "block" {
		t.Fatalf("expected blocked default action block, got %#v", resource.Domains[2])
	}
}

func TestValidateRejectsInvalidResources(t *testing.T) {
	tests := []struct {
		name     string
		resource Resource
	}{
		{
			name:     "missing id",
			resource: Resource{Name: "JSTOR"},
		},
		{
			name:     "missing name",
			resource: Resource{ID: "jstor"},
		},
		{
			name: "missing domain host",
			resource: Resource{
				ID:      "jstor",
				Name:    "JSTOR",
				Domains: []DomainRule{{Match: "exact"}},
			},
		},
		{
			name: "invalid match type",
			resource: Resource{
				ID:      "jstor",
				Name:    "JSTOR",
				Domains: []DomainRule{{Host: "www.jstor.org", Match: "contains"}},
			},
		},
		{
			name: "non-HTTPS sample URL",
			resource: Resource{
				ID:         "jstor",
				Name:       "JSTOR",
				SampleURLs: []string{"http://www.jstor.org/stable/example"},
			},
		},
		{
			name: "unknown role",
			resource: Resource{
				ID:      "jstor",
				Name:    "JSTOR",
				Domains: []DomainRule{{Host: "www.jstor.org", Role: "marketing"}},
			},
		},
		{
			name: "unknown action",
			resource: Resource{
				ID:      "jstor",
				Name:    "JSTOR",
				Domains: []DomainRule{{Host: "www.jstor.org", Action: "mirror"}},
			},
		},
		{
			name: "unknown behavior",
			resource: Resource{
				ID:        "jstor",
				Title:     "JSTOR",
				EntryURLs: []string{"https://www.jstor.org/"},
				Domains:   []DomainRule{{Host: "www.jstor.org", Behavior: "mirror"}},
			},
		},
		{
			name: "bad method",
			resource: Resource{
				ID:          "jstor",
				Title:       "JSTOR",
				EntryURLs:   []string{"https://www.jstor.org/"},
				HTTPMethods: []string{"GET", "TRACE"},
				Domains:     []DomainRule{{Host: "www.jstor.org", Behavior: "proxy"}},
			},
		},
		{
			name: "bad header rule",
			resource: Resource{
				ID:                 "jstor",
				Title:              "JSTOR",
				EntryURLs:          []string{"https://www.jstor.org/"},
				Domains:            []DomainRule{{Host: "www.jstor.org", Behavior: "proxy"}},
				RequestHeaderRules: []RequestHeaderRule{{Action: "remove", Phase: "request"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Validate(tt.resource); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestTestURLMatchesExactAndSubdomainRules(t *testing.T) {
	resources := []Resource{
		{
			ID:     "jstor",
			Name:   "JSTOR",
			Status: "active",
			Domains: []DomainRule{
				{Host: "www.jstor.org", Match: "exact"},
				{Host: "jstor.org", Match: "subdomain"},
			},
		},
	}

	exact := TestURL("https://www.jstor.org/stable/example", resources)
	if !exact.Allowed {
		t.Fatalf("expected exact URL to be allowed: %#v", exact)
	}
	if exact.ResourceID != "jstor" {
		t.Fatalf("expected jstor resource, got %q", exact.ResourceID)
	}
	if exact.Matched == nil || exact.Matched.Match != "exact" {
		t.Fatalf("expected exact matched rule, got %#v", exact.Matched)
	}
	if exact.Role != "content" || exact.Action != "proxy" || exact.RuleHost != "www.jstor.org" || exact.RuleMatch != "exact" {
		t.Fatalf("expected match result role/action/rule fields, got %#v", exact)
	}

	subdomain := TestURL("https://about.jstor.org/", resources)
	if !subdomain.Allowed {
		t.Fatalf("expected subdomain URL to be allowed: %#v", subdomain)
	}
	if subdomain.Matched == nil || subdomain.Matched.Match != "subdomain" {
		t.Fatalf("expected subdomain matched rule, got %#v", subdomain.Matched)
	}
}

func TestTestURLExactBeatsSubdomain(t *testing.T) {
	resources := []Resource{
		{
			ID:     "jstor",
			Name:   "JSTOR",
			Status: "active",
			Domains: []DomainRule{
				{Host: "jstor.org", Match: "subdomain", Role: "content", Action: "proxy"},
				{Host: "static.jstor.org", Match: "exact", Role: "asset", Action: "proxy"},
			},
		},
	}

	result := TestURL("https://static.jstor.org/app.css", resources)
	if !result.Allowed || result.RuleHost != "static.jstor.org" || result.Role != "asset" {
		t.Fatalf("expected exact asset rule to win, got %#v", result)
	}
}

func TestTestURLExplicitBlockBeatsBroaderSubdomainProxy(t *testing.T) {
	resources := []Resource{
		{
			ID:     "jstor",
			Name:   "JSTOR",
			Status: "active",
			Domains: []DomainRule{
				{Host: "jstor.org", Match: "subdomain", Role: "content", Action: "proxy"},
				{Host: "tracking.jstor.org", Match: "exact", Role: "blocked", Action: "block"},
			},
		},
	}

	result := TestURL("https://tracking.jstor.org/pixel", resources)
	if result.Allowed || !result.Blocked || result.Action != "block" || result.Reason != "explicitly_blocked" {
		t.Fatalf("expected explicit block to win, got %#v", result)
	}
}

func TestTestURLDeniesInactiveHTTPAndUnknownHosts(t *testing.T) {
	active := []Resource{
		{
			ID:      "jstor",
			Name:    "JSTOR",
			Status:  "active",
			Domains: []DomainRule{{Host: "jstor.org", Match: "subdomain"}},
		},
	}

	if result := TestURL("http://www.jstor.org/stable/example", active); result.Allowed {
		t.Fatalf("expected HTTP URL to be denied: %#v", result)
	}
	if result := TestURL("https://example.org/", active); result.Allowed {
		t.Fatalf("expected unknown host to be denied: %#v", result)
	}

	inactive := []Resource{
		{
			ID:      "jstor",
			Name:    "JSTOR",
			Status:  "inactive",
			Domains: []DomainRule{{Host: "jstor.org", Match: "subdomain"}},
		},
	}
	if result := TestURL("https://www.jstor.org/stable/example", inactive); result.Allowed {
		t.Fatalf("expected inactive resource to be denied: %#v", result)
	}
}
