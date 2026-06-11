# Adding Resources in Odo

This guide is for library systems staff, e-resource librarians, and access services staff who manage licensed resources in Odo. It assumes you know the resource your library licenses, but it does not assume you know proxy rewrite rules, browser cookies, or HTTP headers.

## What is an Odo resource?

An Odo resource is a JSON record that tells Odo which vendor sites are allowed through the proxy and how those sites should be handled.

A resource usually includes:

- A title users and staff can recognize.
- One or more entry URLs, such as the vendor home page or search page.
- One or more domains that Odo is allowed to proxy.
- Optional rules for cookies, request headers, anonymous asset URLs, and content rewriting.

Odo is default-deny. If a domain is not in a resource, Odo will not proxy it.

## Before you start

Gather the basic information first:

- The resource name, such as "Example Journals".
- The main vendor URL you expect users to open first.
- The vendor domains shown in the browser address bar during normal use.
- A few test URLs, such as a search page, article page, PDF page, video page, or sign-in redirect.
- Any known vendor notes from your license, support ticket, or implementation guide.

Use a test account or staff account when possible. Keep the first version small, then add domains only when testing shows Odo needs them.

## Quick add: simple resource

For most resources, start in `/admin` with the Resource Config Builder:

1. Open `/admin`.
2. Go to **Resources**.
3. Enter a resource ID, title, and entry URL.
4. Add the main domain from the entry URL.
5. Leave the default methods and cookie policy enabled.
6. Select **Generate JSON**.
7. Select **Validate JSON**.
8. If validation passes, select **Save as Resource**.
9. Use **Proxy Test** and **Diagnostics** to test the entry URL and a few real pages.

Simple generic example:

```json
{
  "id": "example-journals",
  "title": "Example Journals",
  "status": "active",
  "entry_urls": [
    "https://www.example-journals.com/"
  ],
  "http_methods": [
    "GET",
    "HEAD",
    "POST"
  ],
  "cookie_policy": {
    "enabled": true,
    "jar_scope": "resource",
    "allowed_cookie_domains": [
      "example-journals.com"
    ]
  },
  "domains": [
    {
      "host": "www.example-journals.com",
      "behavior": "proxy",
      "include_subdomains": false,
      "role": "content"
    },
    {
      "host": "example-journals.com",
      "behavior": "cookie_domain",
      "include_subdomains": true,
      "role": "cookie"
    }
  ],
  "compatibility": {
    "referer_recovery": true,
    "js_shim": true,
    "app_data_recovery": true
  }
}
```

## What the main fields mean

- `id`: A short stable name for Odo and API use. Use lowercase letters, numbers, and hyphens.
- `title`: The human-readable resource name.
- `status`: Use `active` when ready. Use `disabled` or `inactive` to keep a resource saved but unavailable.
- `entry_urls`: Starting URLs for users and staff testing.
- `http_methods`: Request types Odo may send to the vendor.
- `cookie_policy`: How Odo stores vendor cookies for proxied browsing.
- `domains`: Vendor hosts that Odo may proxy, allow, or block.
- `request_header_rules`: Optional changes to outbound request headers.
- `anonymous_url_rules`: Narrow public proxy allowances for specific asset URLs.
- `content_rewrite_rules`: Explicit text substitutions for difficult pages or scripts.
- `compatibility`: Odo browser compatibility flags.
- `sample_urls`: Optional URLs that are useful for testing.

## Domain behaviors

Domain behavior tells Odo what to do when a URL matches a host.

- `proxy`: Odo may fetch this host through the proxy.
- `cookie_domain`: The host may be used when deciding which vendor cookies belong with the resource.
- `redirect_only`: Odo may allow redirects involving this host without treating it as normal content.
- `block`: Odo should block this host even if another broader rule might allow it.
- `external_allow`: Links may leave Odo without being treated as proxy failures.

Use `proxy` for the main site. Use `cookie_domain` for a base domain when the vendor sets cookies there. Use `block` for known unwanted tracking or unrelated hosts.

## Include subdomains

`include_subdomains` controls whether a domain rule also matches hosts below it.

For example, this rule matches `www.example.com`, `assets.example.com`, and `login.example.com`:

```json
{
  "host": "example.com",
  "behavior": "proxy",
  "include_subdomains": true,
  "role": "content"
}
```

Use subdomain matching only when the vendor owns and uses many related subdomains. If you are not sure, start with the exact host and add more hosts after testing.

## Roles

Roles describe why a domain is present. They make diagnostics easier to understand.

Common roles are:

- `content`: Main pages, articles, search, PDFs, and other core resource content.
- `asset`: Images, scripts, fonts, stylesheets, or media needed by the main site.
- `api`: Vendor API or data URLs used by modern pages.
- `auth`: Vendor authentication or session-check URLs.
- `redirect`: Hosts used mainly for redirects.
- `cookie`: Domains used for vendor cookie scope.
- `external`: Sites users may leave to.
- `blocked`: Hosts intentionally blocked.
- `unknown`: A temporary label when you have not identified the host yet.

## HTTP methods

HTTP methods describe the kinds of requests Odo will allow.

Safe starting methods:

```json
[
  "GET",
  "HEAD",
  "POST"
]
```

`GET` loads pages and assets. `HEAD` checks metadata. `POST` is needed for many searches, forms, and sign-in flows. Add `PUT`, `PATCH`, `OPTIONS`, or `DELETE` only when vendor testing shows they are required.

## Request header rules

Headers are small pieces of request metadata sent to the vendor. Most resources do not need custom header rules.

Some vendors behave better when `X-Requested-With` is removed from outbound requests:

```json
"request_header_rules": [
  {
    "name": "X-Requested-With",
    "action": "remove",
    "phase": "request"
  }
]
```

Use header rules only for a known problem or a known vendor requirement.

## Cookie policy

Odo stores vendor cookies server-side for proxied browsing. The user's browser receives an Odo session cookie, while vendor cookies stay with Odo.

Recommended starting policy:

```json
"cookie_policy": {
  "enabled": true,
  "jar_scope": "resource",
  "allowed_cookie_domains": [
    "example.com"
  ]
}
```

Set `allowed_cookie_domains` to the vendor's base domain when the vendor uses cookies across several hosts. Keep the list narrow.

## Anonymous URL rules

Anonymous URL rules allow specific URLs through Odo without a normal logged-in resource session. They are useful for public assets that a vendor page requires, such as a public image or video host.

Keep these rules narrow:

```json
"anonymous_url_rules": [
  {
    "pattern": "https://cms-films.economist.com/*",
    "behavior": "allow_public_proxy",
    "methods": [
      "GET",
      "HEAD"
    ],
    "notes": "Public CMS film assets"
  }
]
```

Do not use anonymous rules for broad vendor access.

## Content rewrite rules

Content rewrite rules are explicit find-and-replace rules for response bodies. They can help when a vendor hard-codes a URL that Odo cannot otherwise rewrite.

Use them sparingly. They can be brittle because vendor pages and scripts change.

Example:

```json
"content_rewrite_rules": [
  {
    "content_types": [
      "text/html",
      "application/javascript",
      "text/javascript"
    ],
    "find": "https://www.example.com/",
    "replace": "{proxy_url:https://www.example.com/}"
  }
]
```

Useful replacement tokens include:

- `{proxy_url:https://www.example.com/}` for an HTTPS proxied URL.
- `{proxy_http_url:https://www.example.com/}` when the page contains an HTTP URL that should still route through Odo.
- `{proxy_base_url}` for Odo's public base URL.
- `{target_origin}` for the current upstream origin.
- `{proxy_host_suffix}` for host suffix rewriting cases.

## Testing a resource

After saving, test in this order:

1. Use **Proxy Test** with the entry URL.
2. Open the entry URL through Odo.
3. Try a search.
4. Open a detail page, article page, or media page.
5. Try a PDF or download if the resource has one.
6. Check **Diagnostics** for blocked hosts, missed rewrites, or upstream errors.
7. Add only the domains or rules that testing shows are needed.
8. Validate and save again.

Retest after each change so you know which rule fixed or changed behavior.

## Common problems

- Validation says a domain is unsafe: Use a plain host like `www.example.com`. Do not include `https://`, paths, wildcards, ports, localhost names, or IP addresses.
- The home page works but search does not: The vendor may use a separate API host. Check Diagnostics and browser DevTools Network, then add the specific host if needed.
- Images or scripts are missing: Add the specific asset host with role `asset` if diagnostics show it is blocked.
- A page redirects away from Odo: Add the redirect host as `redirect_only` or proxy the exact host if it must stay inside Odo.
- Login or session state does not stick: Check `cookie_policy.allowed_cookie_domains` and add the vendor's base cookie domain if appropriate.
- A modern page shell loads but content is blank: Try compatibility flags and inspect missed rewrites before adding broad domains.
- A content rewrite rule stops working: The vendor may have changed its page or script text. Make the rule narrower and retest.

## Safe defaults

Use these defaults unless testing shows a reason to change them:

- Start with one entry URL.
- Start with the exact main domain.
- Enable cookies with `jar_scope` set to `resource`.
- Allow `GET`, `HEAD`, and `POST`.
- Enable `referer_recovery`, `js_shim`, and `app_data_recovery`.
- Keep anonymous URL rules narrow.
- Avoid content rewrite rules unless a specific hard-coded URL is causing a failure.
- Prefer specific hosts over broad subdomain rules.

## Recommended workflow

1. Add the smallest working resource in the builder.
2. Generate JSON.
3. Validate JSON.
4. Save the resource.
5. Test the entry URL in Proxy Test.
6. Browse through Odo as a user would.
7. Review Diagnostics and missed rewrites.
8. Add one domain or rule at a time.
9. Validate and save after each change.
10. Export JSON when the resource is working so it can be reviewed or kept with other configuration.

## JSTOR-style example

This example shows a larger scholarly resource with an entry URL, several main domains, cookie policy, `X-Requested-With` removal, and compatibility flags.

```json
{
  "id": "jstor-style",
  "title": "JSTOR Style Resource",
  "status": "active",
  "entry_urls": [
    "https://www.jstor.org/"
  ],
  "http_methods": [
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "PATCH",
    "OPTIONS",
    "DELETE"
  ],
  "cookie_policy": {
    "enabled": true,
    "jar_scope": "resource",
    "allowed_cookie_domains": [
      "jstor.org"
    ]
  },
  "request_header_rules": [
    {
      "name": "X-Requested-With",
      "action": "remove",
      "phase": "request"
    }
  ],
  "domains": [
    {
      "host": "www.jstor.org",
      "behavior": "proxy",
      "include_subdomains": false,
      "role": "content"
    },
    {
      "host": "jstor.org",
      "behavior": "proxy",
      "include_subdomains": true,
      "role": "content"
    },
    {
      "host": "links.jstor.org",
      "behavior": "redirect_only",
      "include_subdomains": false,
      "role": "redirect"
    }
  ],
  "compatibility": {
    "referer_recovery": true,
    "js_shim": true,
    "app_data_recovery": true
  },
  "sample_urls": [
    "https://www.jstor.org/stable/example"
  ]
}
```

## Economist-style example

This example shows a modern news resource with an anonymous URL rule, content rewrite rule, cookie domain, and JavaScript rewriting flag.

```json
{
  "id": "economist-style",
  "title": "Economist Style Resource",
  "status": "active",
  "entry_urls": [
    "https://www.economist.com/"
  ],
  "http_methods": [
    "GET",
    "HEAD",
    "POST"
  ],
  "cookie_policy": {
    "enabled": true,
    "jar_scope": "resource",
    "allowed_cookie_domains": [
      "economist.com"
    ]
  },
  "domains": [
    {
      "host": "www.economist.com",
      "behavior": "proxy",
      "include_subdomains": false,
      "role": "content",
      "rewrite_javascript": true
    },
    {
      "host": "economist.com",
      "behavior": "cookie_domain",
      "include_subdomains": true,
      "role": "cookie"
    }
  ],
  "anonymous_url_rules": [
    {
      "pattern": "https://cms-films.economist.com/*",
      "behavior": "allow_public_proxy",
      "methods": [
        "GET",
        "HEAD"
      ],
      "notes": "Public CMS film assets"
    }
  ],
  "content_rewrite_rules": [
    {
      "content_types": [
        "text/html",
        "application/javascript",
        "text/javascript"
      ],
      "find": "https://www.economist.com/",
      "replace": "{proxy_url:https://www.economist.com/}"
    }
  ],
  "compatibility": {
    "referer_recovery": true,
    "js_shim": true,
    "app_data_recovery": true,
    "javascript_text_rewriting": true
  }
}
```
