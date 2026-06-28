# Converting an EZproxy Stanza to an Odo Resource JSON Entry

This guide explains how to translate an EZproxy-style stanza into an Odo resource JSON entry.

Odo does **not** aim to be a line-for-line EZproxy clone. Instead, the goal is to preserve the operational intent of a stanza in a structured, inspectable, API-managed JSON object.

Use this guide when converting vendor configurations such as JSTOR, EBSCOhost, The Economist, Project MUSE, ProQuest, publisher platforms, media resources, or other licensed resources.

## Core idea

An EZproxy stanza is usually a compact set of directives that tells EZproxy:

- where the user starts
- which hosts should be proxied
- which domains participate in cookie rewriting
- which URLs may be proxied without authentication
- which URLs should never be proxied
- which request headers should be removed or modified
- which text substitutions should happen in HTML, JavaScript, or URLs
- which HTTP methods are allowed
- which compatibility behaviors are needed

An Odo resource JSON entry makes those behaviors explicit.

Instead of this:

```text
Title JSTOR
URL https://www.jstor.org/
HJ www.jstor.org
DJ jstor.org
Option Cookie
HTTPHeader -request -process X-Requested-With
```

Odo uses structured JSON such as:

```json
{
  "id": "jstor",
  "title": "JSTOR",
  "status": "active",
  "entry_urls": ["https://www.jstor.org/"],
  "domains": [
    {
      "host": "www.jstor.org",
      "behavior": "proxy",
      "include_subdomains": false,
      "role": "content"
    },
    {
      "host": "jstor.org",
      "behavior": "cookie_domain",
      "include_subdomains": true,
      "role": "cookie"
    }
  ],
  "cookie_policy": {
    "enabled": true,
    "jar_scope": "resource",
    "allowed_cookie_domains": ["jstor.org"]
  },
  "request_header_rules": [
    {
      "name": "X-Requested-With",
      "action": "remove",
      "phase": "request"
    }
  ]
}
```

## Recommended workflow

Do not try to perfectly translate every line on the first pass.

Use this workflow:

1. Identify the resource title.
2. Identify the main entry URL.
3. Add the primary proxied host.
4. Add host/domain rules from `HJ` and `DJ`.
5. Add blocked hosts from `NeverProxy`.
6. Add cookie policy from `Option Cookie`.
7. Add allowed methods from `HTTPMethod`.
8. Add request header rules from `HTTPHeader`.
9. Add anonymous/public asset rules from `AnonymousURL`.
10. Add content rewrite rules from `Find` / `Replace`.
11. Add notes for anything Odo cannot yet express.
12. Validate the JSON.
13. Save the resource.
14. Test using the Resources tab and Proxy Test.
15. Review missed rewrites and diagnostics.
16. Iterate.

## Minimal Odo resource shape

A basic Odo resource looks like this:

```json
{
  "id": "example-resource",
  "title": "Example Resource",
  "status": "active",
  "entry_urls": ["https://www.example.com/"],
  "http_methods": ["GET", "HEAD", "POST"],
  "domains": [
    {
      "host": "www.example.com",
      "behavior": "proxy",
      "include_subdomains": false,
      "role": "content"
    }
  ]
}
```

For complex vendors, add optional fields:

```json
{
  "cookie_policy": {},
  "request_header_rules": [],
  "anonymous_url_rules": [],
  "content_rewrite_rules": [],
  "compatibility": {},
  "tags": [],
  "notes": "",
  "license": {}
}
```

## Directive mapping reference

The following table gives the usual translation from EZproxy stanza directives to Odo JSON fields.

| EZproxy directive | Odo JSON field | Notes |
|---|---|---|
| `Title ...` | `title` | Human-readable resource name. |
| `URL ...` | `entry_urls[]` | Main launch URL. Prefer HTTPS. |
| `HJ ...` | `domains[]` with `behavior: "proxy"` | Host should be proxied. |
| `DJ ...` | `cookie_policy.allowed_cookie_domains[]` and/or `domains[]` with `behavior: "cookie_domain"` | Domain participates in cookie/domain rewriting. |
| `NeverProxy ...` | `domains[]` with `behavior: "block"` | Explicit block. Block rules should win. |
| `AnonymousURL ...` | `anonymous_url_rules[]` | Narrow unauthenticated/public proxy allowance. |
| `HTTPMethod ...` | `http_methods[]` | Add non-default methods such as `PUT`, `PATCH`, `OPTIONS`, `DELETE`. |
| `Option Cookie` | `cookie_policy.enabled: true` | Use Odo server-side cookie handling. |
| `HTTPHeader -request -process ...` | `request_header_rules[]` | Usually maps to removing a request header before proxying. |
| `Find ...` / `Replace ...` | `content_rewrite_rules[]` | Explicit text replacements. Use sparingly. |
| `ProxyHostnameEdit ...` | `proxy_hostname_edits[]` or notes | Mostly relevant to virtual-host proxying; may require future Odo support. |
| `AddUserHeader ...` | `user_header_rules[]` | Releases user identity to vendor. Disable by default unless reviewed. |
| `Option MetaEZproxyRewriting` | `compatibility.meta_ezproxy_rewriting: true` | Odo may only partially support this behavior. |
| `Option NoMetaEZproxyRewriting` | `compatibility.meta_ezproxy_rewriting: false` or notes | Marks end/disable of this behavior. |
| `IncludeFile ...` | `compatibility` or notes | Convert manually if it affects cookies, banners, or rewrites. |

## Naming the resource ID

Use a stable, lowercase, machine-readable ID.

Good examples:

```text
jstor
jstor-aluka
ebscohost
economist
project-muse
proquest
```

Avoid spaces, punctuation, and dates in the ID.

The vendor update date should go in `source.updated` or `notes`, not in the ID.

## Translating `Title`

EZproxy:

```text
Title EBSCOhost (updated 20260608)
```

Odo:

```json
{
  "id": "ebscohost",
  "title": "EBSCOhost",
  "source": {
    "type": "ezproxy_stanza",
    "updated": "2026-06-08"
  }
}
```

Keep the display title clean. Put update dates in metadata.

## Translating `URL`

EZproxy:

```text
URL https://search.ebscohost.com/login.aspx
```

Odo:

```json
{
  "entry_urls": [
    "https://search.ebscohost.com/login.aspx"
  ]
}
```

If a stanza has more than one useful start URL, include multiple `entry_urls`.

## Translating `HJ`

`HJ` lines usually identify hosts that should be proxied.

EZproxy:

```text
HJ https://www.jstor.org
HJ www.jstor.org
HJ dfr.jstor.org
HJ plants.jstor.org
```

Odo:

```json
{
  "domains": [
    {
      "host": "www.jstor.org",
      "behavior": "proxy",
      "include_subdomains": false,
      "role": "content",
      "notes": "Normalized from EZproxy HJ directive."
    },
    {
      "host": "dfr.jstor.org",
      "behavior": "proxy",
      "include_subdomains": false,
      "role": "content",
      "notes": "Normalized from EZproxy HJ directive."
    },
    {
      "host": "plants.jstor.org",
      "behavior": "proxy",
      "include_subdomains": false,
      "role": "content",
      "notes": "Normalized from EZproxy HJ directive."
    }
  ]
}
```

Normalize `https://www.example.com` and `www.example.com` to the same host.

Do not duplicate hosts unless there is a behavior difference.

## Translating `DJ`

`DJ` lines usually describe domains involved in cookie or domain rewriting.

EZproxy:

```text
DJ jstor.org
DJ ebscohost.com
```

Odo:

```json
{
  "cookie_policy": {
    "enabled": true,
    "jar_scope": "resource",
    "allowed_cookie_domains": [
      "jstor.org",
      "ebscohost.com"
    ]
  },
  "domains": [
    {
      "host": "jstor.org",
      "behavior": "cookie_domain",
      "include_subdomains": true,
      "role": "cookie",
      "notes": "Normalized from EZproxy DJ directive."
    }
  ]
}
```

If a `DJ` domain is also a proxied host, it may not need a duplicate `domains[]` entry. It should still appear in `cookie_policy.allowed_cookie_domains`.

## Translating `NeverProxy`

`NeverProxy` means Odo should not proxy that host or pattern.

EZproxy:

```text
NeverProxy viewer.ebscohost.com
NeverProxy *.ebsco-assets.com
```

Odo:

```json
{
  "domains": [
    {
      "host": "viewer.ebscohost.com",
      "behavior": "block",
      "include_subdomains": false,
      "role": "unknown",
      "notes": "Normalized from EZproxy NeverProxy directive."
    },
    {
      "host": "ebsco-assets.com",
      "behavior": "block",
      "include_subdomains": true,
      "role": "unknown",
      "notes": "Normalized from EZproxy NeverProxy wildcard directive."
    }
  ]
}
```

Explicit block rules should always win over proxy or cookie rules.

## Translating `Option Cookie`

EZproxy:

```text
Option Cookie
```

Odo:

```json
{
  "cookie_policy": {
    "enabled": true,
    "jar_scope": "resource",
    "allowed_cookie_domains": ["example.com"]
  }
}
```

Use `jar_scope: "resource"` for most licensed resources.

This keeps cookies scoped to that resource instead of mixing cookies across unrelated vendors.

## Translating `HTTPMethod`

EZproxy:

```text
HTTPMethod PUT
HTTPMethod PATCH
HTTPMethod OPTIONS
HTTPMethod DELETE
```

Odo:

```json
{
  "http_methods": [
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "PATCH",
    "OPTIONS",
    "DELETE"
  ]
}
```

Odo should default to:

```json
["GET", "HEAD", "POST"]
```

Only add extra methods when the stanza explicitly requires them.

## Translating `HTTPHeader -request -process`

EZproxy:

```text
HTTPHeader -request -process Authorization
HTTPHeader -request -process X-Requested-With
```

Odo:

```json
{
  "request_header_rules": [
    {
      "name": "Authorization",
      "action": "remove",
      "phase": "request"
    },
    {
      "name": "X-Requested-With",
      "action": "remove",
      "phase": "request"
    }
  ]
}
```

This tells Odo to remove those headers before constructing the outbound vendor request.

Be cautious with identity, authorization, and token headers. Removing them may be necessary for vendor compatibility, but preserving or injecting them can have privacy/security consequences.

## Translating `AnonymousURL`

`AnonymousURL` allows narrow public or unauthenticated proxy access for matching URLs.

EZproxy:

```text
AnonymousURL https://ppws.ebsco-content.com/*
AnonymousURL +https://apis.ebsco.com/public/*
AnonymousURL -*
```

Odo:

```json
{
  "anonymous_url_rules": [
    {
      "pattern": "https://ppws.ebsco-content.com/*",
      "behavior": "allow_public_proxy",
      "methods": ["GET", "HEAD"],
      "notes": "Normalized from EZproxy AnonymousURL."
    },
    {
      "pattern": "https://apis.ebsco.com/public/*",
      "behavior": "allow_public_proxy",
      "methods": ["GET", "HEAD"],
      "notes": "Normalized from EZproxy AnonymousURL +."
    }
  ]
}
```

Important rules:

- Keep anonymous rules narrow.
- Prefer HTTPS only.
- Allow only `GET` and `HEAD` unless there is a strong reason.
- Do not use broad patterns such as `https://*/*`.
- Anonymous rules must never bypass admin API authentication.
- Anonymous rules should apply only to proxy/data-plane requests.

`AnonymousURL -*` usually means the anonymous block is closed. In Odo JSON, represent only the positive rules that should remain active.

## Translating `Find` / `Replace`

EZproxy often uses `Find` and `Replace` for hardcoded links inside HTML, JavaScript, XML, or encoded URLs.

EZproxy:

```text
Find https://www.economist.com/
Replace https://^swww.economist.com^/
```

Odo:

```json
{
  "content_rewrite_rules": [
    {
      "content_types": [
        "text/html",
        "application/javascript",
        "text/javascript"
      ],
      "find": "https://www.economist.com/",
      "replace": "{proxy_url:https://www.economist.com/}",
      "notes": "Odo-native rewrite rule based on EZproxy Find/Replace."
    }
  ]
}
```

### Supported Odo rewrite template tokens

Odo supports the following templates only in `content_rewrite_rules[].replace`:

| Token | Meaning |
|---|---|
| `{proxy_url:https://host/path}` | Build the current Odo proxy URL for the target URL. |
| `{urlencoded_proxy_url:https://host/path}` | Build and URL-encode the Odo proxy URL. |
| `{proxy_prefix_url:https}` | Build the path-mode prefix for an HTTPS target (for example, `/odo/https/`). Rendering is rejected in query mode. |
| `{target_origin}` | The current upstream origin. |
| `{proxy_base_url}` | The current proxied base route. |
| `{proxy_host_suffix}` | Future virtual-host mode suffix; may be empty in path mode. |

`proxy_url` and `urlencoded_proxy_url` require an absolute HTTPS URL. Although
`proxy_prefix_url` recognizes `http` as a scheme, Odo's current path router does
not support HTTP upstream targets, so an HTTP prefix cannot be rendered safely.
Query mode also needs the complete target URL encoded as one value and therefore
cannot render a standalone prefix. Do not use a prefix template in either case.

In particular, replacements such as
`proxy.cfm?url=https://{proxy_prefix_url:https}` would produce a malformed URL
shape. The EBSCO sample omits those `proxy.cfm` and `/login` prefix rules; keep
them documented as unsupported until Odo can represent the complete target URL.

## Translating EZproxy replacement tokens

Some EZproxy `Replace` values contain special tokens such as `^A`, `^S`, `^s`, `^p`, `^h`, or `^/`.

Odo does not support raw EZproxy tokens such as `^A`, `^S`, `^s`, `^p`, `^h`,
or `^/`. Do not copy these blindly into Odo JSON.

Instead:

1. Identify what the replacement is trying to do.
2. Convert it to an Odo-native template if possible.
3. Add a note if Odo cannot yet represent it.
4. Remove unsupported templates from importable JSON rather than importing them.

Example:

```text
Find https%3A%2F%2Fapis.ebsco.com
Replace https%3A%2F%2F^Sapis.ebsco.com^
```

Possible Odo approximation:

```json
{
  "content_types": ["text/html", "application/javascript", "application/json"],
  "find": "https%3A%2F%2Fapis.ebsco.com",
  "replace": "{urlencoded_proxy_url:https://apis.ebsco.com}",
  "notes": "Approximation of EZproxy encoded replacement. Verify against current Odo template support."
}
```

## Translating `AddUserHeader`

EZproxy:

```text
AddUserHeader -base64 X-EBSCO-PROXY-Username
```

Odo draft:

```json
{
  "user_header_rules": [
    {
      "name": "X-EBSCO-PROXY-Username",
      "phase": "request",
      "value_template": "{username}",
      "encoding": "base64",
      "enabled": false,
      "notes": "Disabled by default because it releases user identity to the vendor."
    }
  ]
}
```

This is sensitive.

A user header can release local identity to a vendor. It should be disabled by default unless:

- the license requires it
- local policy permits it
- users are informed where appropriate
- privacy review has happened
- the released identifier is minimized

Prefer pseudonymous or scoped identifiers over direct usernames when possible.

## Translating `ProxyHostnameEdit`

EZproxy:

```text
ProxyHostnameEdit healthlibrary.epnet.com$ healthlibrary-epnet-com
```

Odo draft:

```json
{
  "proxy_hostname_edits": [
    {
      "match": "healthlibrary.epnet.com$",
      "replacement": "healthlibrary-epnet-com",
      "notes": "Requires Odo virtual-host or hostname-edit support."
    }
  ]
}
```

This is usually related to hostname rewriting behavior.

If Odo is running in path mode, this may not have an immediate effect.

Keep it as metadata or a future compatibility instruction unless Odo explicitly supports it.

## Translating `Option MetaEZproxyRewriting`

EZproxy:

```text
Option MetaEZproxyRewriting
...
Option NoMetaEZproxyRewriting
```

Odo draft:

```json
{
  "compatibility": {
    "meta_ezproxy_rewriting": true,
    "notes": "Represents EZproxy meta rewriting behavior for review."
  }
}
```

Odo may only partially support this behavior.

If the stanza enables and later disables the option, document what portion of the stanza it applied to.

## Adding notes and translation metadata

Every converted stanza should include a `source` object.

Example:

```json
{
  "source": {
    "type": "ezproxy_stanza",
    "title": "EBSCOhost",
    "updated": "2026-06-08",
    "translation_status": "draft",
    "translation_notes": [
      "HJ directives normalized into proxy domain rules.",
      "DJ directives normalized into cookie domains.",
      "NeverProxy directives normalized into explicit block rules.",
      "Find/Replace rules require manual validation."
    ]
  }
}
```

This makes it clear whether the JSON is production-ready or a draft.

Recommended `translation_status` values:

```text
draft
testing
validated
production
deprecated
```

## Adding tags, notes, and license metadata

Odo resource configs can include local metadata.

Example:

```json
{
  "tags": [
    "database",
    "journal-platform",
    "vendor-complex",
    "sample"
  ],
  "notes": "Converted from vendor EZproxy stanza. Needs testing before production.",
  "license": {
    "vendor": "EBSCO",
    "status": "",
    "coverage": "",
    "access_model": "licensed",
    "renewal_date": "",
    "erm_id": "",
    "admin_url": "",
    "support_url": "https://support.ebsco.com/"
  }
}
```

These fields are informational. They should not affect proxy behavior unless Odo explicitly implements policy based on them later.

## Domain role suggestions

Use roles to help admins and diagnostics understand why a domain is present.

| Role | Use for |
|---|---|
| `content` | Main site pages and normal content. |
| `asset` | CSS, JS, images, media, CDN-style hosts. |
| `api` | JSON APIs, GraphQL, search endpoints, app data. |
| `auth` | Vendor login/authentication hosts. |
| `redirect` | Hosts used mainly for redirects. |
| `cookie` | Cookie/domain scope rules. |
| `unknown` | Blocked or unclear hosts pending review. |

When unsure, use `unknown` and add a note.

## Complex resource example skeleton

```json
{
  "id": "vendor-example",
  "title": "Vendor Example",
  "status": "active",
  "entry_urls": ["https://search.vendor.example/login"],
  "http_methods": ["GET", "HEAD", "POST", "PUT", "PATCH", "OPTIONS", "DELETE"],
  "cookie_policy": {
    "enabled": true,
    "jar_scope": "resource",
    "allowed_cookie_domains": ["vendor.example"]
  },
  "domains": [
    {
      "host": "search.vendor.example",
      "behavior": "proxy",
      "include_subdomains": false,
      "role": "content",
      "rewrite_javascript": true
    },
    {
      "host": "vendor.example",
      "behavior": "cookie_domain",
      "include_subdomains": true,
      "role": "cookie"
    },
    {
      "host": "tracking.vendor.example",
      "behavior": "block",
      "include_subdomains": false,
      "role": "unknown"
    }
  ],
  "request_header_rules": [
    {
      "name": "X-Requested-With",
      "action": "remove",
      "phase": "request"
    }
  ],
  "anonymous_url_rules": [
    {
      "pattern": "https://assets.vendor.example/public/*",
      "behavior": "allow_public_proxy",
      "methods": ["GET", "HEAD"]
    }
  ],
  "content_rewrite_rules": [
    {
      "content_types": ["text/html", "application/javascript", "text/javascript"],
      "find": "https://search.vendor.example/",
      "replace": "{proxy_url:https://search.vendor.example/}"
    }
  ],
  "compatibility": {
    "referer_recovery": true,
    "js_shim": true,
    "app_data_recovery": true,
    "javascript_text_rewriting": true
  },
  "source": {
    "type": "ezproxy_stanza",
    "translation_status": "draft"
  }
}
```

## Validation checklist

Before saving a converted resource:

- [ ] Resource has a stable `id`.
- [ ] Resource has a clear `title`.
- [ ] `entry_urls` contains at least one URL.
- [ ] Main entry URL uses HTTPS if possible.
- [ ] Duplicate HJ hosts are removed.
- [ ] `HJ` hosts became `proxy` domain rules.
- [ ] `DJ` domains became cookie domains.
- [ ] `NeverProxy` hosts became explicit block rules.
- [ ] `Option Cookie` became `cookie_policy.enabled: true`.
- [ ] Extra `HTTPMethod` values were added only when present.
- [ ] Request header removals were reviewed.
- [ ] Anonymous URL rules are narrow.
- [ ] User identity headers are disabled unless reviewed.
- [ ] Find/Replace rules were converted to Odo-native templates where possible.
- [ ] Unsupported directives are preserved in notes.
- [ ] Resource validates in Odo.
- [ ] Resource launches through Odo.
- [ ] Search and navigation are tested.
- [ ] Browser DevTools shows no obvious missed root-relative paths.
- [ ] Odo missed-rewrite diagnostics are reviewed.
- [ ] Privacy logs do not expose full URLs, query strings, cookies, or credentials.

## Testing after conversion

After saving the resource:

1. Open the Odo admin page.
2. Go to **Resources**.
3. Search for the resource.
4. Select it.
5. Click **Validate**.
6. Click **Test** using the first entry URL.
7. Click **Open Through Proxy**.
8. Browse the homepage.
9. Try search.
10. Try opening an article/result/item.
11. Check browser DevTools Network and Console.
12. Load Odo proxy diagnostics.
13. Load missed rewrites.
14. Add missing domains or rewrite rules only when diagnostics show they are needed.

## Common conversion problems

### Homepage works but search fails

Likely causes:

- missing API domain
- missing app/data route recovery
- request header issue
- cookie policy issue
- hardcoded JavaScript URL

### Articles work but section pages are broken

Likely causes:

- section pages rely more on JavaScript
- missing JS bundle
- missing JSON/data endpoint
- content rewrite rule needed
- path-mode proxy limitation

### Login page loops

Likely causes:

- cookie domain missing
- auth host missing
- redirect target not proxied
- vendor identity flow is blocked by `NeverProxy`
- SAML/OIDC vendor flow needs special handling

### Images/video do not load

Likely causes:

- missing asset host
- `NeverProxy` conflict
- anonymous asset rule needed
- CORS/content-type issue

### User-specific headers appear in the stanza

Treat these as privacy-sensitive.

Do not enable them automatically.

## Privacy rules for converted configs

Odo resource configs should preserve library privacy values.

Default posture:

- Do not release user identity unless required and reviewed.
- Do not log full article URLs by default.
- Do not log query strings by default.
- Do not log search terms.
- Do not log cookies.
- Do not log Authorization headers.
- Keep anonymous URL rules narrow.
- Prefer resource/session diagnostics over patron research trails.

## What not to convert automatically

Some stanza behavior should be reviewed manually:

- `AddUserHeader`
- broad `AnonymousURL` patterns
- complex `Find` / `Replace` token chains
- vendor login/auth flows
- `ProxyHostnameEdit`
- directives that imply identity release
- directives that proxy non-HTTPS content
- wildcard domains covering many unrelated hosts

## Suggested file location

Store converted resources in:

```text
config/resources/{resource-id}.json
```

Examples:

```text
config/resources/jstor.json
config/resources/economist.json
config/resources/ebscohost.json
```

## Suggested commit message

When adding a converted resource:

```text
Add draft Odo resource config for EBSCOhost

- translate HJ/DJ directives to domain rules
- add cookie policy and allowed methods
- add request header removals
- add anonymous URL rules
- preserve unsupported EZproxy directives as notes
```

## Final rule

A stanza conversion is not done when the JSON is created.

It is done when the JSON validates, the resource launches, common user paths work, diagnostics are reviewed, and privacy-sensitive behavior has been checked.
