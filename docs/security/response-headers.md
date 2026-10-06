# Application and vendor response headers

Odo-owned responses (including login, logout, admin, resources, APIs, OpenAPI,
and local errors) receive an application Content-Security-Policy, frame denial,
`nosniff`, a no-referrer policy, and disabled camera, microphone, and geolocation
permissions. The admin CSP authorizes only the compiled-in inline script by its
SHA-256 hash. Other app routes disallow scripts. Inline styles remain permitted
for the existing application layouts. Configure HSTS at the HTTPS terminator.

The application policy stops at the vendor fetch handler. Direct `/odo/...`,
`/odo?url=...`, and silently recovered vendor responses do not receive these
Odo application headers. Authentication failures and redirects generated before
entering that handler remain Odo-owned responses.

Vendor responses retain the existing response-header allowlist. Both upstream
`Content-Security-Policy` and `Content-Security-Policy-Report-Only` are suppressed
for HTML **and non-HTML**, including HEAD responses. This default is not
resource-configurable. No additional upstream headers are removed by the app
policy boundary. Upstream CSP can conflict with path-proxy URL rewriting and
injected compatibility scripts because the browser sees Odo as the origin.

Proxied `text/html` also has `<meta http-equiv="Content-Security-Policy">` and
the report-only counterpart removed by the HTML tokenizer. This is the same
fixed compatibility policy as header suppression, not a per-resource option.
Unrelated meta elements and CSP-like text in scripts/comments are preserved.
Non-HTML bodies are not scanned for meta policies; HEAD has no body to rewrite.
Headers added by a deployment's reverse proxy can still cause browser CSP errors.
The HTML attribute rewriter uses an HTML tokenizer and preserves inline script
text byte-for-byte. JavaScript assignments such as `script.src = src` are not
HTML attributes and are left untouched. Actual tag attributes still undergo URL
rewriting; integrity attributes are removed only on tags that change. Explicit
resource content-rewrite rules remain a separate pass and can still change
script text, invalidating a vendor's script hash.
Those rules run before Odo injects its compatibility shim, so vendor URL
replacements cannot change the shim's origin or base URL.
Suppressing CSP removes a vendor defense-in-depth control: only allowlisted, trusted
resources should be configured, and vendor content should not be considered
isolated from Odo merely because it has a separate header policy.

CSP compatibility handling is not anti-bot bypass. JSTOR, The Economist, and
other vendors may still reject requests because of IP reputation, TLS/browser
fingerprinting, or vendor policy. Odo does not attempt to defeat those systems.

## Operator diagnostics

Use **Diagnostics → Load Proxy Diagnostics** in the admin UI, or the existing
`GET /api/v1/diagnostics/proxy/recent` endpoint with `diagnostics:read` permission.
The bounded in-memory store retains the latest 200 entries and resets on restart.
Each received upstream response records:

- `content_type`: a known media type without parameters, or `other`/`missing`.
- `upstream_csp_present` and `upstream_csp_report_only_present`.
- `csp_removed`: a CSP header or HTML CSP meta element was suppressed.
- `removed_csp_meta_count`: number of CSP meta elements removed from HTML,
  omitted when zero. The upstream CSP presence flags describe HTTP headers only.
- `challenge_path_requested`: the target path starts with `/_fs-ch-` or
  `/cdn-cgi/challenge-platform/`. Only this boolean is recorded, not the path.

Each suppressed header also creates a `response_header_modified` event with
its fixed header name, `action: removed_for_proxy_compatibility`, target host,
resource ID when available, timestamp, and the same safe policy fields. The
events never include CSP values, full URLs, queries, cookies, Authorization,
or request bodies. Other aggregate rewrite diagnostics retain their existing
fields. No new request details are written to application logs.

HTML meta suppression creates one `response_meta_modified` event per response
with the same removal action, target host, resource ID when available, timestamp,
safe content-type label, removal count, and `csp_removed: true`. Policy contents
and page text are never included. A positive meta count with
`upstream_csp_present: false` is expected when the policy was in HTML only.

This applies to HTML, non-HTML, HEAD, and upstream redirects. A challenge-path
flag indicates a request, not successful challenge execution or a confirmed
anti-bot rejection. It can be true even if the fetch fails; CSP/content-type
fields require an upstream response. Odo cannot observe whether a browser
blocked inline scripts before this change. Correlate these signals with the
browser console and deployment headers; do not interpret CSP removal as proof
that a blank-page problem is resolved.
