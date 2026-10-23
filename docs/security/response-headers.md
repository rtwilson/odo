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

## PDF and binary delivery

Vendor requests forward `Range` and `If-Range` through the existing target,
method, and session checks. Responses retain `Content-Disposition`, caching
validators, and cache policy. Untransformed streams also retain `Accept-Ranges`,
`Content-Range`, `Content-Length`, and `Content-Encoding`; upstream 206 status
codes are preserved. Missing Content-Type on a `.pdf` URL defaults to
`application/pdf`. Inline versus attachment behavior remains the vendor's choice.

Odo requests identity encoding to prevent automatic transport decompression.
PDFs, encoded responses, and partial responses stream without text rewriting.
An upstream that ignores identity encoding can therefore return encoded HTML
without URL rewriting. No new resource configuration is required.

## Operator diagnostics

Blocked upstream redirects retain `reason: redirect_to_blocked_target` and
add `redirect_target_host` plus a fixed `redirect_block_reason`:
`target_safety_check_failed`, `explicitly_blocked`, `not_proxyable`,
`no_matching_domain_rule`, or `target_not_allowed`. Signed URLs, paths, query
parameters, and arbitrary rule reasons are excluded. A missing domain rule
requires operator review; Odo does not automatically allow redirect destinations.

The bundled JSTOR profile includes the exact host
`sequoia-cedar.s3.amazonaws.com`, observed as a PDF preview redirect destination
on 2026-10-23. Other S3 buckets and subdomains of that host remain unlisted.
Existing JSTOR installations must merge this rule or reimport the reviewed
profile to use it. Normal login, target validation, and validated-IP dialing
still apply. This enables the observed destination; it does not establish
compatibility with every JSTOR preview or future vendor hosting changes.

### Frames and embedded viewers

Vendor HTML rewrites `iframe src`, `frame src`, `object data`, and `embed src`
through the existing target checks. Relative URLs resolve against the vendor
page. Unapproved hosts and non-HTTP URLs are not made proxyable.

Missed requests with browser destinations `iframe`, `frame`, `object`, or `embed`
are classified as `frame` and silently recovered using the proxied Referer.
They retain target validation, protected app paths, login requirements, and the
server-side vendor cookie jar. Embedded app-data/API responses do not receive
the canonical-navigation redirect. Reserved Odo `/api/` paths remain protected.
Frame recovery diagnostics use `[frame]` instead of a path and omit path
prefixes, canonical URLs, and raw Accept/content-type values.

The vendor response allowlist already suppresses `X-Frame-Options` and both CSP
headers, including `frame-ancestors`; this remains a fixed compatibility policy.
Odo-owned pages retain their application CSP and frame denial.
`proxy_frame_content` events report target host, status, safe MIME type, and the
browser's fixed frame destination when available. Events are also generated
without a destination hint when upstream frame-blocking headers are observed.
`upstream_x_frame_options_present`, `upstream_frame_ancestors_present`,
`x_frame_options_removed`, and `frame_ancestors_removed` describe the decision.
The ancestor flag covers enforced and report-only CSP. Suppression sets
`action: removed_for_proxy_compatibility`; policy values are never recorded.
Browser destination hints are diagnostic inputs, not access authorization.

### JavaScript compatibility

JavaScript MIME types `application/javascript`, `text/javascript`, and
`application/x-javascript` are preserved. Missing MIME on `.js`/`.mjs` URLs
defaults to JavaScript. `application/octet-stream` on those extensions is
corrected only when the resource enables `compatibility.javascript_text_rewriting`.
Explicit binary MIME types are not overridden. Encoded and partial streams
remain unchanged; unencoded text can use the resource's content rewrite rules.
Rules must list the applicable JavaScript MIME type in `content_types`.

`proxy_script_asset` events identify JavaScript by MIME, `.js`/`.mjs` extension,
or a browser `Sec-Fetch-Dest: script` hint. Events contain target host, status,
safe content type, and a `path_kind` of `.js`, `.mjs`, or `other`.
They report MIME fallback/correction, upstream encoding presence, stripped
length, and CSP presence/removal. `referring_integrity` is `unknown`: an asset
request does not reliably identify the referring HTML tag. HTML rewrite
diagnostics separately report `removed_integrity_count`; script and link tags
whose URLs change already have integrity attributes removed by the vendor HTML
rewriter. No filenames, paths, queries, or raw header values enter asset events.

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

PDF streams additionally create a `proxy_pdf_response` event with target host,
upstream status, safe content type, `range_requested`, `partial_content`, and
`content_range_present`. `content_disposition` is only `inline`, `attachment`,
`missing`, or `other`; filenames are excluded. `accept_ranges` is only `bytes`,
`none`, `missing`, or `other`. Raw range values are excluded.
`content_type_missing` and `content_type_corrected` describe MIME fallback.
`delivery_headers_preserved` compares upstream and outgoing disposition, range,
length, encoding, validator, and cache headers; it excludes the intentional CSP
suppression and MIME fallback. False boolean fields may be omitted from JSON.
These events use the existing bounded in-memory store and add no activity logs.

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
