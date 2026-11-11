# Virtual-host routing foundation

Virtual-host request routing is disabled. Production startup rejects
`APP_PROXY_URL_MODE=virtual_host`; development retains its warning and path-mode
fallback. `APP_EXPERIMENTAL_HANDOFF=true` now enables an isolated authentication
handoff and a first experimental vendor content path in development/test only.
It defaults off and is rejected in production. This is not a deployable
virtual-host proxy mode.

| State | Current behavior |
| --- | --- |
| Implemented | Registry, launch/login continuation, bounded hashed tickets/proofs/grants, live parent/version/resource checks, central confirmation and vendor control HTTP handlers, bounded upstream cookie jars and the live grant/snapshot cookie coordinator. |
| Experimentally available | With the flag, registered vendor hosts serve `GET /.well-known/odo/redeem` and grant-authorized `GET`/`HEAD` vendor content, rewriting only same-host absolute URLs in HTML attributes ([browser compatibility](#browser-compatibility)); see [experimental vendor content delivery](#experimental-vendor-content-delivery). Central launch and confirmation complete the browser handshake. |
| Unsupported | Unsafe methods, JavaScript/CSS rewriting, cross-host HTML rewriting, cross-host redirects and assets, automatic cold-host handoff, anonymous grant-free vendor access, cookie persistence and multi-instance handoff state. |
| Production-disabled | All vendor-host delivery: startup rejects the flag outside development/test. Central path content, diagnostic body previews and missed-rewrite recovery are blocked while the experimental mode is on; validated legacy GET bookmarks redirect to central launch. Default path/query deployments are unchanged when off. |

## Trusted deployment names

`proxy.NewHostRoutingConfig` takes the configured central HTTPS origin and proxy
DNS suffix as explicit inputs. The reconciliation API uses it for
`APP_PUBLIC_URL` and `APP_PROXY_BASE_DOMAIN`. No request or forwarded header
supplies these values.

The central URL must have no credentials, query (including an empty `?`),
fragment (including an empty `#`), or path other than the optional literal `/`.
Names use the existing registry IDNA normalization. Only implicit HTTPS port or
explicit 443 is accepted; IP literals and local names are rejected. The proxy
suffix must leave room for a 54-character generated label and separating dot
within the 253-character DNS name limit. Validation performs no DNS or HTTP
requests. Reconciliation returns 503 for invalid deployment settings.

The central hostname can be outside, at, or beneath the proxy suffix. When it
is beneath the suffix, its exact identity always takes precedence over vendor
candidate classification. Deployments remain responsible for certificates
covering both central and eventual vendor names.

## Authority classification

`HostRoutingConfig.ClassifyAuthority` accepts one HTTP authority string. It
rejects URLs, credentials, whitespace/control bytes, raw Unicode, invalid DNS
names, IP literals, header lists, and ports other than 443. ASCII hostname case,
one terminal dot, and explicit 443 are normalized. IDN requests must use their
ASCII form. The unconfigured zero value rejects all authorities.

There are three outcomes:

| Authority | Result |
| --- | --- |
| Exact normalized central hostname | Central classification |
| One DNS label immediately below the configured proxy suffix | Vendor candidate label |
| Anything else, including the suffix apex unless central | Error |

An arbitrary single-label candidate is **not admitted**. It must later resolve
through exact registry lookup; labels are never decoded into upstream authority.
The opt-in boundary below uses this classifier for central-host admission only.

## Opt-in central host guard

`APP_HOST_GUARD` defaults to false. When enabled, both `APP_PUBLIC_URL` and
`APP_PROXY_BASE_DOMAIN` must pass the configuration validation above. The flag
accepts true/1/yes/on and false/0/no/off, ignoring case and surrounding whitespace.
An unknown flag value is an error. Startup validates this in development and
production; invalid settings stop startup. If a handler is constructed directly
with invalid settings, it rejects requests with generic 503 responses.

At handler construction, the settings are captured. The guard runs after
privacy logging setup and application security headers, but before API-key or
browser-session authentication, cookies, registry lookup, and application
routing. With the experimental flag off, only the configured central authority reaches
those handlers. Vendor candidates, including registered hosts, and unknown or
malformed authorities receive generic 421 responses with no-store. With the
experimental flag on, only the exact vendor redemption path can enter the
separate control handler after registry validation; it never enters the central
mux or API/session middleware. Rejection by the central-only guard creates no cookies or mappings, reads no
application database, and fetches no content. Experimental control admission
requires a registry lookup before any cookie is read.
Rejected requests use a fixed `host_rejected` access-log route instead of their
arbitrary submitted path.

For absolute-form requests, both request Host and URL authority must classify
as the same central hostname, and the absolute URL must use HTTPS without
userinfo or opaque syntax. Equivalent case, terminal dot, and port 443 remain
accepted. Forwarded and X-Forwarded-Host are ignored in both directions: they
cannot admit a rejected Host or override an accepted one.

Enabling the guard does not enable virtual-host routing or isolate vendor
scripts still served through central-origin path mode. Existing path/query
traffic on the central host remains available. Without the opt-in flag,
existing deployments retain their prior host behavior.

Reverse proxies must preserve the external central Host. Health probes using
`127.0.0.1`, localhost, a backend name, or a vendor host will be rejected; send
the configured central Host explicitly. For example:

```sh
curl -H 'Host: odo.example' http://127.0.0.1:8080/api/v1/health
```

Adapt container, load-balancer, and service health checks before enabling this
flag. TLS/DNS setup and trusted-edge controls remain deployment responsibilities.

## Central authentication cookie boundary

With `APP_HOST_GUARD=true`, central browser login issues `__Host-odo_session`
and `__Host-odo_csrf`. Both use Secure, Path=/, no Domain, and SameSite=Lax.
The browser session is HttpOnly. The CSRF cookie remains readable by the admin
UI so it can send the existing `X-Odo-CSRF` header; prefixing does not replace
that check.

Session lookup and CSRF derivation accept only the active session-cookie name.
There is no fallback to `odo_session` while guarded mode is enabled. Logout
revokes the active browser session and clears the active session/CSRF cookies
with the same prefix and attributes. The UI receives its active CSRF cookie
name through page metadata; its inline script stays static for CSP hashing.

When the guard is disabled, existing `odo_session` and `odo_csrf` behavior
remains unchanged, including on HTTPS deployments. Guard mode is a startup
setting: sign out before switching it and sign in again afterward. Existing
cookies and sessions from the other namespace are not automatically migrated
or revoked. In particular, disabling the guard can expose still-valid legacy
sessions again if their cookies remain in the browser.

These prefixes prevent sibling hosts from setting central cookies through a
parent Domain attribute in conforming browsers. They do not isolate vendor
scripts served on the same central origin through path mode. The Origin checks
below address sibling origins. Internal grants now depend on live central-session
validity. HTTP-level handoff and host-only vendor cookies are available only
with the experimental flag; production vendor delivery is disabled.

## Guarded central Origin checks

With the host guard enabled, unsafe requests (POST, PUT, PATCH, DELETE) to
`/login`, `/logout`, `/api/v1`, and `/api/v1/...` must carry exactly one Origin
header matching the configured central HTTPS origin. Comparison uses the same
normalized hostname and default-443 authority rules as host admission. Origin
must contain only scheme and authority: paths (even `/`), credentials, queries,
fragments, duplicate values, and sibling/vendor origins are rejected.
Referer and Sec-Fetch-Site do not substitute for a missing Origin.

`Origin: null` is the one exception. Central pages send `Referrer-Policy:
no-referrer`, and under the Fetch standard browsers then send `Origin: null` on
their own same-origin form POSTs (verified with headless Chromium for login and
handoff confirmation). `centralRequestOriginAllowed` therefore accepts `null`
only together with exactly one `Sec-Fetch-Site: same-origin`, a header page
script cannot set. `null` with `same-site`, `cross-site`, `none`, a missing or
duplicated `Sec-Fetch-Site`, and any other origin claiming `same-origin` stay
rejected. CSRF token checks still follow. Before this, real browsers could not
sign in or confirm a handoff whenever the host guard was on.

Host admission runs first, then Origin checking, then authentication and normal
application processing. Origin failures return generic 403 with no-store, no
cookies, and no database access. Rejected requests use the fixed access-log
route `origin_rejected`; Origin header values are not logged. Existing management
session CSRF-token checks remain required after Origin acceptance. Login and
logout now require the central Origin too; they do not gain management-API
bearer exemptions.

Bearer management clients may omit Origin on API requests. If they supply an
Origin, it must pass the same check. Authentication still validates the key,
and an invalid key never falls back to cookie authentication. Browser sessions
cannot use this exemption without supplying a separately valid management key.

Guarded `GET /logout` and `HEAD /logout` return 405 with `Allow: POST` without
revoking sessions or clearing cookies. Built-in logout forms already use POST.
Command-line login/logout callers must supply the central Origin explicitly.
Other safe requests and vendor POST workflows under `/odo` are unchanged. The
guard-disabled legacy behavior is unchanged. No cross-origin CORS allowance is
introduced. SAML handlers remain unimplemented and are not enabled by this work.

These checks do not protect central credentials from vendor code served through
central-origin path mode. Production virtual-host migration still requires
separating those origins before vendor-host routing is enabled.

## Required request boundary before enabling traffic

Vendor content dispatch must preserve the guard's ordering before cookie/session
processing, API-key authentication, and application routing. It must continue
rejecting authority disagreement and ignoring untrusted forwarded host values.
The edge must preserve validated Host, overwrite
forwarded headers, and prevent untrusted direct backend access.

Only the configured central host may reach login, admin, management APIs, source
notices, and central continuations. Vendor candidates require exact registry
lookup and independent current resource, method, session/grant, and DNS safety
checks. Unknown, inactive, or rejected hosts must fail without credential
processing, target fetches, or registry enrollment. A vendor's own `/about`,
`/login`, or `/api` path belongs to its vendor origin, not Odo's central mux.

The opt-in central host, cookie, and Origin boundaries are implemented.
Host admission is active when the guard is enabled. By default only the central
host reaches the application. The experimental flag adds the exact vendor
redemption control path and experimental grant-authorized GET/HEAD content on
registered vendor hosts, never central application routes on vendor hosts. The ticket/grant foundation and test-only HTTP integration below
are implemented. Production origin migration, deployment validation and vendor
compatibility remain delivery gates. The existing local login continuation is
not itself a cross-host grant; it feeds the authenticated launch flow.



## Implemented isolated ticket and grant lifecycle

`internal/api/handoff_security.go` coordinates `pending_handoffs.go` without any
direct HTTP registration. The off-by-default experimental runtime now owns one
instance through `Server.handoff` and wraps it in the control handlers below. The
internal coordinator itself does not set cookies, fetch content or trust forwarded
headers. Registry lookup never registers a hostname. A validated deployment configuration and an
exact persistent hostname/label mapping are required. Mappings are retained
identities, not independently revocable permissions: disabling/removing resource
policy removes authorization. There is no new hostname-revocation API.

1. Begin verifies the complete central-session credential and the joined current
   session/user snapshot, then checks the registered host, current resource/method
   policy and target safety. It creates a pending handoff lasting at most five
   minutes, bound to the central browser nonce.
2. Vendor preflight binds one separate vendor browser nonce once to that exact
   vendor authority. It returns no central credentials or target information.
3. Central confirmation verifies the original central credential and nonce and
   rechecks live session, registry, resource and target safety. It atomically
   replaces prepared state with a 60-second ticket.
4. Redemption verifies the vendor nonce and exact host and rechecks the parent
   and current policy. The original approved resource ID must still be selected
   for the stored target; a different resource cannot replace it silently.
   Redemption atomically consumes the ticket and creates a host-specific grant.
5. Grants expire after 30 minutes without authorized use and never outlive the
   parent's absolute session expiry. Every use checks the live parent session,
   account eligibility and captured `auth_version`, registry mapping, and current
   policy/safety for the actual target and method. Grants are host authorization,
   not independent vendor identities or permission to bypass resource checks.

All lifetimes are capped by the parent session's absolute expiration; parent
idle expiration also denies use. Logout/session revocation, password changes,
disablement, locking, deletion and role changes deny subsequent validations,
regardless of grant TTL. Restoration/re-enablement cannot revive old sessions.
Invalid parents remove local state; database failures deny access without
claiming revocation succeeded. Checks do not touch session activity. Database
snapshots and memory transitions are separate: an operation authorized before a
concurrent revocation may finish, and subsequent operations must revalidate.

Tokens use 32 cryptographically random bytes; only SHA-256 token/nonce hashes
are retained. Pending records and tickets bind parent user/session/hash,
`auth_version`, registry identity, approved resource ID and target. They include
creation/expiration times. Resource IDs are limited to 128 bytes in this internal
state; URLs and other fields also have explicit bounds. Grants retain no target,
resource ID or nonce. The store has at most 256 pending handoffs, 256 tickets,
4096 grants overall and 64 grants per parent. Expiration cleanup runs on store
operations. Exhaustion rejects new state without evicting live state or consuming
a ticket on failed grant allocation. No tokens or patron destinations are logged.

Storage is in process memory, deliberately independent of persistent central
sessions. Restart loses tickets and grants and requires a new handoff. Multiple
replicas need an explicit shared-storage or affinity design before deployment.
No parent-domain authentication cookies or resource-schema changes are
introduced. Vendor-host nonce/grant cookies and the single control endpoint are
opt-in through the experimental runtime below; content routing and rewriting
remain disabled, and default path/query behavior is unchanged. Existing connection-time
validated-IP dialing remains unchanged; future vendor fetches must use it too.

The [HTTP/browser protocol review](cross-host-grants.md#httpbrowser-protocol-review-checkpoint)
specifies endpoint ownership, host-only cookies, an explicit Origin/CSRF-
protected central confirmation POST and a vendor-return proof. Return proofs are
now implemented internally: one hashed proof per pending record, a 60-second
maximum capped by pending/parent expiry, same-nonce rotation and mandatory atomic
confirmation checks. Tests cover two-browser correlation and rotation during
validation. Central confirmation handling is now implemented as described
below and wired only by the experimental flag. Experimental GET/HEAD vendor
content dispatch is described below. Production delivery additionally needs
redirect/content rewriting, cross-host asset handling, wildcard DNS/TLS
deployment and end-to-end browser compatibility tests.


## Central confirmation HTTP handler

`handoff_confirmation.go:centralConfirmationHandler` is a testable HTTP boundary
for `/launch/handoff/confirm`. `Server.Routes` registers its dispatch only when
the experimental handoff flag is enabled. With the flag off, launch retains
existing path/query behavior and the confirmation flow is unavailable.

The handler shares the current host guard's central/absolute-authority check and
ignores forwarded hosts. GET requires the bound session, central nonce and return
proof, checks live authorization, and renders a plain escaped form without
consuming live state or touching session timestamps. POST requires exact central
Origin and the session-derived CSRF form value, then rechecks current parent,
registry, original resource, target safety and proof. The atomic transition uses
a fresh timestamp and rejects a proof that expired or rotated during validation.
A successful POST returns 303 to the exact bound vendor redemption endpoint;
that endpoint remains unavailable unless experimental handoff is enabled.

Only GET and POST are accepted; HEAD returns 405 without state changes. Active
session/nonce cookies must be unique and prefixed, with no legacy fallback.
Inputs permit only the documented fields, reject duplicate keys and POST query
strings, and cap form bodies at 4 KiB. POST accepts URL-encoded UTF-8 forms only;
missing/bad CSRF is 403 and receives no header-based fallback. No cookies are
issued or cleared. Controls use fixed log labels, no-store/no-referrer, a
script-free CSP and frame denial on successes and failures. Generic failures do
not log or expose proofs, tokens or targets.

## Experimental runtime and trust boundary

`APP_EXPERIMENTAL_HANDOFF` accepts the same true/false spellings as the host
guard and defaults to false. True requires `APP_HOST_GUARD=true`, valid configured
HTTPS central/proxy names, and `APP_ENV` empty/development/test. Production and
unknown environment names reject this flag. Startup validation fails; directly
constructed invalid configurations return 503 without credentials or data access.
Startup also validates the runtime's cookie-jar configuration; if the runtime's
coordinator cannot be constructed, the server returns 503 for every request.
Configuration is captured when constructing the server; restart to change it.
The existing `APP_PROXY_URL_MODE=virtual_host` production rejection remains.

The test-only flag is a handoff-only mode. Central application routes remain
central. Valid legacy GET `/odo`, `/odo/`, `/odo/https/<host>/...` and `/p`
bookmarks receive an empty-body 303 to the configured central `/launch`, after
strict syntax, current resource/GET-method and DNS/SSRF validation. No fetch,
credentials or handoff state is created by migration; launch validates again.
HEAD and unsafe methods receive 405 without reading/replaying request bodies.
Central-origin vendor content, diagnostic body previews and missed-rewrite
recovery remain blocked to keep vendor scripts away from central credentials.
See [central-origin migration](vendor-origin-cookie-boundary.md#central-origin-migration)
for parsing and privacy details. With the flag off, existing
path/query/dual behavior is unchanged. Vendor hosts expose only one exact path:

| Request on registered vendor host | Action |
| --- | --- |
| `GET /.well-known/odo/redeem?handoff=<opaque-id>` | Check pending parent/resource/target, bind host-only browser nonce, issue return proof; 303 to configured central confirmation. |
| `GET /.well-known/odo/redeem?ticket=<opaque-ticket>` | Check exact host/nonce, live parent/version, original resource and target safety; atomically exchange ticket for grant; set host-only grant cookie; 303 to the ticket's stored target path/query on this same proxy host (the receipt if it cannot be represented there). |
| `GET /.well-known/odo/redeem` | Validate live grant/parent/registry and active domain policy; show an inert completion receipt. No resource target or content is shown. |
| HEAD or other methods | 405, no state/cookie changes. |
| Other `/.well-known/odo/` paths, including the old proposed `/prepare` | 400; Odo's reserved namespace is never proxied. |
| Every other vendor path, including a vendor's own `/admin`, `/login`, `/api/v1` | Experimental GET/HEAD [vendor content delivery](#experimental-vendor-content-delivery); never the central application. |

The preflight phase shares the redemption path; a separate vendor prepare
endpoint is not admitted. Unknown/unregistered hosts and disagreement between
Host and absolute request authority fail closed. Forwarded host headers never
choose authority. Registry lookup never enrolls hosts. Cookies and management
API keys from central are neither needed nor processed by the vendor handler.

The complete flow is authenticated `/launch` → vendor preflight → central GET
confirmation → explicit central Origin/CSRF-protected POST → one-use ticket →
vendor redemption → the stored target on the proxy host. Ordinary login
continuation is used first when needed. Neither new vendor-facing control URL
contains the upstream destination, central session token or CSRF value. All
redirects use configured central or stored registered-vendor authority. There is
no caller-supplied return URL: final redemption continues only to the ticket's
server-side target, re-expressed on the same proxy host after the same-host,
HTTPS and path checks used for upstream redirects, and never to another host.

Cookie names are `__Host-odo_handoff_nonce` on central, and
`__Host-odo_grant_nonce`/`__Host-odo_proxy_grant` on the exact vendor host. All
are Secure, HttpOnly, SameSite=Lax, Path=/, without Domain. Nonces last at most
five minutes; ticket and return-proof TTLs are at most 60 seconds; grants expire
after 30 minutes without authorized use and never beyond parent absolute expiry. Session revocation,
password/status/role changes and deletion deny subsequent grant/receipt use;
`auth_version` mismatch alone suffices. Cookies on another vendor host cannot
supply that host's grant; even a manually copied value fails server binding.
The inert receipt also checks active domain policy. Content use separately
authorizes its real URL/method through the cookie coordinator and uses
validated-IP dialing; neither the receipt nor the redemption redirect authorizes
an upstream fetch.

Each control response uses no-store, no-referrer, restrictive CSP and frame
denial. Fixed route labels and suppression of Referer/User-Agent in experimental
mode prevent ticket/target leakage in privacy, common, combined and JSON logs.
Bodies, Cookie/Authorization/Set-Cookie, raw tokens and Location are not logged.
Edge/proxy logs must independently suppress complete URLs, sensitive headers and
Location. Short-lived ticket/proof URLs may still appear in browser history;
headers do not erase history or protect against privileged extensions.

State remains bounded process memory: 256 pending records, 256 tickets, 4096
grants globally and 64 per parent. Expiry cleanup runs on store operations.
Capacity/validation/storage failure denies access without consuming live retry
state or claiming success. Restart loses all grants and pending state; replicas
need a separate shared-state/affinity design. Database checks and memory
transitions are not one transaction; requests authorized before revocation may
finish, but each later grant use checks the current parent without a positive
cache. No upstream jar is allocated by the handshake.

## Implementation map

| Files | Functions and responsibility |
| --- | --- |
| `internal/api/handoff_runtime.go` | `experimentalHandoffConfig`, `launch`, `dispatchCentral`, `migrateLegacyBookmark`, cookie/header helpers: flag validation, launch integration and validated legacy migration before API authentication and mux canonicalization. Host/Origin admission stays first. |
| `internal/api/handoff_vendor.go` | `vendorRequest`, `serveVendor`, `prepareBrowser`, `redeemBrowser`, `complete`: the single vendor endpoint, proof exchange, grant cookie and inert receipt. |
| `internal/api/server.go`, `host_guard.go` | Server construction/`Routes`, `guardHost`, `ValidateHostGuardConfig`: process-local state and fail-closed startup/admission. |
| `internal/api/launch_handlers.go`, `proxy_handlers.go` | `redirectLaunchTarget` and `handleUnknownPath`: opt-in handoff and central content/recovery isolation. |
| `internal/api/resources_handlers.go`, `legacy_migration_test.go` | `proxyTestFetch` blocks diagnostic body delivery in experimental mode; regression tests cover migration, aliases, policy/SSRF failures, method/body rejection, recovery, privacy and flag-disabled delivery. |
| `internal/api/handoff_confirmation.go` | `serveConfirmation`, `confirmationError`: shared control headers, central confirmation, capacity/error mapping. |
| `internal/accesslog/accesslog.go` | `Metadata.SuppressBrowserHeaders` and `Logger.Log`: suppress raw browser headers on sensitive controls across log formats. |
| `internal/api/handoff_browser_test.go`, `internal/accesslog/accesslog_test.go`, `cmd/odo/main_test.go` | Local TLS/cookie integration, privacy regression and production rejection tests. |

The internal `handoff_security.go`/`pending_handoffs.go` security foundation is
reused without duplicating ticket/grant state or changing account transactions.

## Repeatable local test with fake hostnames

From the repository root, with existing Go dependencies cached:

```sh
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go test ./internal/api -run '^TestExperimentalHandoffBrowserFlow$' -count=1 -v
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go test ./internal/api -run '^TestExperimentalHandoff' -count=1 -v
```

The fixture creates a temporary SQLite database, an active local user/resource,
and an explicitly enrolled `vendor.example` mapping. A local TLS listener serves
Odo. Only the test browser transport maps `odo.example` and canonical vendor
labels beneath `proxy.example` to that listener, verifying its loopback TLS
certificate. Odo's injected target resolver returns a fixed public test IP and
its outbound HTTP client fails the test on any vendor fetch. The flow needs no
public DNS, hosts-file edits, real vendor requests, certificates installed on the
machine or persistent configuration changes. A cookie jar verifies HTTPS
host isolation; manual redirects exercise confirmation rather than auto-posting.
These are HTTP/cookie integration tests, not a claim of full real-browser or
vendor compatibility.

For a separate manual test deployment, the flag configuration is:

```text
APP_ENV=development
APP_EXPERIMENTAL_HANDOFF=true
APP_HOST_GUARD=true
APP_PUBLIC_URL=https://odo.example
APP_PROXY_BASE_DOMAIN=proxy.example
```

A manual browser setup still needs trusted TLS, DNS/edge Host preservation and
explicit admin registry/resource enrollment. The automatic tests above supply
those equivalents locally; the runtime does not install them or bypass SSRF for
fake names. Do not turn on this flag in an existing production deployment.

The `grant_cookies.go` coordinator connects live grant/parent checks, the actual
winning resource and its snapshot's cookie generation, under the Store resource
guard; see [the cookie boundary](vendor-origin-cookie-boundary.md#internal-live-grantcookie-coordinator).
The experimental runtime now owns one coordinator and uses it for every vendor
content request and response.

## Experimental vendor content delivery

`internal/api/handoff_delivery.go` serves the first vendor content path. It
exists only when `APP_EXPERIMENTAL_HANDOFF=true` (development/test, host guard
on); production startup rejects that flag, and a runtime construction failure
makes the guard answer 503 for every request rather than fall back.

Runtime ownership: `newHandoffRuntime` constructs one `grantCookieCoordinator`
(one bounded jar manager, sharing the Server's `db.Store` with all resource
writers) and one dedicated client from `proxy.NewSafeHTTPClient`. Vendor
delivery never uses the injectable legacy proxy client or the `odo_proxy_sid`
session store. `ValidateHostGuardConfig` also checks the jar configuration at
startup.

Request flow on a non-central authority:

1. `guardHost` classifies `Host` only (forwarded headers are ignored). The exact
   `/.well-known/odo/redeem` control path keeps its existing handler. Every
   other path goes to vendor content; the central mux (admin, login, logout,
   `/api/v1`, resources, about/source, session routes) is never reachable on a
   vendor host. A vendor's own `/login` or `/api` path is proxied to the vendor
   like any other vendor path, without Odo credentials.
2. Admission requires `GET` or `HEAD` (others 405), no request body or
   `Transfer-Encoding`, an absolute-form URI (if any) naming the same HTTPS
   proxy label with no userinfo, a request target of at most 8 KiB, and a path
   without dot segments (including `%2e` forms), backslashes, control
   characters or Odo's reserved `/.well-known/odo/` namespace. The host must be
   an exact registry mapping (else 421) and the request must carry exactly one
   host-only `__Host-odo_proxy_grant` cookie (else 401).
3. The upstream URL is `https://` + the registry mapping's hostname + the
   request's escaped path and opaque query, and must survive canonical parsing
   unchanged. Clients cannot supply upstream URLs, resource IDs or hosts.
4. Only `Accept`, `Accept-Language`, `User-Agent`, `Range` and `If-Range` are
   copied upstream, plus `Accept-Encoding: identity`. Cookies, `Authorization`,
   `Proxy-Authorization`, `Forwarded`/`X-Forwarded-*`, CSRF and hop-by-hop
   headers never are.
5. `grantCookieCoordinator.prepareRequest` validates DNS safety, then under the
   resource guard checks the live grant, parent session, current resource
   policy for the exact target and method, and selects the winning resource's
   jar. Proxied activity refreshes the parent session (throttled).
6. The safe client has no cookie jar, never follows redirects, verifies TLS
   certificates normally, validates every resolved IP at connection time
   (rebinding-safe) and uses 10 s TLS, 15 s response-header and 30 s overall
   timeouts. The browser request's context cancels the upstream request.
7. Responses that cannot be represented are refused before any cookie is
   stored: statuses outside 200-599 (including a `101` protocol switch) and
   redirects other than same-host HTTPS return 502 with no `Location`, and their
   `Set-Cookie` reaches neither the browser nor the jar.
8. `storeResponse` reauthorizes and stores cookies before any header or byte is
   forwarded; failure (session revoked mid-request, expired grant, policy
   revision, cookie rejection) fails closed and discards the body. Same-host
   HTTPS redirects are then re-expressed on the proxy authority (fragment
   dropped). Only `Content-Type`, `Content-Disposition`,
   `Content-Language`, `Last-Modified`, `ETag`, `Content-Length`,
   `Content-Encoding`, `Accept-Ranges` and `Content-Range` are copied;
   `Set-Cookie`, CSP, CORS, HSTS, `Link`, `Refresh`, `Alt-Svc` and `Location`
   are dropped. Responses get `Cache-Control: no-store`,
   `Referrer-Policy: no-referrer` and `X-Content-Type-Options: nosniff`. HEAD
   responses carry no body. Bodies are streamed unmodified, except the
   narrow same-host HTML link rewriting described under
   [browser compatibility](#browser-compatibility).

Errors map to 401 (grant/parent invalid), 403 (policy or method denied), 502
(unsafe or unresolvable destination, TLS/connection failure, unsupported
redirect or status), 504 (timeout) and 503 (coordinator storage or capacity). Access logs
record only the route `handoff_vendor_content`, status and upstream status;
paths, queries, cookies and upstream error text (which embeds URLs) are never
logged.

`internal/api/handoff_delivery_test.go` covers these paths against fake HTTPS
vendors with locally issued certificates. The real safe client is used: the
test resolver returns a public test IP and only the test dialer maps that
already-validated IP to the loopback listener.

Re-handoff: a top-level `GET` document navigation (`Sec-Fetch-Dest`/`Mode`
document/navigate or absent, `Accept` HTML or absent) that has no grant cookie,
or whose grant the coordinator rejects as unknown, expired or bound to an
invalid parent session, receives a body-less 303 to central
`/launch?url=<trusted upstream target>`. The target is built from the registry
hostname, so this is never an open redirect. The patron repeats the normal
login (if needed) and explicit central confirmation, and redemption returns
them to the same path and query. The vendor jar survives because jar lifetime
follows patron inactivity, not the grant. Subresource, `fetch`/XHR, `HEAD`,
duplicate-grant-cookie and policy-denied requests are never redirected; they keep
401 or 403.

Grant renewal: after a request is fully authorized and `storeResponse`
succeeds, the grant's deadline slides to 30 minutes from now, capped at the
parent session's absolute expiry, and the response refreshes the host-only
`__Host-odo_proxy_grant` cookie (same value, new `Max-Age`). Renewal is
throttled to once a minute so routine assets do not churn cookies. Denials,
upstream failures and redirects that fail closed never renew; renewal never
revives an expired grant. Every request still checks the live parent session,
so logout, revocation or account changes end a renewed grant immediately. An
active patron therefore re-confirms only after 30 minutes of inactivity or when
the central session itself ends.

Known limits: only same-host absolute URLs in HTML attributes are rewritten
(see [browser compatibility](#browser-compatibility)); cross-host links, assets,
frames and redirects, and URLs built by JavaScript or CSS, leave the proxy host
and do not work.
After 30 minutes of inactivity, a re-handoff requires the patron to confirm
again at central. A stolen grant cookie can be kept alive by use until the
parent's absolute expiry unless the parent session ends. There is no cookie
persistence and no multi-instance state.

## Browser compatibility

`internal/api/handoff_browser_compat_test.go` drives the complete browser path
against a fake multi-page HTTPS vendor (locally issued certificate, fake DNS):
central session → `/launch` → confirmation → grant → vendor index → assets →
second page → same-host redirect → vendor session cookie, plus a PDF.

Baseline before any rewriting (recorded on the unchanged branch): root-relative
CSS/JS/images, relative and parent-relative navigation, query strings, escaped
paths (`%2F`, `%20`, UTF-8), same-host redirects, the vendor's own session
cookie (kept in the upstream jar, never in the browser), PDF full/`Range`/
`If-Range`/`HEAD` responses and fragments all worked through native browser
URL resolution. The only same-host failure was a URL-rewriting problem:
absolute (`https://vendor.example/...`, `http://...`) and scheme-relative
(`//vendor.example/...`) same-host links, and a `<base href>` naming the vendor
host, sent the browser to the real vendor outside Odo.

Same-host rewriting rules (`proxy.RewriteSameHostHTML`, applied in
`handoff_delivery.go`):

- Only complete `GET` responses with `text/html` or `application/xhtml+xml`,
  no `Content-Encoding` (other than identity), not 206/204/304, and at most
  2 MiB are examined. Larger documents stream unchanged. PDFs, images, scripts,
  stylesheets and every other type are never modified.
- Only the attributes `href`, `src`, `srcset` (each candidate), `poster`,
  `action`, `formaction` and `data` are examined, on any element (including
  `<base>`). `data-*`, `style`, inline scripts and styles, comments, text and
  `<meta http-equiv=refresh>` are never changed.
- A value is rewritten only when it is an absolute `https`/`http` or
  scheme-relative URL whose host equals the resource's registered upstream host
  (case-insensitive, default port, no userinfo or percent-encoded authority).
  The scheme and authority become `https://<this proxy host>`; every following
  byte (escaped path, query, fragment) is kept. Relative URLs, other hosts and
  unregistered destinations are never rewritten, so no new host is reached and
  authorization is unchanged.
- Unchanged tokens are copied byte-for-byte. Only a changed tag is
  re-serialized: its name and attribute keys lower-cased, values double-quoted,
  decoded non-ASCII characters written as numeric character references (valid
  in any document encoding) and non-UTF-8 bytes kept as supplied. A document
  with nothing to rewrite is forwarded unchanged with its original headers.
- When a document changes, `Content-Length` is recomputed and `ETag` and
  `Accept-Ranges` are removed, since they describe the upstream bytes. `HEAD`
  for eligible HTML omits `Content-Length`, `ETag` and `Accept-Ranges`,
  because it cannot know whether `GET` would rewrite. Range responses are
  never rewritten.

Real-browser verification: headless Chromium 156 was driven over the DevTools
protocol through Odo's real TLS listener and this fake vendor (browser-side
host mapping and certificate bypass for the local listener only; Odo's upstream
TLS and IP validation unchanged). It found three central-flow failures the Go
client tests could not see, now fixed: login and confirmation POSTs carried
`Origin: null` (see [guarded central Origin checks](#guarded-central-origin-checks)),
and CSP `form-action 'self'` blocked the confirmation POST's 303 to the vendor
host and the login-continuation chain's redirect to it, because browsers apply
`form-action` to every redirect of a form submission. The confirmation page,
and a login page serving this browser's live launch continuation, now allow
exactly that one registered proxy origin (`form-action 'self'
https://<label>.<proxy base>`); every other page keeps `'self'`. After the
fixes Chromium completed logged-out entry → login → confirmation → vendor
index, applied the CSS, ran the script, decoded the image, followed relative,
`../`, absolute, `http`, scheme-relative and `<base>`-relative links, the
same-host redirect and escaped URLs, fetched the PDF (200) and a range (206),
opened it in the PDF viewer, and held only Odo's `__Host-` cookies. The
external CDN image did not load through Odo, as expected.

Vendor HTML is served without the central application's CSP, frame or
permissions headers (it is not an Odo page), with `no-store`, `no-referrer`
and `nosniff`. Access logs record only the route and statuses.

Confirmed limitations (deferred, not failures of this milestone): forms that
`POST` (only `GET`/`HEAD` exist), cross-host links and assets such as a CDN
image (they load directly from the third party, outside Odo and its privacy
controls), URLs constructed by JavaScript, URLs inside CSS (`url(...)`,
`@import`), `<meta http-equiv=refresh>` and `Link`/`Refresh` headers, cookies
set by vendor JavaScript (`document.cookie` stays in the browser and is never
sent upstream), and documents over 2 MiB or compressed upstream. Cross-host
support needs registered-host rewriting with per-host grants and automatic
cold-host handoff, which remain unimplemented.

## Post-commit retirement

`db.CommitHooks` (`internal/db/commit_hooks.go`) notify the process that owns
in-memory credential state as soon as a change commits. `newHandoffRuntime`
registers one set per Store:

- `ResourcesChanged` runs after every committed resource upsert or delete
  (including each resource of a config import) while the writer still holds the
  resource guard. It republishes the current snapshot's active policies through
  the coordinator, so jars of changed, disabled or deleted resources are dropped
  at commit even if no request follows. Any read/publication failure invalidates
  all jars, as on the request path.
- `SessionsRevoked` receives exactly the session IDs a transaction revoked
  (`UPDATE ... RETURNING id`): logout, administrative revoke-sessions, password
  set, disable/lock, security-relevant role changes, deletion and restoration.
  It runs only after a successful commit, holds no Store lock, and drops those
  parents' upstream jars and their pending handoffs, tickets and grants. Other
  patrons are untouched.

Hooks are cleanup notifications, not authorization. Every request still
revalidates the live session, account and resource policy, so a missed hook
(another process, direct SQL, a crash between commit and hook) only delays
memory cleanup until the next request, jar idle expiry or grant expiry.

Remaining delivery work: production origin rollout, virtual-host
URL/rewrite behavior, cross-host redirect/cold-host rules, wildcard DNS/TLS deployment and real-browser/vendor
compatibility/privacy testing.
