# Virtual-host routing foundation

Virtual-host request routing is disabled. Production startup rejects
`APP_PROXY_URL_MODE=virtual_host`; development retains its warning and path-mode
fallback. `APP_EXPERIMENTAL_HANDOFF=true` now enables an isolated authentication
handoff in development/test only. It defaults off and is rejected in production.
This is not a deployable virtual-host proxy mode.

| State | Current behavior |
| --- | --- |
| Implemented | Registry, launch/login continuation, bounded hashed tickets/proofs/grants, live parent/version/resource checks, central confirmation and vendor control HTTP handlers. |
| Enabled for testing | With the flag, registered vendor hosts admit only `GET /.well-known/odo/redeem`; central launch and confirmation complete the browser handshake. |
| Disabled | All upstream vendor content on vendor hosts; central path content and missed-rewrite recovery are also blocked while the experimental mode is on. Default path/query deployments are unchanged when off. |
| Not yet implemented | Production vendor delivery, resource-scoped upstream jars, virtual-host rewriting, automatic cold-host access and multi-instance handoff state. |

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
with the experimental handoff-only flag; production vendor delivery is disabled.

## Guarded central Origin checks

With the host guard enabled, unsafe requests (POST, PUT, PATCH, DELETE) to
`/login`, `/logout`, `/api/v1`, and `/api/v1/...` must carry exactly one Origin
header matching the configured central HTTPS origin. Comparison uses the same
normalized hostname and default-443 authority rules as host admission. Origin
must contain only scheme and authority: paths (even `/`), credentials, queries,
fragments, `null`, duplicate values, and sibling/vendor origins are rejected.
Referer and Sec-Fetch-Site do not substitute for a missing Origin.

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

Future vendor content dispatch must preserve the guard's ordering before cookie/session
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
host reaches the application. The experimental flag adds only the exact vendor
redemption control path, never vendor content or central application routes on
vendor hosts. The ticket/grant foundation and test-only HTTP integration below
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
5. Grants last at most 30 minutes. Every use checks the live parent session,
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
below and wired only by the experimental flag. Vendor content dispatch remains
absent.
Vendor delivery additionally needs upstream cookie isolation, session activity
handling, validated-IP fetch integration, redirect/content rewriting, wildcard
DNS/TLS deployment and end-to-end browser compatibility tests.


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
Configuration is captured when constructing the server; restart to change it.
The existing `APP_PROXY_URL_MODE=virtual_host` production rejection remains.

The test-only flag is a handoff-only mode. Central application routes remain
central, but central-origin `/odo` content and missed-rewrite recovery are blocked
to keep vendor scripts away from central credentials. With the flag off, existing
path/query/dual behavior is unchanged. Vendor hosts expose only one exact path:

| Request on registered vendor host | Action |
| --- | --- |
| `GET /.well-known/odo/redeem?handoff=<opaque-id>` | Check pending parent/resource/target, bind host-only browser nonce, issue return proof; 303 to configured central confirmation. |
| `GET /.well-known/odo/redeem?ticket=<opaque-ticket>` | Check exact host/nonce, live parent/version, original resource and target safety; atomically exchange ticket for grant; set host-only grant cookie; 303 to the same endpoint without query. |
| `GET /.well-known/odo/redeem` | Validate live grant/parent/registry and active domain policy; show an inert completion receipt. No resource target or content is shown. |
| HEAD or other methods | 405, no state/cookie changes. |
| Every other vendor path, including `/admin`, `/login`, `/logout`, `/api/v1`, `/resources`, `/launch` and the old proposed `/prepare` | 421 before central authentication or cookie handling. |

The preflight phase shares the redemption path; a separate vendor prepare
endpoint is not admitted. Unknown/unregistered hosts and disagreement between
Host and absolute request authority fail closed. Forwarded host headers never
choose authority. Registry lookup never enrolls hosts. Cookies and management
API keys from central are neither needed nor processed by the vendor handler.

The complete flow is authenticated `/launch` → vendor preflight → central GET
confirmation → explicit central Origin/CSRF-protected POST → one-use ticket →
vendor redemption → clean inert receipt. Ordinary login continuation is used
first when needed. Neither new vendor-facing control URL contains the upstream
destination, central session token or CSRF value. All redirects use configured
central or stored registered-vendor authority. There is no caller-supplied return
URL, and final redemption never redirects to the upstream target.

Cookie names are `__Host-odo_handoff_nonce` on central, and
`__Host-odo_grant_nonce`/`__Host-odo_proxy_grant` on the exact vendor host. All
are Secure, HttpOnly, SameSite=Lax, Path=/, without Domain. Nonces last at most
five minutes; ticket and return-proof TTLs are at most 60 seconds; grants last
at most 30 minutes and never beyond parent absolute expiry. Session revocation,
password/status/role changes and deletion deny subsequent grant/receipt use;
`auth_version` mismatch alone suffices. Cookies on another vendor host cannot
supply that host's grant; even a manually copied value fails server binding.
The inert receipt also checks active domain policy. Actual future content use
must separately authorize its real URL/method through `validateGrant` and use
validated-IP dialing; the receipt does not authorize an upstream fetch.

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
| `internal/api/handoff_runtime.go` | `experimentalHandoffConfig`, `launch`, `dispatchCentral`, cookie/header helpers: flag validation, launch integration and central dispatch. |
| `internal/api/handoff_vendor.go` | `vendorRequest`, `serveVendor`, `prepareBrowser`, `redeemBrowser`, `complete`: the single vendor endpoint, proof exchange, grant cookie and inert receipt. |
| `internal/api/server.go`, `host_guard.go` | Server construction/`Routes`, `guardHost`, `ValidateHostGuardConfig`: process-local state and fail-closed startup/admission. |
| `internal/api/launch_handlers.go`, `proxy_handlers.go` | `redirectLaunchTarget` and `handleUnknownPath`: opt-in handoff and central content/recovery isolation. |
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

Remaining delivery work: production origin migration, bounded parent/resource
upstream cookie jars with cookie-policy enforcement, actual target/method grant
checks on each fetch, validated-IP integration, virtual-host URL/rewrite behavior,
redirect/cold-host rules, wildcard DNS/TLS deployment and real-browser/vendor
compatibility/privacy testing. Vendor content routing is not enabled here.
