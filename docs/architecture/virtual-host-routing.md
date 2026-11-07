# Virtual-host routing foundation

Virtual-host request routing is disabled. Production startup rejects
`APP_PROXY_URL_MODE=virtual_host`; development retains its warning and path-mode
fallback. This document describes implemented validation helpers and the
remaining routing boundary, not a deployable virtual-host mode.

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
routing. Only the configured central authority reaches those handlers. All
vendor candidates, including registered hosts, and unknown or malformed
authorities receive generic 421 responses with no-store. Rejection creates no
cookies or mappings, reads no application database, and fetches no content.
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
validity; HTTP-level cross-host handoff and vendor cookies remain disabled.

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

Future vendor dispatch must preserve the guard's ordering before cookie/session
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
Host admission is therefore already active when the guard is enabled; it admits
only the configured central host, not registered vendor hosts. The internal
ticket/grant foundation described below is implemented, but its HTTP/browser
protocol and path-mode origin separation remain release gates. See the proposed
[cross-host grant protocol](cross-host-grants.md) for the protocol review. The
current local login continuation is not a cross-host grant. Vendor dispatch,
DNS/TLS deployment guidance, and vendor compatibility validation remain pending.


## Implemented isolated ticket and grant lifecycle

`internal/api/handoff_security.go` coordinates `pending_handoffs.go` without any
HTTP registration or runtime attachment to `Server`. It does not set cookies,
redirect browsers, fetch upstream content, or use forwarded headers. Registry
lookup never registers a hostname. A validated deployment configuration and an
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
No parent-domain authentication cookies, vendor-host cookies, public handoff
endpoints, routing, response rewriting, resource-schema changes or changes to
path/query behavior are part of this foundation. Existing connection-time
validated-IP dialing remains unchanged; future vendor fetches must use it too.

The [HTTP/browser protocol review](cross-host-grants.md#httpbrowser-protocol-review-checkpoint)
now specifies endpoint ownership, host-only cookies, an explicit Origin/CSRF-
protected central confirmation POST and a vendor-return proof. That proof is not
implemented by the current internal API and must be added and tested before
HTTP controls are wired. The next small implementation milestone is internal
return-proof state and two-browser correlation tests, without routes or cookies.
Vendor delivery additionally needs upstream cookie isolation, session activity
handling, validated-IP fetch integration, redirect/content rewriting, wildcard
DNS/TLS deployment and end-to-end browser compatibility tests.
