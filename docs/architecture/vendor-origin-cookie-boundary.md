# First vendor-host deployment: origin and cookie boundaries

Status: an isolated bounded upstream jar manager is implemented and tested in
`internal/proxy/upstream_cookies.go` and `upstream_cookie_policy.go`. It is not
connected to routes, grants, resource updates, or fetches. The experimental
handoff-only runtime implements control routes and host-only nonce/grant cookies
in development/test. Virtual-host content delivery remains disabled and rejected
in production. The production origin recommendations below remain rollout gates.

This checkpoint complements [cross-host grants](cross-host-grants.md). The
account-security transactions and experimental grant protocol are implemented;
delivery integration and the boundaries below still need review before traffic.

## Recommended first deployment

| Decision | Recommended first scope |
| --- | --- |
| Processes | One Odo process; no multi-instance grant/jar sharing. |
| Routing identities | Canonical registry labels only, bound to the configured full proxy authority. No request-driven enrollment or readable aliases. |
| Grant handoff | The experimental prepare → central confirmation → redeem flow, with browser nonces, parent-session binding and single-use tickets. |
| State | Process memory only, using the lifetimes/capacities in the grant proposal. Restart invalidates handoffs, tickets, grants and jars. |
| Central origin | Outside the vendor wildcard suffix; login, admin, management APIs, launch and legal/source notices stay central. |
| Legacy content | Redirect-only migration of safe GET bookmarks on the central origin. No vendor response bodies there once vendor-host mode is enabled. |
| Cookie scope | Parent browser session plus the currently winning resource, using existing `jar_scope: resource`. |
| Anonymous exceptions | Cookieless upstream requests; never borrow an authenticated jar. |
| Cold hosts | Restrict the first pilot to workflows whose required hosts receive explicit top-level launches. No automatic asset/frame login, enrollment or credential minting. |

For example, use `login.library.example` as central and
`*.proxy.library.example` for vendor candidates. These are distinct origins;
the existing host-only prefixed cookies and strict central Origin/CSRF checks
remain necessary. This does not claim that sibling origins are different sites.
The edge must preserve validated Host, overwrite forwarding headers, terminate
TLS for both host spaces, and prevent direct untrusted backend access.

## Central-origin migration

By default, `Routes` in `internal/api/server.go` still serves `/odo` path/query
traffic on the central host. `APP_HOST_GUARD=true` alone does not isolate vendor
scripts. With `APP_EXPERIMENTAL_HANDOFF=true`, the implemented migration boundary
intercepts legacy proxy routes before mux canonicalization and ordinary proxy
session/login handling:

1. GET `/odo?url=...`, `/odo/?url=...`, `/p?url=...`, and literal
   `/odo/https/<host>/<path>?<vendor-query>` bookmarks validate through the launch
   parser and current resource, GET-method and DNS/SSRF policy, then return an
   empty-body 303 to the configured central HTTPS `/launch?url=...`. Encoded
   query envelopes and launch's raw `url=https://...` compatibility form are
   supported. Escaped target paths and query bytes are preserved. Duplicate or
   unexpected encoded-envelope fields, malformed targets and encoded route
   aliases fail closed. Inputs use the launch parser's 16 KiB bound.
2. Migration performs no upstream fetch, jar allocation, login or grant issuance.
   `/launch` revalidates on the subsequent request, then uses existing opaque
   login continuation and experimental handoff. Registry admission remains a
   launch/handoff check, not hostname enrollment during migration.
3. HEAD and all other non-GET methods on legacy proxy routes return 405 with
   `Allow: GET`, without reading/replaying bodies or initiating a handoff.
   Missed-rewrite recovery and direct proxy-engine access remain blocked. The
   diagnostic test-fetch API also returns 403 before reading its body or fetching;
   it cannot return a vendor body preview in experimental mode.
4. Migration responses use no-store/no-referrer, fixed privacy-safe log routes
   and no reflected target in the response body. Central management, login, API
   and source/legal notice routes remain central; vendor hosts cannot reach them.

This mode-specific migration must preserve existing path/query/dual deployments
when virtual-host mode is not selected. A separate legacy content deployment is
a possible later alternative, but shared central credentials and ad hoc
cross-origin session copying are outside the recommended first deployment.

## Existing path-mode cookie model

Inspected implementation:

- `internal/resources/resources.go:CookiePolicy` has `Enabled`, `JarScope` and
  `AllowedCookieDomains`. `normalizeCookiePolicy` defaults an omitted scope to
  `resource` and normalizes domain names. Current normalization does not restrict
  arbitrary nonempty scope strings.
- `internal/resources/resources_test.go:TestValidateExpandedJSTORLikeConfig`
  covers cookie-policy normalization alongside the resource model.
- `internal/proxy/session.go:GetOrCreate` selects a process-memory jar using the
  browser's `odo_proxy_sid`. `NewSessionStore` currently has no total jar-count
  bound and no central-session revocation link.
- `internal/proxy/proxy.go:FetchHandlerWithOptions` attaches that jar to the
  upstream client. It does not enforce the configured resource cookie policy.

These legacy path/query behaviors remain unchanged. The new manager is separate;
resource-scoped-cookie enforcement is not yet a running proxy guarantee. Do not
reuse the legacy jar store for grants.

## Implemented isolated authenticated jar rules

Resolve the request through the existing live resource/method policy first.
Use its winning `ResourceID` to load that resource's current cookie policy. Do
not change resource matching, merge competing policies or attach the grant to
the resource that happened to launch the hostname first. A missing/changed
resource must never fall back to a different resource's jar.

The server-side jar identity is the parent session ID and stored session-hash
binding, the winning resource ID, and an explicit cookie-policy generation.
The browser cannot choose these values through a cookie, header or query string.
Different parent sessions, including two logins for the same user, remain
isolated. Hosts authorized by the same resource can share permitted vendor
cookies within that parent. Grants still require independent exact-host checks.

Manager policy interpretation (existing resource JSON/import/export is unchanged):

| Existing field/state | Isolated manager behavior |
| --- | --- |
| `enabled: false` | Send no vendor cookies and discard upstream Set-Cookie; do not allocate a jar. |
| Enabled, `jar_scope: resource` | Use the parent/resource jar described above. |
| Omitted scope | Use the existing normalization to `resource`. |
| Other scope string | Fail closed before an upstream fetch in vendor mode; do not silently share a broader jar. Preserve existing JSON import/export shape. |
| Empty `allowed_cookie_domains` | Accept host-only cookies for the currently authorized upstream host; reject cookies carrying a Domain attribute. |
| Nonempty allowed domains | Permit host-only cookies, and Domain cookies whose normalized domain is explicitly listed and valid for the response host. A listed parent domain can cover authorized sibling hosts of the same resource. |
| Cookie-policy change | Select a new empty jar and retire the old policy's jar; do not resurrect its cookies if policy later reverts. |

Domain entries must be DNS names, not URLs, IPs, wildcard patterns or public
suffixes. Enforce ordinary domain/path/Secure/expiry rules as well as the resource
allowlist. Reject central/proxy deployment-domain cookie targets. Do not forward
browser Cookie or upstream Set-Cookie directly across the proxy boundary. Filter
on storage and delivery; an allowlist never authorizes an upstream request.
Use the existing Go cookie-jar implementation with public-suffix protection;
policy enforcement and bounds are additional requirements, not a new cookie parser.

`ReplacePolicies` installs a complete trusted active-resource snapshot. Omitted
scope normalizes to `resource`; case, domain ordering and duplicate domains are
normalized for comparison. Changed policies receive monotonically increasing
process-local generations and their old jars are immediately cleared. Removal
also clears jars. Restoring the old JSON creates a new generation, never a link
to old state. Unchanged policy snapshots retain jars. Unsupported/invalid or
oversized snapshots clear all jars and make the manager unavailable until a
valid snapshot is installed. Generation overflow also fails closed.

Integration must publish **every** committed resource-policy change, including
disable/removal and intermediate changes before a reversion. Polling only the
final JSON cannot discover a change that happened and reverted between polls.

Anonymous URL exceptions use a client without an authenticated jar even when
the browser also has a grant. They must discard upstream cookies and retain
existing URL/method and block-precedence checks. Cookie-dependent anonymous
workflows are not part of the first pilot.

## Interfaces and future caller contract

`NewUpstreamCookieJars(HostRoutingConfig)` requires trusted central/proxy names
for deployment-domain exclusions. It does not read browser credentials or
environment flags. The interfaces are intentionally not `http.CookieJar`, since
automatic client cookie/redirect handling cannot perform live authorization.

1. A trusted resource-update coordinator installs the complete active-resource
   snapshot through `ReplacePolicies`. `PolicyGeneration` identifies the
   installed policy for a resource. Publishing resource updates and authorizing
   against their generations must be coordinated; a generation read after an
   unrelated/stale resource lookup is not proof of a consistent snapshot.
2. `PrepareRequest(upstreamRequest, CookieAuthorizer)` receives an already safely
   constructed upstream request. The callback must validate current exact-host
   grant binding, central parent/session hash, account eligibility/auth_version,
   actual target and method, and the current winning resource. It supplies a
   `CookieAuthorization` with that resource's installed generation and parent
   deadline clipped to absolute and idle expiry. Grant possession alone is
   insufficient. A lookup failure must return an error, never anonymous access.
3. Preparation clones the request, removes browser `Cookie`/`Cookie2` regardless
   of header-name casing, and supplies only permitted upstream cookies. It
   reserves capacity before fetching and returns an `UpstreamCookieExchange`.
   Anonymous authorization must explicitly identify the authorized resource and
   generation and carry no parent fields; disabled and anonymous paths allocate
   no jar and send no cookies.
4. The future caller must use a client with `Jar=nil`, automatic redirects
   disabled, the existing validated-IP transport, and existing safe request
   header filtering. The manager performs no fetch, DNS lookup, redirect, body
   rewriting, or general header sanitization. Every redirect requires a separate
   authorized request/exchange; response request URL/method mismatches fail.
5. Before copying response headers, call `exchange.StoreResponse(ctx, response)`.
   It removes all `Set-Cookie`/`Set-Cookie2` headers even on failure, invokes live
   authorization again and requires the same parent/resource/generation and an
   unretired jar. Failure must prevent forwarding the response. Successful
   storage does not return any browser cookie. Anonymous/disabled responses
   discard cookies. A changed winner cannot deposit cookies in either resource.

This callback is a trusted Go integration boundary, not a new authentication
mechanism. The manager cannot verify a fabricated callback or independently
query the database. Production callback/update/lifecycle integration remains
unimplemented; the tests exercise this boundary with local fake authorization.

Bounded retained cookie records are rebuilt into Go's standard `cookiejar` with
the existing `golang.org/x/net/publicsuffix.List` dependency. Go performs
domain/path/Secure matching and sending order; manager metadata tracks expiry,
cookie replacement, policy and capacity because Go's private jar maps expose no
capacity accounting. No independent cookie parser is added: `http.ParseSetCookie`
and `http.Cookie.Valid` handle response syntax. Max-Age takes precedence over
Expires. Policy is checked when storing and sending. Retained fields are copied
out of raw headers/URLs so substrings cannot retain those larger buffers.

## Implemented bounds, retirement and privacy

Fixed initial jar bounds: 256 jars globally, 32 per parent session,
64 cookies and 64 KiB of stored cookie name/value data per jar, and 4 KiB per
cookie (name plus value). These are starting limits to test against pilot vendors,
not measured compatibility guarantees or exact Go heap bounds. They are separate
from grant capacity: possession of a grant does not reserve a jar.

At jar capacity, `PrepareRequest` returns `CookieJarCapacityError` for future
callers to map to generic HTTP 503 before fetching, retaining the existing grant
for retry. It does not evict another patron's live jar. Oversize or excess
incoming cookies are discarded rather than stored unboundedly. Never return
the rejected value in diagnostics. Expiry and cleanup
must also bound retained metadata and release cookie contents. No durable cookie
store or patron browsing-history table is proposed.

Additional metadata bounds are 1,024 active policies, 64 allowlisted domains per
policy, 128 bytes per resource/session ID or session hash, 253-byte DNS names,
4 KiB cookie paths, and 8 KiB raw Set-Cookie lines. At most 256 Set-Cookie lines
are considered per response. Invalid/oversize/excess cookies are silently
discarded, including oversized derived default paths. Only required cookie
fields and origin scheme/host are retained; no Raw/Unparsed headers or request
URLs are stored. Names/values/paths are detached from larger input buffers.
Go's transient matching jars are rebuilt from at most 64 bounded records, so
their private expired-cookie metadata cannot accumulate across operations.

Jars expire after 30 minutes idle or the validated parent deadline, whichever
comes first. Cookie Max-Age/Expires and deletion are enforced independently.
Operations sweep the bounded state, and `Cleanup` provides explicit maintenance
when idle. There is no background cleanup worker. Without maintenance or traffic,
expired state can remain allocated until the next sweep, within the fixed bounds.
Restart loses all cookie contents; no cookie persistence or new dependencies
are introduced.

Validate the parent session/user and current resource policy before using a jar.
Committed logout, explicit revocation, password reset, role change, disablement,
lock or deletion denies subsequent use. Remove affected jars/grants during
revocation/cleanup; cleanup is not the authorization check. Restoration and
enablement cannot revive the revoked parent session. Failed database validation
fails closed; in-flight requests already authorized may finish.

`RetireParent` clears all jars for a parent ID, including outstanding exchanges'
references. Late responses cannot repopulate retired jars. It stores no revoked
parent tombstones: subsequent requests must still pass live authorization.
Calling retirement without implementing that authorization is not session
revocation. Logout/account mutation integration will need to call retirement
after durable revocation; failed transactions must not claim durable revocation.

Browser grant/nonce cookies remain host-only `__Host-` cookies with Secure,
HttpOnly, Path=/ and no Domain. Central session/CSRF cookies remain central;
vendor dispatch must not process them or management API keys. Logs must omit
cookie values, grant/nonce/ticket tokens, target queries and patron search terms.

## Acceptance and next implementation boundary

`internal/proxy/upstream_cookies_test.go` covers separate users/logins, stored
session-hash binding, resource isolation on a shared host, permitted sibling-host
sharing, host-only/Domain/PSL/deployment exclusions, Secure/path matching,
disabled/anonymous operation, policy normalization/change/reversion/removal,
global/per-parent/cookie/metadata bounds, Max-Age/Expires/deletion, idle/parent
expiry, restart, rejected/changed authorization, response host binding, retirement,
concurrent use and browser/upstream cookie-header stripping. These are isolated
manager tests, not proof that a production authorizer/lifecycle is connected.

Before enabling traffic, test two browsers and two sessions for one user;
shared hosts/resources; disabled and unsupported cookie policies; host-only and
Domain cookies; public-suffix rejection; cookie/grant capacity; policy changes
and reversion; revocation/restoration; restart; database errors; hostile sibling
origins; cold assets/frames; legacy GET migration and unsafe-method rejection.
Verify that rejected operations neither fetch upstream nor mint credentials.

The [bounded pending-state foundation](pending-handoff-state.md) now implements
hashed opaque identifiers, trusted parent/mapping/authority and browser-nonce
bindings, expiry, capacity and cleanup as private state operations. Single-assignment
vendor preflight nonce binding is implemented in that store too. The store also
implements bounded ticket creation and atomic
confirmation. Bounded grants and atomic redemption are implemented as state
operations too. Live parent/user/authentication-version, registry, resource and
safety validation and vendor-return proofs are now implemented internally.
The central confirmation boundary specified in the revised
[HTTP/browser protocol review](cross-host-grants.md#httpbrowser-protocol-review-checkpoint)
is implemented, tested and available only through the experimental flag. The
experimental runtime now wires central/vendor controls and host-only cookie issuance behind `APP_EXPERIMENTAL_HANDOFF`. Its vendor preflight and redemption
share only the exact redemption path, followed by an inert receipt. Default URL
modes are unchanged; experimental mode blocks central-origin vendor content.
The bounded jar manager is implemented separately and remains unwired, as does
vendor content dispatch. The experimental central-origin migration boundary is
implemented; production rollout and live authorization/policy/jar integration
remain mandatory gates before delivery is enabled.
