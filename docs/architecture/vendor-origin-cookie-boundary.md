# First vendor-host deployment: origin and cookie boundaries

Status: an isolated bounded upstream jar manager is implemented and tested in
`internal/proxy/upstream_cookies.go` and `upstream_cookie_policy.go`. The internal
`internal/api/grant_cookies.go` coordinator now joins live grant validation,
database resource snapshots and jar preparation/response storage. It is not
constructed by the runtime or connected to routes, post-commit hooks or fetches. The experimental
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

The legacy session generator now fails closed instead of falling back to a
timestamp. `SessionStore.GetOrCreate` returns `(SessionInfo, error)` and requires
32 complete bytes from its cryptographic reader before allocating a jar or
issuing `odo_proxy_sid`. Production stores use `crypto/rand.Reader`; tests supply
empty/short readers on individual stores without changing process-wide entropy.
`FetchHandlerWithOptions` handles failure with a generic HTTP 500 and no-store,
without creating a session/cookie, reading the request body or fetching upstream.
Existing stored sessions can still be reused without generating another ID.
Normal legacy path/query/dual behavior and the separate authenticated manager
are unchanged. `internal/proxy/session_test.go` covers these failure and reuse
paths alongside the existing proxy cookie round-trip tests.

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

`ReplacePolicySnapshot(revision, activeResources)` now provides revision-aware
installation on the same manager. Entering this mode and every higher database
revision assign fresh generations to **all** active-resource policies, even if
their normalized JSON is unchanged. All old jars and outstanding exchanges are
retired under the manager's lock. This covers skipped intermediate changes and
reversions without storing policy history. Reinstalling the same revision and
equivalent normalized cookie policies retains jars and generations.

Older revisions are rejected without replacing current valid state. Unversioned
`ReplacePolicies` is permanently rejected once the revision-aware method has
been attempted, including after an initial failure. Invalid policy data, changed
cookie policies or a different active-resource set at an installed unchanged
revision, invalid negative revisions, snapshot-capacity failures and generation exhaustion
discard all jars/policies and fail closed. The highest nonnegative revision seen
is retained even after an installation failure. Recovery from invalidated state
must use that revision or newer and assigns fresh generations. Exhausted generation counters require a
restart. No failed operation can recover old cookies through a legacy installer
or a delayed lower revision. Tests in `upstream_cookie_snapshot_test.go` cover
these boundaries and concurrent preparation/storage during revision changes.

Integration must account for **every** committed resource-policy change,
including disable/removal and intermediate changes before a reversion. Polling
only the final JSON cannot discover a change that happened and reverted between
polls. The database revision described below makes those intervening writes
visible even when the resulting resource JSON is identical.

The resource-write transaction foundation is now implemented:
`db.Store.UpsertResource` and `DeleteResource` commit the resource mutation and
its existing audit event together. An audit failure rolls back the resource
change; a write failure creates no audit event. API writes and file imports
already use these methods. This removes the previous case where a resource
changed but an audit error made the write appear to have failed. Focused tests
in `internal/db/resource_transactions_test.go` inject both failure types.
These transactions do not yet publish policy generations or retire jars. File imports still
commit each resource separately, and a later import/revision error does not undo
earlier successful writes. The internal coordinator observes their persisted
revision on every cookie operation, independently of the import's final result.
Immediate post-commit publication/retirement hooks remain a separate step.

`db.Store.ResourceSnapshot()` now returns validated resources and their database
`Revision` from one read transaction. The additive `resource_state` table holds
one integer counter, not resource history, patron activity or cookies. Existing
databases start at revision zero with their resources preserved; repeated
migration and process restart retain the counter. This is an internal Go read
interface; resource JSON, import/export and HTTP API shapes are unchanged.

Every successful `UpsertResource` advances the counter, including identical
writes, cookie-policy reversion and disable/re-enable. Deleting an existing
resource advances it too; a missing deletion or rejected write does not. The
resource mutation, counter increment and audit commit or roll back together.
Missing/exhausted counter state rejects writes rather than wrap. Snapshot read
or validation failures return no configuration or usable revision. Snapshots
contain all resource statuses, so the coordinator selects active
resources when installing jar policies.

This global configuration revision is separate from the manager's per-resource
cookie-policy generations. The revision-aware installer implements conservative
retirement, including after unrelated or identical resource writes. The internal
coordinator calls it with active policies from the database snapshot before
allowing jar access. Comparing only the final policy would still revive cookies
after an unseen change/reversion. Reading a revision separately from the resources
being authorized is also unsafe. Snapshot reads do not reserve authorization
against later writes. The coordinator uses the Store guard below. The
experimental runtime constructs it for GET/HEAD vendor delivery; post-commit
retirement hooks remain unwired and production delivery stays disabled. Revision
tracking covers the Store write methods, including API and file-import calls;
direct SQL changes and writers from older binaries are outside this contract.

The first synchronization primitive is now implemented:
`db.Store.WithResourceSnapshot(use)` reads a fresh transactional snapshot and
holds a Store-local mutex until `use` returns. `UpsertResource` and
`DeleteResource` hold the same mutex through their resource/revision/audit
transaction, including commit or rollback. Guarded callbacks are serialized too.
The coordinator uses the same guard to keep snapshot publication, current resource
authorization and the complete jar preparation or response storage operation
inside one boundary. Locking only the `CookieAuthorizer` callback would leave a
gap before the manager accesses a jar and is insufficient.

The SQL read transaction finishes before the callback. Ordinary Store reads are
allowed there; DNS, network requests, resource writes and recursive guarded calls
must remain outside. Snapshot errors never invoke the callback, and all error
paths release the mutex. Callers still need to invalidate published cookie state
on lookup/publication failure. This primitive does not itself publish policies,
authorize grants, retire jars or serialize account/session changes.

The guard covers one shared Store instance only. Separate Store instances,
other processes and direct SQL writes do not participate; deployment must not
claim cross-process authorization consistency from this mutex. The
coordinator must use the same Store as API and import writers. Focused tests in
`internal/db/resource_coordination_test.go` exercise writes during guarded use,
fresh reads after commit, callback errors and failed snapshot reads.
`WithResourceAccess(use)` exposes the same guard without performing a read first,
so the manager's authorizer can read exactly one fresh snapshot per operation.
The guard covers the complete manager operation, including jar access after
authorization. It is not held while resolving DNS or waiting for vendor traffic.

## Internal live grant/cookie coordinator

`newGrantCookieCoordinator` constructs a private manager owned by one handoff
security instance. The runtime constructs exactly one per experimental handoff runtime, and experimental
vendor content delivery (`handoff_delivery.go`) uses it for every request and
response. Its `prepareRequest` and
`grantCookieExchange.storeResponse` methods:

1. Validate the canonical upstream URL and current DNS safety outside the Store
   guard. They perform no upstream fetch themselves. The prepared upstream
   request clears the server-side `Host` and `RequestURI`, so the proxy
   authority is never sent upstream. This preliminary check does not replace
   connection validation: the delivery handler's safe client dials only
   validated IPs.
2. Hold `WithResourceAccess` around the entire cookie-manager operation. The
   retained authorizer captures the grant token and exact authority, not a
   resource snapshot, winning-resource decision or cookie generation.
3. Read one fresh database resource snapshot per authorizer invocation and
   install its active policies with `ReplacePolicySnapshot`. Authorize the
   actual target and method against that same snapshot with existing matching
   precedence, then select that winner's installed generation. The grant does
   not select a resource or retain its original launch-resource association.
4. Reuse `grantParent` and `grantParentAuthorization` for exact registry/grant
   binding and live joined parent/account/hash/auth-version/expiry checks.
   Authenticated jar deadlines are the parent's idle/absolute expiry plus the
   manager's 30-minute jar inactivity timeout, not the grant TTL, so a patron's
   later handoff keeps an active jar. An expired grant still denies use until a
   new handoff. Each authorization reads the clock once, so grant lookup and
   deadline checks agree. Authorization itself writes nothing; after the
   Store guard is released, a successfully prepared request records parent
   session activity with the central `last_seen_at` throttle, so a patron
   actively browsing proxied content does not idle out. Denied requests and
   response-time rechecks record nothing, and an idle, expired or revoked
   parent is never revived.
5. Fail closed on snapshot lookup or publication errors, including stale
   revisions. `InvalidatePolicies` clears all jars/exchanges while preserving
   the manager's revision floor and generation counter. Recovery creates fresh
   generations. Invalid parent checks retire that trusted parent's jars lazily;
   an expired grant only denies, because one grant ending does not invalidate
   the parent. Failed database reads never count as proof of eligibility.

This coordinator requires a valid grant. If the current winning rule is an
explicit public exception, it supplies anonymous/cookieless authorization only
after the grant and parent pass; invalid credentials never downgrade to public
access. Grant-free anonymous delivery remains outside this increment.
Disabled cookie policies are also cookieless. Browser cookie headers are removed
by the manager, and response cookie headers are removed even when the wrapper
rejects a response before reaching the manager. A response from a retired
generation cannot store cookies after a revision change, including a skipped
change/reversion or an identical write.

Resource changes are observed at the next cookie operation. No access can pass
through this coordinator using the old revision after a participating write
commits, but idle jars are not proactively cleared at commit yet. Session changes
are not serialized by the resource guard: the existing rule that an operation
authorized before a concurrent revocation may finish still applies. Later
operations revalidate. Immediate lifecycle retirement hooks and idle
maintenance remain follow-up work; there is no second session store.

`internal/api/grant_cookies_test.go` covers local request/response round trips,
wrong host/target/method, current winners, disabled/deleted/changed resources,
policy reversions, partial imports, browser cookie stripping, concurrent users
and sessions, logout/password/account/role/hash/version changes, expirations,
lookup/publication failures and recovery, capacity exhaustion, cookieless rules,
response failures, and resource writes during DNS and guarded jar preparation.

Anonymous URL exceptions use a client without an authenticated jar even when
the browser also has a grant. They must discard upstream cookies and retain
existing URL/method and block-precedence checks. Cookie-dependent anonymous
workflows are not part of the first pilot.

## Interfaces and future caller contract

The first live-authorization integration step is implemented in
`internal/api/handoff_security.go:authorizeGrant`. The existing `validateGrant`
delegates to it. It reuses exact-host registry/grant, joined parent/account/hash/
`auth_version`, actual target/method, resource and DNS/SSRF checks, and returns
only the validated parent ID/hash, current winning resource ID and parent
deadline clipped to absolute and idle expiry. `authorizeGrant` denies access at
the exact idle deadline. It does not update session activity, cache authorization or create a
jar; failures return an empty result. Database-backed regression tests are in
`grant_authorization_test.go`.

This internal result deliberately has no cookie-policy generation. The cookie
coordinator reuses the shared parent validation helpers with its own guarded
resource snapshot instead of attaching a generation to this independent lookup.
Post-commit policy/session retirement remains separate work.
No HTTP handler obtains an upstream jar from this result; experimental delivery
uses the cookie coordinator instead, and production delivery stays disabled.

`NewUpstreamCookieJars(HostRoutingConfig)` requires trusted central/proxy names
for deployment-domain exclusions. It does not read browser credentials or
environment flags. The interfaces are intentionally not `http.CookieJar`, since
automatic client cookie/redirect handling cannot perform live authorization.

1. A trusted resource-update coordinator installs the complete active-resource
   snapshot and its revision through `ReplacePolicySnapshot`. `PolicyGeneration` identifies the
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
query the database. The internal coordinator provides database-backed callbacks;
runtime/update/lifecycle integration remains unfinished. Manager unit tests also
exercise the boundary separately with local fake authorization.

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
share only the exact redemption path, which then continues to the stored
target on the same proxy host (or an inert receipt). Default URL
modes are unchanged; experimental mode blocks central-origin vendor content.
The bounded jar manager and live authorization coordinator are implemented and
owned by the experimental runtime, which uses them for experimental GET/HEAD
vendor content delivery. Immediate lifecycle hooks remain unwired. The
experimental central-origin migration boundary is implemented; production
rollout remains a mandatory gate before delivery is enabled.
