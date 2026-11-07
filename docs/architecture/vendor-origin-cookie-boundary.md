# First vendor-host deployment: origin and cookie boundaries

Status: concrete recommendations for maintainer review. Documentation only;
none of these deployment switches, jar policies, routes or limits are enabled.
Virtual-host delivery remains rejected in production.

This checkpoint complements [cross-host grants](cross-host-grants.md). The
account-security transactions are implemented; the grant protocol and the
boundaries below still need approval and implementation before vendor traffic.

## Recommended first deployment

| Decision | Recommended first scope |
| --- | --- |
| Processes | One Odo process; no multi-instance grant/jar sharing. |
| Routing identities | Canonical registry labels only, bound to the configured full proxy authority. No request-driven enrollment or readable aliases. |
| Grant handoff | The proposed prepare → central confirmation → redeem flow, with browser nonces, parent-session binding and single-use tickets. |
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

The current `Routes` in `internal/api/server.go` deliberately still serves
`/odo` path/query traffic on the central host. `APP_HOST_GUARD=true` alone does
not isolate vendor scripts. Do not describe the current guard as that isolation.

Before enabling vendor-host delivery, the new mode must:

1. Remove central-origin vendor content delivery, including `/odo` and any
   fallback/recovery path that can reach the proxy handler. Review diagnostics
   separately to ensure they never render untrusted vendor HTML as central HTML.
2. Accept only supported old GET bookmark forms for a redirect through the
   validated central launch workflow. Retain target parsing, current policy,
   method and SSRF checks. Never fetch a vendor merely to discover a destination.
3. Reject legacy unsafe-method requests instead of replaying their bodies across
   origins. HEAD must not initiate an authentication handoff. Malformed targets
   fail without fetching content or setting vendor credentials.
4. Use configured authorities, not request-supplied return URLs. Apply no-store,
   no-referrer and query/token log suppression through the migration/handoff.

This mode-specific migration must preserve existing path/query/dual deployments
when virtual-host mode is not selected. A separate legacy content deployment is
a possible later alternative, but shared central credentials and ad hoc
cross-origin session copying are outside the recommended first deployment.

## Existing cookie model and implementation gap

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

Consequently the documentation's resource-scoped-cookie intent is not yet a
runtime guarantee. Do not reuse this jar store unchanged for grants, and do not
claim this design changes existing path-mode behavior.

## Recommended authenticated jar rules

Resolve the request through the existing live resource/method policy first.
Use its winning `ResourceID` to load that resource's current cookie policy. Do
not change resource matching, merge competing policies or attach the grant to
the resource that happened to launch the hostname first. A missing/changed
resource must never fall back to a different resource's jar.

The server-side jar identity is the parent session ID and stored session-hash
binding, the winning resource ID, and the normalized cookie-policy identity.
The browser cannot choose these values through a cookie, header or query string.
Different parent sessions, including two logins for the same user, remain
isolated. Hosts authorized by the same resource can share permitted vendor
cookies within that parent. Grants still require independent exact-host checks.

Recommended policy interpretation:

| Existing field/state | Proposed vendor-mode behavior |
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

Policy retirement needs an explicit generation/retirement rule, not only a
content hash: restoring the old JSON must not reconnect an old jar. The jar
implementation batch must establish and test this before rollout.

Anonymous URL exceptions use a client without an authenticated jar even when
the browser also has a grant. They must discard upstream cookies and retain
existing URL/method and block-precedence checks. Cookie-dependent anonymous
workflows are not part of the first pilot.

## Bounds, revocation and privacy

Proposed initial jar bounds for review: 256 jars globally, 32 per parent session,
64 cookies and 64 KiB of stored cookie name/value data per jar, and 4 KiB per
cookie. These are starting limits to test against pilot vendors, not measured
compatibility guarantees or exact Go heap bounds. They are separate from grant
capacity: possession of a grant does not reserve a jar.

At jar capacity, return a generic 503 before fetching, retaining the existing
grant for retry; do not evict another patron's live jar. Oversize or excess incoming cookies are discarded rather than stored
unboundedly. Never return the rejected value in diagnostics. Expiry and cleanup
must also bound retained metadata and release cookie contents. No durable cookie
store or patron browsing-history table is proposed.

Validate the parent session/user and current resource policy before using a jar.
Committed logout, explicit revocation, password reset, role change, disablement,
lock or deletion denies subsequent use. Remove affected jars/grants during
revocation/cleanup; cleanup is not the authorization check. Restoration and
enablement cannot revive the revoked parent session. Failed database validation
fails closed; in-flight requests already authorized may finish.

Browser grant/nonce cookies remain host-only `__Host-` cookies with Secure,
HttpOnly, Path=/ and no Domain. Central session/CSRF cookies remain central;
vendor dispatch must not process them or management API keys. Logs must omit
cookie values, grant/nonce/ticket tokens, target queries and patron search terms.

## Acceptance and next implementation boundary

Before enabling traffic, test two browsers and two sessions for one user;
shared hosts/resources; disabled and unsupported cookie policies; host-only and
Domain cookies; public-suffix rejection; cookie/grant capacity; policy changes
and reversion; revocation/restoration; restart; database errors; hostile sibling
origins; cold assets/frames; legacy GET migration and unsafe-method rejection.
Verify that rejected operations neither fetch upstream nor mint credentials.

The [bounded pending-state foundation](pending-handoff-state.md) now implements
hashed opaque identifiers, trusted parent/mapping/authority and browser-nonce
bindings, expiry, capacity and cleanup without runtime integration. Single-assignment
vendor preflight nonce binding is implemented in that store too. The next
state-only batch is bounded ticket creation and atomic confirmation. Routes,
cookies, ticket redemption, jars and vendor dispatch remain separate work. Origin
migration and jar enforcement remain mandatory gates before delivery is enabled.
