# Cross-host grants and revocation

Status: implemented for isolated development/test handoff behind
`APP_EXPERIMENTAL_HANDOFF`, off by default and rejected in production. Bounded
hashed state, return proofs, tickets, grants, central confirmation and vendor
control HTTP integration are implemented. Experimental grant-authorized
GET/HEAD vendor content is available only behind the same flag; production
vendor delivery remains disabled.
The original endpoint proposal below is narrowed to one vendor redemption path;
preflight uses its `handoff` query phase, not a separate prepare endpoint. See
[runtime flags and fake-host tests](virtual-host-routing.md#experimental-runtime-and-trust-boundary).

The [origin and cookie boundary checkpoint](vendor-origin-cookie-boundary.md)
records concrete first-deployment recommendations and the current jar-model gap.
It is also proposed; it does not approve or enable vendor traffic.

## Existing foundations and gaps

`internal/api/launch_handlers.go` validates launch targets and supports local
login return through `launch_continuations.go`. `host_guard.go` rejects vendor
hosts before central authentication. `auth_handlers.go` uses prefixed central
cookies when guarded; `origin_guard.go` protects unsafe central operations.
Registry identity and live domain-policy inspection exist in `internal/db`.

Current vendor jars in `internal/proxy/session.go` use `odo_proxy_sid` and have
no parent browser-session revocation link. Resource CookiePolicy settings are
not enforced by this jar implementation. They cannot serve as host grants.

Logout now validates token ownership without session-touch writes and reports
lookup/revocation failures; see [logout behavior and audit policy](../security/logout.md).
Account-change revocation now has these foundations:

- `db.go:SetUserStatus` commits disable/lock and session revocation together.
  `PatchUser` does the same for disabled/locked status and effective role-set
  changes, including rollback of accompanying metadata. PATCH enforces last-admin status
  protection. Deletion, role changes, and status changes enforce the last-admin
  invariant under SQLite's writer lock, using current database state. PATCH applies
  only supplied fields to that current state, preserving omitted roles/status.
- Password resets now commit the new hash and session revocation together in
  `db.go:SetUserPassword`; revocation failure rolls back the password change and
  produces a generic API error. The post-commit password audit remains best-effort.
- Explicit user-session revocation increments the account security version and
  revokes sessions atomically, while retaining existing error reporting.
- Guarded browser-session insertion matches the active account's verified password
  hash and private security version. Security mutations increment that version in
  the same transaction as revocation, preventing pending logins from escaping it.
  Validation reads session/user state from one snapshot. See the full
  [account-security inventory and race boundary](../security/user-lifecycle.md).

A successful disable/lock or password reset commits the intended session
revocation atomically with its account change. Re-enabling does not clear those
revocations. Tests cover both insertion/revocation orders, concurrent login, role
changes, rollback, restoration and last-admin mutations. Already-authorized
requests may finish; revocation does not cancel in-flight streams.

## Proposed first deployment boundary

Use one Odo process for central and vendor hosts. Keep pending handoffs, tickets,
and grants in bounded process memory; persist no patron target URLs. Restart
invalidates all host grants and pending state, even if central browser sessions
are configured to survive restart. Multiple instances need a separate shared
state/affinity design before support is claimed.

Require central host admission, prefixed cookies, Origin checks, wildcard
DNS/TLS, and trusted edge forwarding. Central authentication must not share its
origin with path-mode vendor scripts: choose a separate legacy origin or a
redirect-only migration for safe old GET bookmarks before enabling host traffic.

Use canonical registered labels initially. A mapping identity is the existing
`(hostname, label)` pair, not a resource ID or a new invented registry ID.
Bind state to the full proxy authority as well, so deployment-name changes do
not reinterpret an old handoff. Registry membership never grants access.

## Current automatic browser continuation

The manual-confirmation checkpoint below records the original protocol design.
[Automatic handoff](automatic-handoff.md) now supersedes its requirement for a
Continue click: GET renders a CSP-hashed first-party script and hidden form;
the script sends the same Origin/CSRF-protected POST. GET itself cannot confirm.
The return proof, browser nonce, session binding, single-use ticket and live
resource checks remain. Opaque restart and grant-cookie verification controls
are described in that document. Development/test-only restrictions remain.

## HTTP/browser protocol review checkpoint

This revision replaces automatic GET confirmation with a central confirmation
page followed by an explicit POST. Vendor-return proofs are now mandatory in
the internal `prepare`/`confirm` operations. Central confirmation methods,
Origin/CSRF checks and cookie validation are implemented in HTTP handler. Central/vendor controls and cookie issuance are now wired only
in the experimental test mode; content delivery remains later work.

The nonce-only proposal had an incomplete browser correlation: an attacker
could initiate a handoff in their central session, cause a second browser to
prepare that handoff on the vendor host, and then confirm it from the original
session. The resulting ticket would be bound to the second browser's vendor
nonce. Knowing only that preflight happened is insufficient. Requiring central
CSRF alone would not fix this: the initiating attacker owns their own central
session and CSRF token.

A fresh opaque return proof must travel from vendor preflight to central
confirmation through the browser that owns the vendor nonce. The proof is never
retrievable from central pending-state inspection or by knowing a handoff ID.
An attacker who sends their handoff ID to a second browser cannot retrieve that
browser's return proof to confirm their own session. The second browser cannot
confirm the attacker's handoff because its central session/nonce does not match.
This relies on TLS, same-origin protections and suppression of URL/Location
leakage; proof possession is a bearer check, not browser fingerprinting.

### Endpoint ownership and methods proposed for review

| Host | Method and path | Proposed behavior |
| --- | --- | --- |
| Central | `GET /launch?url=...` and existing login continuation | Existing target validation/login, then begin a handoff only in a separately reviewed enabled mode. Current path/query behavior remains unchanged. |
| Registered vendor | `GET /.well-known/odo/redeem?handoff=...` | Admit the exact registry host, validate pending state, bind its vendor nonce, issue a return proof, then 303 to the configured central confirmation page. |
| Central | `GET /launch/handoff/confirm?handoff=...&proof=...` | Validate central session/nonce, return proof, live policy and expiry; render a plain confirmation form. Do not mint a ticket, consume the proof or redirect automatically to redemption. |
| Central | `POST /launch/handoff/confirm` | Require exact central Origin and session-derived CSRF, plus handoff/proof form fields. Recheck all bindings and live authorization, then atomically replace pending state/proof with one ticket; 303 to the exact vendor redemption endpoint. |
| Registered vendor | `GET /.well-known/odo/redeem?ticket=...` | Require the matching vendor nonce, recheck live authorization, and atomically replace the ticket with a host grant. Cookie issuance is a later implementation gate. |

All other methods receive 405 with an explicit Allow header and no state/cookie
changes. In particular HEAD must never initiate preflight or redeem a ticket,
even where Go's GET routing would ordinarily accept HEAD. No OPTIONS/CORS
credential allowance is introduced.

The reserved vendor control prefix is `/.well-known/odo/`. Exact endpoints are
handled by a separate control dispatcher. Unknown paths under that prefix
return generic 404 and never fall through to upstream content or the central
mux. Vendor content with colliding paths is unsupported. Central management,
authentication, legal/source notices and local continuations remain central.

Before any cookie/credential processing, validate request Host and any
absolute-form URL authority together against trusted deployment configuration.
Ignore untrusted Forwarded/X-Forwarded-Host. Only the exact registered vendor
mapping may enter vendor controls. Do not register hosts from requests. A
experimental dispatcher serves `/.well-known/odo/redeem` after exact registry
lookup and authority validation. Other vendor paths go only to experimental
grant-authorized GET/HEAD content delivery (see
[virtual-host routing](virtual-host-routing.md#experimental-vendor-content-delivery));
Odo's reserved `/.well-known/odo/` namespace, including the old separate
`/prepare` proposal, is rejected. With the flag off, the existing guard rejects
all vendor requests.

### Browser sequence and proof lifecycle

```mermaid
sequenceDiagram
    participant B as Browser
    participant C as Central host
    participant V as Registered vendor host
    B->>C: GET launch; central session and central nonce
    C-->>B: 303 to fixed vendor prepare with handoff ID
    B->>V: GET prepare; vendor nonce cookie
    V-->>B: 303 to fixed central confirmation with ID and new return proof
    B->>C: GET confirmation; central session and nonce cookies
    C-->>B: Plain confirmation form, no ticket
    B->>C: Explicit POST; Origin, CSRF, handoff ID and return proof
    C-->>B: 303 to fixed vendor redemption with one-use ticket
    B->>V: GET redeem; vendor nonce cookie
    V-->>B: Future host grant cookie and clean destination redirect
```

1. Begin after central login using the verified central session, user and
   `auth_version`, central browser nonce, exact registry mapping/authority,
   selected resource ID and approved target. The complete central session token,
   CSRF token and target never enter vendor-facing control URLs.
2. Vendor prepare must validate the handoff/host before setting a nonce cookie.
   Read the exact host-only vendor nonce cookie, or generate it securely if
   absent. A different nonce cannot replace an existing binding. Generate a
   fresh 32-random-byte return proof and retain only its hash in that pending
   record, bound to the same vendor nonce and host. It expires after at most
   60 seconds and never beyond the pending/parent deadline. It is distinct from
   the handoff ID, ticket and both nonce values.
3. Send the return proof only in a 303 Location to the configured central
   confirmation endpoint, alongside the handoff ID. Do not return it through
   JSON, reflected HTML, a caller-chosen callback, inspection APIs or diagnostic
   output. Failed preparation reveals no target, parent or expected nonce.
   A prepare retry with the same nonce may replace the proof hash; this
   invalidates the previous confirmation link without renewing pending expiry.
   A different nonce fails. Retain at most one proof hash per pending record,
   so there is no additional unbounded store or proof-retrieval API.
4. Central GET confirmation checks the proof and the original central browser
   and session. Render an escaped vendor hostname and a Continue button, with
   hidden handoff/proof and CSRF fields. Do not display patron target URLs or
   search terms. No script, third-party assets or automatic form submission is
   needed. A return GET may lack Origin; session/nonce/proof checks apply, and
   GET does not authorize the next state transition.
5. Central POST confirmation requires exactly the configured central HTTPS
   Origin and a CSRF value derived from the active central session. Reject
   absent, duplicate, sibling or malformed Origin, and `null` unless the
   browser also sends exactly `Sec-Fetch-Site: same-origin` (the no-referrer
   page makes real browsers send `Origin: null` on this form POST). This is a browser
   session operation with no bearer-key exemption. The confirmation
   handler uses `centralRequestOriginAllowed` directly, before reading credentials, so
   this protection does not depend on global management-API middleware covering
   the path. Existing API CSRF enforcement uses a header; confirmation explicitly
   compares its hidden form field against the same session-derived value. It
   accepts no header fallback. Do not put CSRF in URLs or relax management API
   header checks. Future registration must retain this handler-level boundary.
6. Recheck parent/user/version, registry, original selected resource, method,
   target safety, both nonce bindings, proof hash and all expirations. Compare
   the proof and atomically remove it with pending state only when the ticket
   insertion succeeds. Capacity/randomness failure preserves the current live
   pending state/proof for retry; neither expiry is extended. Competing POSTs
   produce at most one ticket. Expired proof confirmation fails without silently refreshing it. Browser
   recovery starts a fresh launch; an explicit same-nonce preflight retry can
   replace the proof only within the original pending/parent deadlines.
7. Vendor redemption uses the exact host and its nonce, without inspecting
   central session/CSRF cookies or management API keys. Recheck the trusted
   parent's live database state and original resource/target safety. Atomically
   consume the ticket and allocate the host grant; allocation failure leaves the
   live ticket usable for retry. A consumed ticket cannot be replayed to recover
   its raw grant. Loss of the response requires a fresh central launch.
8. Current successful redemption sets the exact-host grant cookie and 303
   redirects to the ticket's stored target path/query on the same proxy host,
   where experimental delivery authorizes it again; if that cannot be
   represented there, it falls back to the redemption path without query. That
   clean endpoint validates the live grant/parent and current domain policy, then
   displays only an inert completion receipt. No target is shown or fetched.
   Never accept a redemption return URL or concatenate an unchecked path into
   Location: a path beginning `//` must remain on the current vendor authority,
   using a URL built from that trusted authority and parsed upstream path/query. Preserve legitimate vendor
   parameters named `ticket` or `url`. Reject the reserved control prefix,
   including equivalent escaped/normalized forms, to avoid handler loops.

The future controls must reject noncanonical/ambiguous encodings of their
reserved paths and must not proxy a request that normalizes into that namespace.
Use exact documented query/form fields with bounded input, canonical token
syntax, no duplicate keys and no unknown parameters; confirmation POST accepts
only bounded `application/x-www-form-urlencoded` input (initial limit 4 KiB).
URL query parameters are decoded once. Do not merge query and body values for
POST. No raw nonce, central token, API key or patron target is a form field.

### Cookie contract proposed for review

| Cookie | Origin | Attributes and lifetime |
| --- | --- | --- |
| Existing `__Host-odo_session` | Central only | Existing Secure, HttpOnly, Path=/, no Domain, SameSite=Lax session policy remains unchanged. |
| Existing `__Host-odo_csrf` | Central only | Existing Secure, Path=/, no Domain, SameSite=Lax, readable by central UI; never shared with vendor origins. |
| New `__Host-odo_handoff_nonce` | Central only | Secure, HttpOnly, Path=/, no Domain, SameSite=Lax; at most five minutes. Separate from existing login-continuation nonce semantics. |
| New `__Host-odo_grant_nonce` | One registered vendor host | Secure, HttpOnly, Path=/, no Domain, SameSite=Lax; at most five minutes. |
| New `__Host-odo_proxy_grant` | One registered vendor host | Secure, HttpOnly, Path=/, no Domain, SameSite=Lax; Max-Age/Expires no later than the server grant's remaining lifetime. |

Do not accept legacy/unprefixed alternatives or client-provided nonce fields.
Validate cookie uniqueness and token syntax, rejecting duplicate active cookie
names instead of depending on header order. Reuse a valid nonce while its cookie
is present, without rotating it on another tab's launch. Existing shorter cookie
lifetimes may cause a handoff to fail and restart. Do not clear shared nonce
cookies on successful redemption or generic failure: another tab may still need
them. Server-side expiry/bindings remain authoritative. If a fresh nonce replaces
an expired/missing cookie, old pending state is not rebound; launch again.

Different tabs may create independent handoffs on the same parent/vendor nonce.
Each has its own one-use return proof and ticket. One grant cookie per vendor
host means later successful redemptions can replace that cookie; older server
grants still count toward capacity until cleanup/expiry. Logging into another
central session does not reparent old grants. Parent revocation prevents their
use without cross-host cookie deletion. Reserved Odo cookie names must never be
set, overwritten or reflected by upstream vendor responses when delivery is
implemented. This is a prerequisite for cookie isolation, not implemented here.

### Headers, redirects and privacy

Apply `Cache-Control: no-store`, `Referrer-Policy: no-referrer`,
`X-Content-Type-Options: nosniff`, frame denial and a restrictive application CSP
to every control response, including redirects and errors. The confirmation
page needs no script; use `default-src 'none'; base-uri 'none'; object-src 'none';
frame-ancestors 'none'; form-action 'self'` with a suitable explicit style policy.
Because browsers apply `form-action` to the POST's 303 to the vendor host, the
rendered confirmation page adds exactly that pending handoff's registered proxy
origin to `form-action`; nothing else is widened.
Never use vendor response headers or vendor/third-party assets on controls.
Do not run preflight or redemption through the vendor content response policy.

The only allowed redirect authorities are configured central and the exact
registered vendor bound to state. Browser-supplied Host is validated, not copied
into Location. There are no `next`, `redirect_uri` or `return_to` parameters.
Return-proof/ticket URLs can appear transiently in browser history; no-store
and no-referrer do not erase history. Browser history/extension access and
cooperating users who share complete callback URLs are outside this binding's
protection. Keep lifetimes short and require the bound browser state.

Odo and edge logs must omit full handoff queries, form bodies, Cookie,
Authorization and Set-Cookie headers, and Location values. Use fixed control
route labels, generic outcomes/status and existing request IDs. Even debug logs,
error wrapping and monitoring must not record tokens, proofs or patron targets.
The edge/CDN must suppress these fields before a pilot; application sanitization
cannot undo an upstream access log. Existing access-log behavior needs an
explicit regression check for each future route; do not claim edge scrubbing
is implemented by this proposal.

## State, bounds, and failures proposed for review

Use `local.NewToken` with 32 random bytes and `local.HashToken`; no custom
cryptography or signed target URLs are needed. Retain only token/nonce hashes
and trusted bindings in server-side records, alongside the short-lived target.

| State | Lifetime and capacity |
| --- | --- |
| Pending authenticated handoffs | Five minutes; 256 globally |
| Vendor-return proof (implemented internally) | At most 60 seconds, capped by pending/parent expiry; one hash per pending record |
| Redemption tickets | 60 seconds; 256 globally |
| Vendor grants | 30 minutes of inactivity (renewed by authorized use), capped by parent absolute expiry; 4,096 globally and 64 per parent session |

The existing pre-login continuation retains its separate five-minute bound, with 1,024 entries that evict the oldest when full.
Expired records must lose access immediately; cleanup must erase expired target
records during normal state operations. Full capacity returns 503 without
evicting live state or consuming a handoff/ticket needed for a retry. Restart,
expiry, or revocation requires a new central launch. Grant renewal requires a
fresh authenticated handoff; vendor assets cannot mint or extend grants.

Malformed, expired, swapped, unknown, or replayed control state receives a generic
404. Missing login at central confirmation receives 401 without moving a target
into the login URL. Policy/safety denial receives generic 403. Database or
revocation uncertainty and unexpected internal failures return generic 500; no
vendor fetch follows them. CSRF/Origin failure returns generic 403 before state
transitions. Wrong methods return 405. Oversized form bodies return 413;
unsupported form types return 415; ambiguous field encoding returns generic 400.
Capacity exhaustion returns 503, with an optional short Retry-After and no
automatic retry loop. Missing confirmation login returns 401 with a fixed local
login link, never an attacker-provided next URL. After login the user launches
again; the old handoff is not reassigned to a new session.
Responses expose neither private resource details nor expected nonce/session IDs.

## Grant validation and revocation

A grant contains no lasting target URL and grants no resource-policy bypass.
Explicit anonymous URL exceptions retain their existing URL/method and block
precedence checks. Such a request need not mint or redeem a grant; it must not
borrow another patron's authenticated jar or turn anonymous access into a
host-wide authorization. Registry, safety and resource checks still apply.

For vendor requests requiring login, validate the opaque cookie hash, exact mapping and
authority, grant expiry, and trusted parent session reference. Load the parent
session and user; check stored session-hash binding, revocation, absolute/idle
expiry and active user status. Reuse current throttled session-touch semantics
only after successful authorization. Do not synthesize a central cookie or
accept a plain session ID supplied by a vendor client.

Captured parent user identity and `auth_version` must also match the current
account snapshot. Tickets remain bound to the original selected resource ID;
grants retain no resource ID or target.

Then apply the actual request URL/method to current resource policy and use
validated-IP dialing. Shared-host resources retain the existing winning-rule
semantics; a grant is not owned by whichever resource first launched that host.
Redirects and cross-host rewrites need independent current checks. No positive
session/policy authorization cache may postpone revocation in this first design.

After committed logout, user-session revocation, password reset, disablement,
lock, deletion or role change, parent validation denies all affected grants and outstanding tickets.
Re-enabling a user does not resurrect revoked sessions. Remove their in-memory
state and jars during revocation/cleanup; remote cookie clearing is unnecessary.
Database failure is not evidence that a session is valid. Local cleanup cannot
substitute for a successful durable revocation transaction.

Revocation applies to authorization checks after the revocation commit. A request
already authorized may finish; this proposal does not cancel in-flight streams
or recall content already delivered. Test that boundary explicitly.

Vendor jars must be tied to the authenticated parent and an explicitly enforced
resource cookie policy before rollout. The legacy browser-selected jar model
cannot simply be shared across vendor hosts. The isolated manager now enforces
resource scope, disabled/anonymous cookieless behavior, allowed domains and policy
retirement; see [the cookie boundary](vendor-origin-cookie-boundary.md).
The internal grant/cookie coordinator now validates live authorization and
publishes a guarded resource snapshot on every request/response cookie operation.
The experimental runtime owns one coordinator for vendor content delivery and
registers post-commit retirement hooks for resource and session changes. Legacy
resource import
compatibility is preserved.

## Cross-host assets and acceptance gates

The first handoff starts from top-level GET navigation, with the explicit central
confirmation POST above. A vendor iframe, fetch,
or asset request without a valid host grant must not trigger login redirects,
silently enroll a host, or mint credentials. Return a bounded 401 response.
Before vendor rollout, choose explicit pre-approved host warm-up or restrict
testing to workflows whose required hosts have top-level grants. Automatic
vendor-response discovery is excluded. Cold cross-host assets/frames are not
claimed to work by this proposal.

Acceptance tests must cover two browsers and sessions, hostile sibling origins,
wrong Host/mapping/nonce, token swapping, exact expiry, capacity, concurrent
preparation/redemption, replay, DB failure, resource change, DNS rebinding,
logout/revocation races, disable then re-enable, password reset, restart,
anonymous URL/method exceptions and block precedence, and
no sensitive logs or upstream fetches during handoff. Include vendor endpoint
collisions, cold assets/frames and legacy-origin migration tests before rollout.

## Review outcome and next implementation milestone

The proposed endpoint ownership, explicit confirmation POST, return-proof
requirement, cookie table, failure mapping and privacy rules above are concrete
review choices. No endpoints or delivery are authorized by this document.
Existing internal state already enforces parent/user/version, exact registry
host, original ticket resource/target, lifetime/capacity and atomic transitions;
it now also enforces return proofs. `handoff_confirmation.go` implements the
central confirmation HTTP boundary, including GET rendering, strict POST
Origin/CSRF checks, unique prefixed cookie validation and bounded input parsing.
`APP_EXPERIMENTAL_HANDOFF=true` now connects it to `Server.Routes` and launch
in development/test. The flag requires host admission, rejects production and
blocks central-origin vendor content/recovery while on. The default server
retains existing path/query operation.

The **internal vendor-return-proof state and validation** batch is implemented
in the existing pending record, without a separate store, routes or cookies.
Regression tests cover these conditions:

- Attacker begins in session A; browser B prepares using nonce B. Session A
  cannot confirm with just the handoff ID and its own CSRF/central nonce, or a
  proof for a different handoff. Session B cannot confirm A's handoff even with
  its valid return proof. Neither path mints a ticket or grant.
- A fresh valid proof completes the same-browser flow once. Proofs for another
  host, nonce or pending record, manipulated proofs, missing proofs and exact
  expiry fail without consuming another browser's live state.
- Repeated preflight from the same vendor nonce replaces only that pending
  record's proof; different nonces cannot replace it. Retry does not renew
  pending expiry, bypass capacity, or expose a stored raw proof.
- Concurrent confirmations create at most one ticket. Database/policy failure
  and ticket-capacity failure preserve live retry state without false success.
  Parent revocation and restart invalidate the proof with its pending record.

Central confirmation is implemented as a separately constructed, tested handler.
GET does not consume live state or touch sessions; POST revalidates and checks
proof expiry again with a fresh clock at the atomic transition. It emits a 303
only to the stored registered vendor redemption endpoint. It creates no cookies
or grants and fetches no upstream content. Malformed/duplicate fields, unknown
parameters, POST query strings, duplicate active cookies, encoded path aliases
and unsupported methods are rejected. The shared central-authority predicate
preserves the existing host guard; the confirmation handler applies it even
when constructed independently of the running mux.

The vendor HTTP control is now implemented and registered only in experimental
mode. Preflight and ticket exchange share `/.well-known/odo/redeem`; a clean GET
there validates the live grant and renders the inert receipt; redemption itself
continues to the stored target on the same proxy host. No separate vendor
prepare endpoint is admitted. Cookie issuance is host-only, Secure, HttpOnly,
SameSite=Lax and Path=/; no central credentials are copied. All other vendor
paths, including management routes, are blocked before central authentication.

End-to-end local TLS/cookie-jar tests exercise login continuation, nonce/proof
confirmation, redemption, replay and concurrency, policy/registry changes,
revocation, password/account changes, host spoofing, cookie isolation, state
capacity, transaction rollback, default URL modes and all access-log formats.
No public DNS, upstream vendor request or upstream jar is involved. See the
[routing guide](virtual-host-routing.md#repeatable-local-test-with-fake-hostnames)
for exact commands and current limits.

Bounded parent/resource upstream cookie jars are now implemented as an isolated
manager, with policy generations, cookie filtering and capacity/cleanup tests.
An internal coordinator now joins live grant/parent validation and guarded
resource snapshots to request/response cookie operations. The experimental
runtime owns one coordinator and uses it for grant-authorized GET/HEAD vendor
content delivery with actual-target authorization and validated-IP dialing on
each fetch. Experimental central-origin migration now redirects only
validated legacy GET bookmarks to central launch and rejects HEAD/unsafe methods
without replay; recovery and diagnostic vendor body previews remain blocked.
The next milestones are vendor URL rewriting and cross-host rules, plus
production origin rollout. Do not
treat this experimental delivery path as approval to enable production vendor
delivery.

Origin separation, authenticated upstream jar isolation, validated-IP fetches,
rewriting, cold-host behavior and DNS/TLS remain separate delivery gates. Do not
relax production's virtual-host rejection or existing path/query behavior as a
side effect of implementing the control handshake.
