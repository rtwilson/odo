# Cross-host grants and revocation

Status: protocol proposed, with implemented but unconnected pending storage and
single-assignment vendor preflight nonce binding in the
[pending-state foundation](pending-handoff-state.md). No handoff endpoints,
tables, cookies, tickets or grants are enabled. Virtual-host routing remains
disabled. The current local `/launch/continue` is not a host grant.

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

## Proposed top-level browser handoff

```mermaid
sequenceDiagram
    participant B as Browser
    participant C as Central host
    participant V as Registered vendor host
    B->>C: /launch with target
    C-->>B: Redirect to vendor prepare with opaque handoff ID
    B->>V: Prepare; establish host-only nonce
    V-->>B: Redirect to central confirmation with handoff ID
    B->>C: Confirm with central session and browser nonce cookies
    C-->>B: Redirect to vendor redemption with single-use ticket
    B->>V: Redeem with vendor nonce cookie
    V-->>B: Set host-only grant; redirect to clean vendor path
    B->>V: Request content with host grant
```

1. Central launch completes ordinary login if needed, then rechecks DNS safety,
   current resource policy and GET permission. The target must already have a
   canonical registry mapping. Store an opaque pending handoff bound to the
   authenticated parent session ID and stored session hash, central browser
   nonce hash, mapping identity, proxy authority, and target. The target stays
   server-side. Do not discover or register hosts from the target or responses.
2. Redirect to proposed vendor `/.well-known/odo/prepare?handoff=<id>`. Admit the
   exact registry host before inspecting its nonce cookie. Read or establish a
   Secure/HttpOnly/Path=/, SameSite=Lax, no-Domain `__Host-odo_grant_nonce` cookie. Bind its hash
   to that pending handoff atomically, once; later preparations must match that
   binding. Return only to the configured central confirmation endpoint.
3. Proposed central `/launch/handoff/confirm?handoff=<id>` requires the same
   currently authenticated parent session and central browser nonce. A copied
   handoff from another session/browser must fail. Verify vendor preflight,
   mapping identity, expiry and current target policy. Atomically consume the
   pending handoff and create one ticket bound to both nonce hashes, the parent
   session, exact vendor authority/mapping and stored target. Redirect to vendor
   `/.well-known/odo/redeem?ticket=<token>`. Never put a target or caller-supplied
   return URL in the handoff query.
4. Redemption requires the exact vendor authority and matching preflight nonce.
   Recheck parent session/user validity and current target safety/policy. Consume
   the ticket and create its grant in one atomic operation; duplicate redemption
   cannot produce two grants. Set Secure/HttpOnly/Path=/, no-Domain,
   SameSite=Lax `__Host-odo_proxy_grant`, then redirect to the validated target's
   vendor path/query taken from stored state, not the redemption query. Preserve
   legitimate vendor parameters even if named `ticket` or `url`. Reject reserved
   endpoint loops.

The proposed vendor control namespace is reserved and cannot proxy same-path
vendor content. Its handlers must never enter the central mux, process central
cookies/API keys, fetch vendor content, or render vendor/third-party assets.
Use no-store/no-referrer on every handoff response, including failures. Scrub
all handoff/ticket queries from Odo and edge logs. Tokens in redirects do not
authorize redemption without their browser binding and current parent session.
These top-level GET returns may lack Origin headers; browser/session/nonce
binding, not a broad exception to unsafe central Origin checks, protects them.

## State, bounds, and failures proposed for review

Use `local.NewToken` with 32 random bytes and `local.HashToken`; no custom
cryptography or signed target URLs are needed. Retain only token/nonce hashes
and trusted bindings in server-side records, alongside the short-lived target.

| State | Proposed lifetime and capacity |
| --- | --- |
| Pending authenticated handoffs | Five minutes; 256 globally |
| Redemption tickets | 60 seconds; 256 globally |
| Vendor grants | 30 minutes, capped by parent absolute expiry; 4,096 globally and 64 per parent session |

The existing pre-login continuation retains its separate five-minute/256 bounds.
Expired records must lose access immediately; cleanup must erase expired target
records during normal state operations. Full capacity returns 503 without
evicting live state or consuming a handoff/ticket needed for a retry. Restart,
expiry, or revocation requires a new central launch. Grant renewal requires a
fresh authenticated handoff; vendor assets cannot mint or extend grants.

Malformed, expired, swapped, unknown, or replayed control state receives a generic
404. Missing login at central confirmation receives 401 without moving a target
into the login URL. Policy/safety denial receives generic 403. Storage or
revocation uncertainty fails closed with 500; no vendor fetch follows it.
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

Then apply the actual request URL/method to current resource policy and use
validated-IP dialing. Shared-host resources retain the existing winning-rule
semantics; a grant is not owned by whichever resource first launched that host.
Redirects and cross-host rewrites need independent current checks. No positive
session/policy authorization cache may postpone revocation in this first design.

After committed logout, user-session revocation, password reset, disablement,
or lock, parent validation denies all affected grants and outstanding tickets.
Re-enabling a user does not resurrect revoked sessions. Remove their in-memory
state and jars during revocation/cleanup; remote cookie clearing is unnecessary.
Database failure is not evidence that a session is valid. Local cleanup cannot
substitute for a successful durable revocation transaction.

Revocation applies to authorization checks after the revocation commit. A request
already authorized may finish; this proposal does not cancel in-flight streams
or recall content already delivered. Test that boundary explicitly.

Vendor jars must be tied to the authenticated parent and an explicitly enforced
resource cookie policy before rollout. The current process-wide browser-jar
model cannot simply be shared across vendor hosts. Supported jar scopes,
disabled-policy behavior and cookie-domain enforcement need their own focused
specification; legacy resource import compatibility must be preserved.

## Cross-host assets and acceptance gates

The first handoff supports top-level GET navigation only. A vendor iframe, fetch,
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

Maintainer decisions at this checkpoint: approve or revise the four-step
handoff and limits, the reserved vendor namespace, single-process state, grant
renewal, jar policy, cold-host bootstrap expectations, and legacy-origin
separation. Bounded pending state is implemented without runtime integration.
Single-assignment vendor nonce binding is also implemented without handlers.
The next focused state-only batch is bounded ticket creation with an atomic
pending-to-ticket transition; all routes remain separate work. This document does not approve enabling
virtual-host traffic.
