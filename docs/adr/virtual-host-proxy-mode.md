# Stable launch URLs and virtual-host proxy routing

Status: proposed architecture; first review checkpoint, 2026-10-25.
Internal handoff security foundation implemented 2026-11-06; vendor delivery
remains disabled. See the implementation update at the end of this ADR.

## Problem and direction

Modern vendor applications assume paths belong to their own origin. Path proxying
requires increasingly complex rewriting of navigation, scripts, assets, frames,
and cookies. Introduce virtual-host routing as the preferred production mode
once its security and compatibility acceptance criteria pass. Keep path mode for
local testing and existing integrations. Virtual hosts improve origin fidelity;
they do not guarantee compatibility or bypass vendor anti-bot controls.

External library systems use one permanent application URL:

```text
https://odo.access.edu/launch?url=https%3A%2F%2Fwww.jstor.org%2Fstable%2F123
```

They must not need a resource ID or know the selected routing mode. Constructing
a launch redirect must never fetch vendor content. DNS safety checks are allowed;
HTTP requests to discover redirects, content, or hostnames are not.

## Original review inventory (2026-10-25)

Paths are relative to the repository root. This inventory describes inspected
code at the original review date, not current completion status.

| Area | Current implementation and evidence |
| --- | --- |
| URL strategy | `internal/proxy/urlstrategy.go` already defines `URLStrategy`, `BuildProxyURL`, `ParseProxyRequest`, and prefix generation. `urlstrategy_test.go` covers path/query output, escaped paths, and repeated-prefix normalization. |
| Modes | `APP_PROXY_URL_MODE` currently accepts `path`, `query`, and `dual`; default and `dual` generate path URLs. `virtual_host` warns and falls back to path. Both proxy request shapes are parsed regardless of generated URL mode. |
| Routes | `internal/api/server.go:Routes` registers `/odo`, `/odo/`, and legacy `/p`; there is no `/launch` or hostname registry. Application routes and proxy routes share one mux. |
| Resource policy | `internal/resources/resources.go` defines `Resource`, `DomainRule`, anonymous URL rules, validation, and `TestURL`. Active rules select a winning candidate; domain roles/actions, method constraints, and anonymous exceptions must remain effective. Resource IDs are not hostname ownership. |
| Target safety | `internal/proxy/safety.go` rejects unsafe schemes, IP literals, local names, userinfo, fragments, and non-default ports in normal production targets; validates DNS and supports validated-IP transport. `internal/api/proxy_handlers.go:proxyTarget` combines safety and resource checks. |
| Storage | `internal/db/db.go` stores resource JSON, configuration revisions, API keys, users, and browser sessions in SQLite. Resource writes already call validation. There are no mapping/ticket tables. |
| Browser authentication | `internal/api/auth_handlers.go` uses `odo_session` and `odo_csrf`; `safeNextPath` allows only selected local paths, not arbitrary URLs. `/launch` is not currently an allowed login return path. Local and SAML flows must both be reviewed. |
| Vendor sessions | `internal/proxy/session.go` holds upstream cookie jars in process memory keyed by `odo_proxy_sid`. Existing browser-session logout revokes the browser session and clears application cookies; it does not implement the proposed cross-host grant revocation. |
| Headers and rewriting | `internal/proxy/proxy.go`, `rewrite.go`, `jsshim.go`, and `missed.go` implement upstream headers, redirects, HTML/CSS/JS transformations, and recovery. Upstream request headers are allowlisted. Vendor CSP is currently suppressed; do not claim virtual-host CSP fidelity is already implemented. |
| Security middleware | `internal/api/middleware.go`, `security_headers.go`, and `internal/cookiepolicy` implement API scopes, session/CSRF and application header/cookie policy. Host dispatch must precede application routing and credential processing. |
| Deployment | `cmd/odo/main.go` validates production settings. Existing `docs/virtual-host-proxying.md` describes an earlier future direction and inactive placeholders; it is not an implemented hostname contract. |
| Tests and tooling | URL, navigation, PDF/frame, SSRF/rebinding, login/SAML, API and response-header tests exist under `internal/proxy` and `internal/api`. `Makefile` has build/test/install targets, no documentation checker. |

## Decision 1: persist mappings; derive defaults deterministically

Use SQLite for exact upstream-host-to-proxy-label records, with unique normalized
upstream hostname and unique label, and a many-to-many resource relationship.
A resource can reference many hosts; many resources can reference one host.
A mapping never grants access. Evaluate current resource policy, method rules,
explicit anonymous rules, and target safety on every request and redirect.

Generate the default label as `h-` plus lower-case, unpadded base32 of SHA-256 of
the normalized ASCII hostname (54 characters total). This fits a single DNS
label without truncating long upstream names. It is a lookup key, never decoded
into authority. Enforce uniqueness and fail closed on a hash/alias collision;
do not claim that a finite hash is mathematically collision-free.

Allow explicit readable aliases such as `jstor`, reserved transactionally in the
same label namespace. Reserve application/internal labels and the entire `h-`
namespace against friendly aliases. Keep the generated canonical address working
when an alias changes. Retire aliases without reassigning them to another host;
old bookmarks and cookies must never acquire a different vendor origin.

Normalize DNS names using the existing x/net IDNA package with an explicitly
selected lookup profile, lowercase ASCII and one terminal-dot normalization;
validate label and full-name lengths after conversion. Reject malformed IDNs,
IP literals, ports other than HTTPS 443, and proxy/application host loops.
No dot-to-hyphen decoding. Valid long vendor names use the fixed-length generated
label; reject names beyond DNS limits. Validate proxy FQDN length too.

Registry population is an administrative reconciliation operation from configured
exact hosts and explicitly approved concrete hosts covered by subdomain rules.
A wildcard rule is not a list of concrete hosts. Never register a host merely
because an untrusted URL or vendor response mentions it. Removing or disabling
the last authorizing resource disables routing immediately; retain a tombstone
for stable identity. Reconciliation/import needs atomic conflict handling.

Alternatives: pure deterministic encoding avoids tables but cannot cleanly manage
friendly aliases, tombstones and inspectable relationships. Fully manual labels
increase setup work and typo risk. Persistent generated defaults plus optional
aliases add one durable registry while keeping routine setup predictable.

## Decision 2: one launch contract with bounded raw-prefix compatibility

Canonical callers percent-encode the entire absolute HTTPS target as one `url`
value, once. Preserve the target's escaped path and raw query; never decode and
re-encode nested query values. Reject missing/duplicate envelope parameters,
malformed escaping, credentials, unsafe destinations and excessive input length.
Use generic public errors without disclosing private resource details.

Compatibility parser proposal: inspect `RawQuery`, requiring its first bytes to
be `url=`. If the remainder begins literally with `https://`, treat the entire
remainder as the raw target, with no outer query decoding or additional envelope
parameters. Otherwise use strict `url.ParseQuery`, requiring exactly one `url`
value and no other keys. Select the parsing branch once, before decoding; do not
repeatedly decode. Raw `&url=` inside the raw target is vendor data, not a second
launch parameter. In encoded mode duplicate `url` keys are an error.

For example, raw `url=https://vendor.example/search?a=1&b=2` must preserve both
vendor parameters. Go's ordinary `URL.Query().Get("url")` loses `b=2`; query
unescaping also turns `+` into space and consumes one percent-encoding layer.
Go's `ParseQuery` reports invalid escapes and raw semicolons; `URL.Query` drops
parse errors. See the [Go net/url contract](https://pkg.go.dev/net/url).

A literal browser `#` never reaches the server as query data. Canonical encoding
can carry a target fragment, but current safety validation rejects fragments:
retain that rejection for the launch MVP, documenting the limitation. A later
fragment-preservation design requires explicit approval. Raw prefix integrations
cannot promise lossless fragment or intermediary-reencoded input handling.
Document byte-level cases for `&`, `=`, `?`, `+`, `%`, Unicode and nested URLs in
the subsequent launch specification. Do not change `/login` parameter meanings;
no `/login?url=` alias in the MVP.

## Decision 3: isolate central credentials and vendor grants

Use a host-only `__Host-` central authentication cookie (Secure, HttpOnly, Path=/,
no Domain, SameSite=Lax). Keep central CSRF state host-only too. No application
API, admin page, login form, or API-key processing is available on vendor hosts.
No browser or API credentials are forwarded upstream. Never distribute a
parent-domain authentication or CSRF cookie.

Store pending destinations briefly on the server, referenced by an opaque random
continuation. Login returns only to a validated central continuation endpoint;
recheck destination policy after authentication. Do not broaden `safeNextPath`
to arbitrary external return URLs.

After login, issue a short-lived, single-use random launch ticket bound to the
central session, exact destination hostname/mapping, policy context and pending
target. Store only a hash of the ticket; consume atomically. Redeem at a reserved
vendor-host endpoint, set that host's Secure/HttpOnly `__Host-` proxy-grant cookie,
and immediately redirect to the clean vendor path. Prevent redemption CSRF and
ticket swapping with a host-only preflight binding nonce. Ticket endpoints must
be no-store/no-referrer, render no vendor assets and emit no analytics. Scrub
queries/tickets from reverse-proxy logs as well as Odo logs. Exact handoff and
cross-host frame/asset bootstrapping need specification before implementation.

Use server-side session references to revoke all host grants at central logout,
user disablement or explicit revocation. Clearing cookies on remote hosts is not
required for revocation. Scope vendor jars by patron/session and explicit vendor
cookie policy, never by a global browser cookie shared with admin credentials.

Sibling hosts are different origins but usually the same site. SameSite alone
is not CSRF protection against vendor scripts: require exact central Origin,
existing CSRF checks and restrictive central CORS, including login/logout flows.
Host-only cookies also do not make legacy path-mode vendor scripts safe to run
on the central origin. Production central authentication must not coexist with
path-mode vendor content on that origin; migration must redirect safe old GET
bookmarks into virtual hosts, or use a separate legacy origin. This is a release
gate, not a detail deferred until after routing is enabled. Cookie prefix behavior
is documented in [MDN Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie).

## Mode, host, API and deployment direction

Retain the current path default during development. Existing `query` and `dual`
semantics remain until an explicit migration introduces a separate canonical
output preference or a versioned mode change. Proposed `APP_PROXY_BASE_DOMAIN`
identifies the proxy suffix; existing `APP_PUBLIC_URL` identifies the central
application origin. In virtual-host production, unsupported configuration must
fail closed rather than silently fall back to path mode.

Central host dispatch uses configured authority, never arbitrary Host or forwarded
host values. Only exact registered single-label hosts below the proxy suffix may
reach vendor routing. Unknown hosts are rejected before cookies or authentication
are processed. Reverse proxies must preserve validated authority, overwrite
forwarded headers and prevent direct untrusted backend access. Wildcard DNS and
TLS are infrastructure requirements, not authorization.

Extend resource APIs and rules/test-url for relationship inspection and policy
preview; add registry list/preview/alias operations only where distinct registry
state requires them. Existing resource read/write scopes are candidates; no new
scope names are established here. Anonymous clients use launch redirects and
generic errors, with no public registry enumeration or target-fetch oracle.

Subsequent specifications will define API payloads/status codes, proposed SQLite
tables and transactions, DNS/TLS/Caddy/Apache deployment examples, compatibility
matrices and acceptance tests. Their names are the requested
`docs/architecture/virtual-host-routing.md`, `hostname-registry.md`, and
`launch-url-compatibility.md`; they are intentionally pending this checkpoint.

## Implementation order and release gates

1. Extend the existing URL strategy seam with explicit routing context; preserve
   path/query output and parsing. Inventory all URL construction call sites.
2. Implement normalization, registry, alias lifecycle and protected management
   APIs, with collision/concurrency tests and migration rollback planning.
3. Add mode-independent launch and continuation handling in path testing mode;
   verify byte-preserving prefix behavior, policy rejection and no upstream fetch.
4. Specify and implement host admission, central cookie isolation, ticket handoff,
   revocation, cookie-jar boundaries and reserved internal endpoint handling.
   Keep virtual-host traffic disabled until these work together.
5. Enable experimental virtual-host routing behind a disabled-by-default flag;
   adapt redirects, rewriting, CSP, CORS, iframe/assets and PDF workflows. Unknown
   hosts get bounded diagnostics and explicit deny/direct policies, no auto-enroll.
6. Supply wildcard DNS/TLS (including DNS-01 renewal) deployment examples before
   enabling a test deployment. Verify host forwarding and log redaction at edges.
7. Run vendor compatibility, browser isolation, DNS rebinding, open-redirect,
   replay/race, cross-host asset/frame, logout and migration/rollback tests.
   Only then recommend virtual-host production mode.

Acceptance gates: stable mappings across restart; collision failure without partial
writes; shared-host authorization unchanged; disable/delete enforced immediately;
unknown Host rejected; upstream dialing remains validated; no credentials cross
origin boundaries; replay/expired/swapped tickets fail; central logout revokes
all grants; complex encoded links preserve target bytes; raw limitations explicit;
no sensitive target/ticket logs; old GET bookmarks and rollback documented.

## Decisions for maintainer review

- Approve generated opaque canonical labels plus optional friendly aliases, with
  permanent non-reassignment of retired labels.
- Approve explicitly registered concrete hosts even when a policy permits a wider
  suffix; this trades automatic wildcard-host discovery for inspectability.
- Choose legacy path deployment separation versus redirect-only production
  migration; do not serve vendor scripts alongside central credentials.
- Confirm fragment rejection, raw compatibility parsing and no login alias.
- Set ticket/continuation limits and retention, exact nonce-binding protocol,
  iframe bootstrapping expectations, and shared-host resource-policy conflict
  behavior in the detailed specifications before runtime implementation.

## Implemented internal handoff security foundation

`internal/api/handoff_security.go` coordinates the bounded in-memory state in
`pending_handoffs.go`. It is internal and deliberately not constructed by the
HTTP server. No public handoff protocol, wildcard delivery, browser grant cookie,
content rewriting, or change to path/query proxying is enabled.

Pending browser handoffs last at most five minutes. Confirmation replaces a
prepared handoff with a cryptographically random, single-use 60-second ticket;
redemption atomically replaces that ticket with a host-specific grant lasting
at most 30 minutes. All lifetimes are capped by the original central session's
absolute expiration. Records include creation/expiration times, parent user and
session references, the captured account `auth_version`, and exact registry
hostname/label and proxy authority. Tokens and browser nonces are stored only as
SHA-256 hashes. Pending handoffs and tickets also bind the selected approved
resource ID (at most 128 bytes); confirmation and redemption reject a change to
the resource selected for that same target, even when the replacement permits
access. Tickets retain the approved destination only until redemption;
grants retain no destination or browsing history.

Vendor preparation now issues a separate 32-random-byte return proof, retaining
only its hash in the pending record. It lasts at most 60 seconds and is capped by
pending/parent expiry. Same-vendor-nonce retries replace that proof without
extending the pending deadline. Confirmation requires the proof as well as the
central session/nonce, and checks it again under the atomic transition lock.
This prevents confirmation based only on another browser having completed
preflight. Proofs are not retained in tickets/grants; HTTP cookie, Origin/CSRF and
redirect checks remain unimplemented prerequisites.

The coordinator verifies the complete central token before beginning or
confirming a handoff. Vendor operations require their own browser nonce and
never receive that central token. Issuance, confirmation, redemption, and grant
validation recheck the persistent registry, current resource/method policy and
existing DNS/SSRF validation. Grant validation takes the actual requested
upstream target and method: host enrollment alone never authorizes a resource.
These checks perform no fetch and do not update session activity timestamps.

Each redemption and grant use reads a joined session/account snapshot and
requires an active account, matching user and authentication version, matching
session hash, no revocation, and valid absolute and idle lifetimes. Central
logout revokes that session. Password, account status, role, deletion and
restoration changes transactionally advance the account authentication version
and revoke affected sessions. An old grant therefore cannot survive such a
change simply because its own TTL remains. Definitively invalid parents remove
all their local handoff state; absence represents local revocation rather than
retaining unbounded revocation tombstones. Database errors fail closed without
asserting successful revocation. No authentication result is cached.

Database validation and memory transitions are separate operations. A concurrent
revocation can occur after a validation snapshot; every subsequent use must
validate again, including any newly minted grant. Requests already authorized
before a security change may finish. This is not a cross-store transaction or a
promise to cancel requests already in flight.

State has hard limits of 256 pending records, 256 tickets, 4096 grants overall
and 64 grants per parent session. Retained fields are length-bounded. Expired
entries are reclaimed on operations; capacity exhaustion rejects new state and
preserves live entries for retry. Restart loses all state and requires a new
handoff. State is process-local: multiple replicas require a deliberate shared
storage/affinity design before deployment. No persistent patron destination
history or background worker is introduced.

Remaining delivery gates include the reviewed HTTP/browser handshake with
host-only nonce/grant cookies and CSRF defenses, validated-IP dialing on actual
fetches, session activity handling, origin-isolated upstream cookie jars,
redirect/content rewriting, wildcard DNS/TLS deployment, and end-to-end browser
and privacy testing. The current host guard continues rejecting vendor traffic.
