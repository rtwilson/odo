# Pending handoff state foundation

Implemented: `internal/api/pending_handoffs.go` and its focused tests. This is a
passive, package-private state store. The experimental runtime owns it through
`handoffSecurity`; database/DNS checks and HTTP cookie handling remain in the
coordinator/handlers, not in this store. Existing launch
continuations and path/query behavior are unchanged. Bounded tickets/grants,
atomic confirmation, vendor-return proofs and atomic ticket redemption are
implemented as state operations only. Handoff/grant HTTP behavior is enabled only with `APP_EXPERIMENTAL_HANDOFF`;
virtual-host content delivery remains disabled.

## Retained state and bounds

`create` generates an opaque 32-random-byte token with the existing
`local.NewToken`, retaining only its hash as the map key. Each record contains:

- Trusted parent session ID, stored session hash, user ID and `auth_version`.
- The upstream hostname/registry-label pair and full proxy authority.
- Hashes of the central browser nonce and, once prepared, the vendor browser
  nonce; no raw nonce is retained.
- One vendor-return proof hash and deadline after preparation; no raw proof is
  retained or recoverable through inspection.
- The approved resource ID, short-lived target, creation time and expiry, held
  only in process memory.

There are at most 256 entries. Expiry is the earlier of five minutes after
creation and the supplied parent absolute expiry. Exact expiry denies lookup.
Full capacity returns a private capacity error without evicting live entries.
Future HTTP callers must map that error to a generic 503.

The original parent absolute expiry is retained alongside the pending deadline.
Tickets have a separate 256-entry bound and expire at the earlier of 60 seconds
after confirmation and the parent absolute expiry. Confirmation may occur just
before the five-minute handoff deadline; its ticket can then outlive that consumed
handoff's deadline, but never the parent expiry. Token/nonce hashes, bindings and
the stored target transfer to the ticket; raw ticket tokens are not retained.

Every retained field is bounded: user/session ID, session hash and resource ID
to 128 bytes each, registry label
to 63, host/authority to 253 each, and target to the existing 16 KiB launch envelope
limit. Nonces and token lookup inputs must use the canonical 43-character token
format. Target parsing reuses the launch parser, requires HTTPS and a hostname
matching the trusted binding, and preserves legitimate vendor query parameters.
These are input/storage bounds, not a promise about exact Go heap consumption.

## Operations and caller obligations

`inspect` requires the token, central nonce and every binding field to match. All
mismatches return an empty result with the same false status. It returns a value
copy without consuming or extending the record. Failed lookups do not destroy
another browser's live state. Inspection is not authorization or ticket issuance.

`prepare` takes the opaque handoff token, trusted `db.ProxyHostname` identity,
admitted full proxy authority and canonical vendor browser nonce. Under the
store mutex it binds that nonce once and generates a fresh 32-random-byte return
proof, returning only that raw proof to the preflight caller. It takes no central
credentials and returns no target or parent details. The record's exact hostname,
label and authority must match before anything changes.

Only the nonce/proof hashes are retained. Proof expiry is the earlier of 60
seconds after preparation and the pending deadline, already capped by parent
expiry. Repeating preparation with the same nonce replaces the proof hash and
deadline, invalidating the previous confirmation link; it never extends pending
or parent expiry. A different nonce cannot replace the binding. Wrong mapping,
authority, malformed/unknown tokens, expiry and removed parents all fail without
modifying another live record. Randomness/collision failure preserves the record.
Preparation allocates no additional map entry and works at pending capacity.

A future vendor handler must admit the exact host and look up its mapping before
reading that host's nonce cookie. Only that preflight response may carry the raw
proof to the configured central callback. The coordinator's internal `preflight`
returns it for this purpose; the experimental vendor preflight phase invokes it after live validation. Central inspection
can see a hash but cannot recover the proof. Initial preparation in another
browser cannot be repaired by replacing its nonce; launch again.

The [HTTP/browser review](cross-host-grants.md#httpbrowser-protocol-review-checkpoint)
explains why session/nonce checks alone cannot prevent an initiator from splicing
another browser's preflight into their own confirmation. The new proof is
mandatory in both the coordinator and the atomic store transition. It does not
replace the Origin/CSRF checks required by future HTTP handlers.

`confirm` requires the original handoff token, complete trusted binding, central
browser nonce, a nonempty vendor preflight nonce hash, and the matching unexpired
return proof. Proof comparisons use the hash and constant-time comparison. It creates the ticket
and removes the pending record, including its proof, under the same mutex. The handoff can confirm only
once, including under concurrent attempts. Unknown/malformed/expired/unprepared
or swapped inputs return the same invalid-state error without a ticket or target.
Valid confirmation at ticket capacity returns a separate capacity error (future
HTTP 503), preserving the pending record, proof, browser bindings and expiry for retry.
Token-generation or collision failures also preserve the record. The proof must
still be live on retry; confirmation never renews it. Proof fields are not copied
into ticket or grant state. No live state
is evicted; expired tickets are removed before testing capacity. Tokens are checked
for collisions across pending, ticket and grant maps.

`inspectTicket` returns a value copy only for the ticket token and exact trusted
vendor hostname/label/authority and vendor nonce. It needs no central cookie or
nonce. Failure returns an empty record and false; failure cannot consume a live
ticket. Successful inspection neither consumes nor renews a ticket and is **not
redemption**. The target still comes from stored state, including legitimate
vendor parameters named `ticket` or `url`.

`redeem` requires the original ticket token and vendor nonce plus the complete
trusted binding, including the parent session ID/hash verified by the caller.
Under the same mutex, it creates a fresh opaque grant and consumes the ticket.
Only successful redemption returns the stored target separately for the eventual
redirect; the target never becomes grant state. Concurrent replay creates at most
one grant. Invalid, expired or swapped inputs return an invalid-ticket error and
no token/target, preserving live state.

Grants are bounded to 4,096 globally and 64 per parent session ID, counting all
stored-hash bindings of that parent together. Expired grants are purged before
checking limits. Both limits use the same capacity error (future HTTP 503);
capacity, randomness and collision failure preserve the live ticket for retry
without evicting another grant. Slot checks, creation and consumption share the
state lock, including when different tickets race for the final slot.

Grant lifetime is an inactivity deadline: initially the earlier of 30 minutes
after redemption and the original parent absolute expiry, retained through
ticket creation as the grant's fixed limit. `renewGrant` slides the deadline to
30 minutes after each fully authorized experimental delivery use (at most once
per minute) and never beyond that limit; it cannot revive an expired grant. It is not capped by
the consumed ticket's 60-second deadline. Each grant retains only its trusted
parent/host binding and expiry: no target, path/query, browser nonce, raw token,
resource ID or browsing history. Token keys remain hashes.

`inspectGrant` requires the opaque token and exact trusted registry mapping/full
proxy authority. It returns a value copy and never renews expiry. A successful
lookup is not authorization: the coordinator loads the parent session/user
using the trusted record and check stored-hash binding, revocation, absolute/idle
expiry, active status, user identity and `auth_version`, then current request
policy/method and DNS safety.
It must not fabricate a central browser cookie or cache a positive authorization.

`removeParent` erases pending, ticket and grant records for a trusted parent
session ID, including entries
with older stored-hash bindings. It is idempotent and preserves unrelated parents.
The internal live validator invokes it for definitively invalid parents; it
cannot replace durable database revocation and live validation.

All operations purge expired pending, ticket and grant records under the same
mutex; explicit `cleanup` is also available. There is no background sweeper. Expired targets are removed on
the next store operation, not necessarily while the process is idle. A newly
constructed store cannot recover an earlier store's tokens, including after restart.

Callers must obtain bindings from current authenticated session, registry and
trusted deployment state. The store checks field presence/size and target syntax;
it does not prove that a mapping is enrolled, that an authority is correctly
configured, or that a session is active. Current user/session validity, resource
and method policy, DNS/SSRF safety and host admission remain mandatory live checks.
Nothing here logs tokens, target URLs, cookies or parent references.

## Next boundary

Pending-to-ticket confirmation and ticket-to-grant redemption are atomic. `handoff_security.go` now checks live parent/user/version,
registry, original ticket resource/target, method policy and DNS safety. These
checks do not touch session timestamps or cache positive authorization; only the
cookie coordinator records throttled parent activity, and only after a delivered
vendor request is authorized (which may also renew the grant). Only the
experimental handoff runtime attaches this state to handlers.

Vendor-return proofs are now implemented and tested internally, including the
two-browser splice, nonce/proof replacement, exact expiry, capacity retry, parent
revocation and proof rotation during live validation. The revised
[cross-host protocol review](cross-host-grants.md#httpbrowser-protocol-review-checkpoint)
specifies the HTTP lifetime/retry rules and explicit Origin/CSRF-protected
central confirmation POST. `handoff_confirmation.go` implements that HTTP
boundary, wired into `Server.Routes` only in experimental handoff mode. It checks
unique prefixed
cookies, exact central authority/Origin, session-derived form CSRF and strict
bounded inputs. GET does not consume live state; POST rechecks live authorization
and current proof at the atomic transition. The experimental vendor control uses
the single redemption endpoint for
preflight, ticket exchange and an inert receipt. Cookie issuance and runtime
admission are enabled only by the off-by-default test flag; content delivery
remains disabled.

Memory cleanup does not replace durable revocation. Renewal requires a fresh
handoff, not inspection or a vendor asset request. Non-consuming inspection is
not authorization; there is no standalone consume API.

See [cross-host grants](cross-host-grants.md) and the
[origin/cookie checkpoint](vendor-origin-cookie-boundary.md) for the remaining
protocol, origin-separation, cookie-policy and deployment gates. This foundation
does not authorize enabling vendor traffic.
