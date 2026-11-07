# Pending handoff state foundation

Implemented: `internal/api/pending_handoffs.go` and its focused tests. This is a
passive, package-private state store, not connected to `Server`, routes, cookies,
database operations, DNS, upstream fetching or vendor dispatch. Existing launch
continuations and path/query behavior are unchanged. Bounded tickets/grants,
atomic confirmation, and atomic ticket redemption are implemented as state
operations only. No handoff/grant HTTP behavior or virtual-host delivery is enabled.

## Retained state and bounds

`create` generates an opaque 32-random-byte token with the existing
`local.NewToken`, retaining only its hash as the map key. Each record contains:

- Trusted parent session ID and stored session hash.
- The upstream hostname/registry-label pair and full proxy authority.
- Hashes of the central browser nonce and, once prepared, the vendor browser
  nonce; no raw nonce is retained.
- The short-lived target and expiry, held only in process memory.

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

Every retained field is bounded: session ID/hash to 128 bytes each, registry label
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

`bindVendorNonce` binds the first vendor nonce under the store's existing mutex.
It takes the opaque handoff token, a trusted `db.ProxyHostname` identity, the
admitted full proxy authority, and a canonical vendor nonce. It does not take
central cookies, the central nonce, or a client-supplied parent-session ID, and
returns only a boolean, never the target or parent details. The record's exact
hostname, label and authority must match before anything changes.

Only the vendor nonce hash is retained. Repeating the same nonce succeeds
idempotently; a different nonce cannot replace it. Wrong host/mapping/authority,
malformed or unknown tokens/nonces, expired records and removed parents all fail
without modifying another live record. Preparation neither extends expiry nor
consumes/allocates an entry, so existing entries can prepare at full capacity.
Expired entries are purged during preparation as on every other store operation.
There is no endpoint or cookie issuance yet; this is state binding, not a grant.

The future vendor handler must admit the exact host and look up its mapping
before inspecting a nonce cookie or calling this method. It must use that host's
cookie, not a query-supplied nonce. A stolen handoff ID alone cannot authorize
central confirmation: that later operation still requires its original central
browser/session binding and all current authorization checks. Initial preparation
by a different browser cannot be repaired by replacing its nonce; a fresh launch
is required. No current handler invokes this behavior.

`confirm` requires the original handoff token, complete trusted binding, central
browser nonce, and a nonempty vendor preflight nonce hash. It creates the ticket
and removes the pending record under the same mutex. The handoff can confirm only
once, including under concurrent attempts. Unknown/malformed/expired/unprepared
or swapped inputs return the same invalid-state error without a ticket or target.
Valid confirmation at ticket capacity returns a separate capacity error (future
HTTP 503), preserving the pending record, browser bindings and expiry for retry.
Token-generation or collision failures also preserve the record. No live state
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

Grant lifetime is the earlier of 30 minutes after redemption and the original
parent absolute expiry, retained through ticket creation. It is not capped by
the consumed ticket's 60-second deadline. Each grant retains only its trusted
parent/host binding and expiry: no target, path/query, browser nonce, raw token,
resource ID or browsing history. Token keys remain hashes.

`inspectGrant` requires the opaque token and exact trusted registry mapping/full
proxy authority. It returns a value copy and never renews expiry. A successful
lookup is not authorization: the future caller must load the parent session/user
using the trusted record and check stored-hash binding, revocation, absolute/idle
expiry and active status, then current request policy/method and DNS safety.
It must not fabricate a central browser cookie or cache a positive authorization.

`removeParent` erases pending, ticket and grant records for a trusted parent
session ID, including entries
with older stored-hash bindings. It is idempotent and preserves unrelated parents.
It is not connected to runtime revocation yet and cannot replace database checks.

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

Pending-to-ticket confirmation and ticket-to-grant redemption are now atomic,
without HTTP routes. The next batch is live validation of the trusted parent
session reference, still without enabling vendor routing. Later HTTP confirmation,
redemption and grant use must independently check current parent/user eligibility,
registry, policy, method and DNS safety. Memory cleanup does not replace durable
revocation. Renewal requires a new authenticated handoff, not inspection or a
vendor asset request. Non-consuming inspection alone is not authorization or
redemption; there is no standalone consume API.

See [cross-host grants](cross-host-grants.md) and the
[origin/cookie checkpoint](vendor-origin-cookie-boundary.md) for the remaining
protocol, origin-separation, cookie-policy and deployment gates. This foundation
does not authorize enabling vendor traffic.
