# Pending handoff state foundation

Implemented: `internal/api/pending_handoffs.go` and its focused tests. This is a
passive, package-private state store, not connected to `Server`, routes, cookies,
database operations, DNS, upstream fetching or vendor dispatch. Existing launch
continuations and path/query behavior are unchanged. Bounded tickets and atomic
confirmation are implemented as state operations only. Ticket redemption, grants
and virtual-host delivery remain unimplemented/disabled.

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
for collisions across both pending and ticket maps.

`inspectTicket` returns a value copy only for the ticket token and exact trusted
vendor hostname/label/authority and vendor nonce. It needs no central cookie or
nonce. Failure returns an empty record and false; failure cannot consume a live
ticket. Successful inspection neither consumes nor renews a ticket and is **not
redemption**. The target still comes from stored state, including legitimate
vendor parameters named `ticket` or `url`.

`removeParent` erases pending and ticket records for a trusted parent session ID, including entries
with older stored-hash bindings. It is idempotent and preserves unrelated parents.
It is not connected to runtime revocation yet and cannot replace database checks.

All operations purge expired pending and ticket records under the same mutex; explicit `cleanup` is
also available. There is no background sweeper. Expired targets are removed on
the next store operation, not necessarily while the process is idle. A newly
constructed store cannot recover an earlier store's tokens, including after restart.

Callers must obtain bindings from current authenticated session, registry and
trusted deployment state. The store checks field presence/size and target syntax;
it does not prove that a mapping is enrolled, that an authority is correctly
configured, or that a session is active. Current user/session validity, resource
and method policy, DNS/SSRF safety and host admission remain mandatory live checks.
Nothing here logs tokens, target URLs, cookies or parent references.

## Next boundary

Pending-to-ticket confirmation is now atomic, without HTTP routes. The next
state-only batch is bounded grant creation and atomic ticket redemption, including
per-parent capacity. It must require the vendor nonce/authority and trusted parent
binding, preserve a ticket on grant-capacity failure, and consume it only when
grant creation succeeds. Later HTTP confirmation/redemption must independently
recheck current parent/user eligibility, registry, policy, method and DNS safety.
Do not build redemption as inspect-then-consume. Non-consuming inspection alone
is not an authorization or redemption check; there is no standalone consume API.

See [cross-host grants](cross-host-grants.md) and the
[origin/cookie checkpoint](vendor-origin-cookie-boundary.md) for the remaining
protocol, origin-separation, cookie-policy and deployment gates. This foundation
does not authorize enabling vendor traffic.
