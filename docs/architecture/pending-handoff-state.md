# Pending handoff state foundation

Implemented: `internal/api/pending_handoffs.go` and its focused tests. This is a
passive, package-private state store, not connected to `Server`, routes, cookies,
database operations, DNS, upstream fetching or vendor dispatch. Existing launch
continuations and path/query behavior are unchanged. Tickets and grants remain
unimplemented; virtual-host delivery remains disabled.

## Retained state and bounds

`create` generates an opaque 32-random-byte token with the existing
`local.NewToken`, retaining only its hash as the map key. Each record contains:

- Trusted parent session ID and stored session hash.
- The upstream hostname/registry-label pair and full proxy authority.
- A hash of the central browser nonce; no raw nonce is retained.
- The short-lived target and expiry, held only in process memory.

There are at most 256 entries. Expiry is the earlier of five minutes after
creation and the supplied parent absolute expiry. Exact expiry denies lookup.
Full capacity returns a private capacity error without evicting live entries.
Future HTTP callers must map that error to a generic 503.

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

`removeParent` erases records for a trusted parent session ID, including entries
with older stored-hash bindings. It is idempotent and preserves unrelated parents.
It is not connected to runtime revocation yet and cannot replace database checks.

All operations purge expired records under the same mutex; explicit `cleanup` is
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

Add single-assignment vendor preflight nonce binding as a separate state-only
batch. Later confirmation must recheck live authorization and atomically convert
pending state into a ticket under one state lock, preserving the pending record
on ticket-capacity failure. Do not build that transition as inspect-then-consume.
The current store deliberately exposes no consume operation.

See [cross-host grants](cross-host-grants.md) and the
[origin/cookie checkpoint](vendor-origin-cookie-boundary.md) for the remaining
protocol, origin-separation, cookie-policy and deployment gates. This foundation
does not authorize enabling vendor traffic.
