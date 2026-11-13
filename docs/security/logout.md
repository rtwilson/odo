# Browser logout and revocation failures

Logout reads only the active Odo browser-session cookie: `odo_session` normally,
or `__Host-odo_session` when the host guard is enabled. Guarded mode never falls
back to the legacy name. Host and Origin guards continue to run before logout;
guarded logout requires POST and the central Origin. Legacy GET/POST routing
is unchanged.

## Session validation

`sessionForLogout` uses the existing `local.SessionIDFromToken` parser and the
parameterized `Store.GetSession` lookup. An ID alone cannot authorize revocation:
the complete supplied token must match the stored session hash using the existing
restart-persistence/hash policy and a constant-time comparison. The session must
not already be revoked or past its absolute or idle expiry.

This check performs no session-touch writes, user-status changes, or access
authorization. A proven owner may revoke their own active session even if the
account has become inactive. It does not call `currentUser`, whose normal access
validation can touch or revoke sessions. Existing authentication behavior is
otherwise unchanged.

For a valid active session, logout checks `RevokeSession` before clearing cookies.
An unknown or invalid token, missing cookie, already revoked session, or expired
session needs no revocation: logout clears the relevant session/CSRF cookies and
returns the same 302 to `/login`. Missing/clearly malformed tokens require no
session lookup. Cookie names, Secure/HttpOnly/SameSite attributes, Path=/ and
host-only scope remain unchanged.

## Operational failures

A session lookup failure or failed revocation returns the existing generic HTTP
500 response with a request ID. The internal error helper records the cause and
the same ID; the browser receives no database details, successful redirect, or
cookie-clearing headers. These responses are no-store. A session may remain
usable after failed revocation: the client must retry rather than assume logout
completed. No vendor grants or upstream cookie jars are revoked by this change.

## Logout audit policy

Following existing best-effort authentication audit conventions, logout attempts
these events through `Store.Audit`:

- `logout_success`, outcome `revoked`: validated-session revocation returned
  success. Concurrent idempotent revocation may already have removed access.
- `logout_success`, outcome `no_active_session`: the supplied browser state
  required no revocation. This does not claim a session was revoked.
- `logout_failed`, outcome `lookup_failed` or `revocation_failed`: logout could
  not safely complete.

Details contain only `/logout`, request ID, and the fixed outcome. They contain
no session identifiers, tokens, cookies, credentials, vendor URLs or search data.
All invalid/missing/inactive states share the same external redirect behavior;
the response does not disclose whether a cookie-supplied ID exists.

Audit failure does not undo confirmed revocation or turn a completed logout into
a failed revocation. It produces a `logout audit write failed` warning containing
the event name, request ID and internal audit error. The requested audit event
is not claimed to be durable when its insert fails. When both lookup/revocation
and audit persistence fail, logout still returns the generic 500. This is a
logout-specific documented policy, not an audit-durability guarantee for Odo.

Password-change and account-status/revocation transactions remain separate work.
