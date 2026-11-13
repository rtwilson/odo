# Local user lifecycle

## Database foundation

The database, documented management APIs, and Users section of the admin UI
support transactional soft deletion and restoration.

Deletion uses the existing persistent `status` column with value `deleted`.
Soft deletion itself needs no new status column. The account-security migration
adds a private `users.auth_version` counter (see below). `disabled_at`
records when deletion disabled the account; the `user_deleted` audit event
records the deletion time. `ListUsers` excludes deleted accounts;
`ListDeletedUsers` explicitly selects them. `CountUsers` still includes them:
deleting accounts must not accidentally reactivate first-run bootstrap behavior.

Deletion retains the account ID, username, roles, and profile fields. The username
remains reserved under the existing unique constraint, preventing impersonation
through reuse and avoiding conflicts during restoration. It removes the password
hash and revokes every unrevoked session. Account changes, revocation, and a
minimal audit reference commit in one transaction. Any failure rolls back the
whole operation, including audit insertion failure. Repeated deletion is a
successful no-op without a second deletion audit event.

Self-deletion is rejected when the authenticated actor ID matches the target.
Deletion of the last active account with `admin` or `super_admin` role is rejected.
Deletion, status changes, and role/metadata updates acquire SQLite's writer lock
before reading current account state or counting administrators. They check the
last-active-administrator invariant inside the same transaction as the mutation.
Concurrent deletion, disablement, locking, and demotion therefore cannot each
remove a different administrator based on an outdated count. Database errors
while determining the count return generic `500` responses, rather than being
treated as a count of zero. Last-admin deletion retains `409`; role/status changes
retain `400`. Existing
login and session authentication already require `status == active`.

Ordinary update, password-setting, and enable/disable/lock methods cannot modify
a deleted account. Restoration requires a fresh password hash, preserves its
identity and roles, leaves it **disabled**, and revokes any additional sessions
that appeared while deleted. An administrator must explicitly enable it before
login. Restoration never clears a session's revocation timestamp. Repeated
restoration of an account that is not deleted is a conflict.

Database methods are not an authorization boundary. The management APIs enforce
administrative permissions and the existing browser-session CSRF checks. They
derive the actor ID from authentication, never from a request body.

## Management APIs

All endpoints require authentication. Listing and reading users requires
`users:read`, `users:write`, or `admin`; deletion and restoration require
`users:write` or `admin`. Restoring an account with any retained role other than
`user` additionally requires `admin`, consistent with the existing restriction
on assigning roles. Browser-session mutations require `X-Odo-CSRF`; authenticated
bearer-key requests follow the existing CSRF exemption. Host guard and Origin
policies remain in effect.

| Operation | Request | Success |
| --- | --- | --- |
| List non-deleted users (including disabled/locked) | `GET /api/v1/users` | `200`, existing users envelope |
| List only deleted users | `GET /api/v1/users?deleted=true` | `200`, existing users envelope |
| Read an account, including deleted | `GET /api/v1/users/{id}` | `200`, account metadata without password hash |
| Soft-delete | `DELETE /api/v1/users/{id}` | `200`, `{"deleted":true,"id":"..."}` |
| Restore with a new password | `POST /api/v1/users/{id}/restore` with `{"password":"new password"}` | `200`, `{"restored":true,"id":"...","status":"disabled"}` |
| Enable after restoration | `POST /api/v1/users/{id}/enable` | Existing `200` account response |

Restore accepts only the password field, between 8 and 72 UTF-8 bytes. Its JSON
body is limited to 4096 bytes and must contain exactly one JSON value. Password
hashes are generated server-side and never returned. The `deleted` query parameter
accepts `true` or `false`; absent, empty, or `false` selects non-deleted users.

Deletion/restoration return `401` without valid authentication, `403` for
insufficient scope or invalid browser CSRF, and `404` for an unknown user.
Self-deletion returns `403`, as does deleting an account with any non-default
role without the `admin` scope (the same scope required to change or restore
those roles). Last-administrator deletion and restoration of a
non-deleted account return `409`. Invalid restore input or a malformed deleted
filter returns `400`. Database failures return a generic `500`, with the internal
cause logged under the existing request ID; neither operation reports success
when its transaction fails.

Repeating deletion returns the same successful response. Deleted accounts cannot
be enabled, disabled, locked, unlocked, or assigned a password through ordinary
endpoints. Status changes and metadata/status PATCH of a deleted account return
`409`; use restore instead. Password assignment returns `404` for an
unavailable account. Restore does not accept a
new username, role list, account status, or actor ID.

## Admin UI

In **Users**, load the user list and select an account. **Delete User** asks for
explicit confirmation showing the selected username and explains that the account
will be disabled, its password removed, and its sessions revoked. The action uses
the loaded account identity, not editable values from the JSON editor. Deleting
your own browser account is disabled in the UI and rejected by the API.

Choose **Deleted users** from **User view** to list deleted accounts. Select an
account, enter a new password in the password field, and choose **Restore User**.
The confirmation explains that the account remains disabled. Switch back to
**Non-deleted users**, load/select the restored account, then choose **Enable**
when access should resume. Old sessions remain revoked throughout.

User mutation controls are hidden without `users:write` or `admin`. Restore is
disabled for non-default roles unless the caller has `admin`.

Any change to an account holding a role other than `user` requires `admin`
scope. That covers set-password, disable, enable, lock, unlock,
revoke-sessions, PATCH (metadata, status or roles), delete and restore.
`users:write` alone, including the `security_admin` role, manages default-role
(patron) accounts only. Callers may still act on their own account, except to
delete it. Before 2026-11-12, `users:write` could reset an administrator's
password and then sign in as that administrator. Such attempts now return 403
"admin scope is required to … accounts with non-default roles". The API remains the
authorization boundary and also rejects deleting the last active administrator.
The optional API-key override refreshes the displayed permissions when changed.
Switching account/view clears the password field. Successful deletion/restoration
clears the selection; failures leave the account available for review and retry.

## Disable, delete, restore, and future purge

- **Disable:** temporarily deny access while retaining the account and password.
- **Delete:** hide the account from the default list, discard the password hash,
  and revoke its sessions atomically. This is reversible account removal.
- **Restore:** recover a deleted account using a fresh password; keep it disabled
  until explicitly enabled. Old sessions remain revoked.
- **Personal-data purge:** a future, separate irreversible operation with a
  defined retention policy. Soft deletion is not personal-data erasure.

Lifecycle audit events contain the target account ID and the authenticated actor
ID (empty for API-key callers). They do not contain usernames, passwords, password
hashes, session identifiers, or tokens. Profile fields are retained in the account,
not copied into lifecycle audit events.

## Password changes and other revocation paths

`POST /api/v1/users/{id}/set-password` commits the password hash update and
revocation of every unrevoked session for that account in one database
transaction. A database failure rolls back both writes and returns a generic
`500` with request-ID logging; the old password and sessions remain unchanged.
Missing and deleted accounts still return `404`. A successful reset invalidates
old sessions, including the requesting session when resetting one's own password.
Sessions for other accounts and earlier revocation timestamps are unchanged.

The existing `user_password_set` audit event is attempted after commit and remains
best-effort. A successful response confirms the password change and revocation,
not audit durability. An audit failure does not undo a committed password reset.

Disable and lock operations also commit their status change and revocation of
every unrevoked session together. This includes `PATCH /api/v1/users/{id}` with
`status: disabled` or `status: locked`; any accompanying metadata/role changes
roll back if revocation fails. Status changes update the corresponding
`disabled_at`/`locked_at` timestamp; metadata-only updates preserve these timestamps.
Re-enabling or unlocking does not clear session revocations, so fresh login is
required. Metadata-only PATCH of an active account does not revoke sessions.

Status-write or revocation failure returns a generic `500` and leaves account and
session state unchanged. Unknown/deleted accounts retain their existing handling.
PATCH now applies the same last-active-administrator status protection as the
disable/lock endpoints (`400`). Scope and browser CSRF checks remain required.
The existing post-commit `user_status_set` and `user_updated` audit events remain
best-effort; success does not guarantee audit persistence.

Last-admin removal is protected across concurrent account mutations. Production
lock contention fails closed through the existing generic server-error path;
there is no automatic retry policy.

## Account-security inventory and transaction boundaries

| Mutation | Session behavior and transaction boundary |
| --- | --- |
| Create/bootstrap local user | Creates a new identity; no pre-existing sessions to revoke. Existing creation/audit behavior is unchanged. |
| Set password | Update hash, increment security version, and revoke all unrevoked sessions in one transaction. This applies even when setting the same password. |
| Disable/lock, including PATCH | Update status/timestamps, increment version, and revoke sessions in one transaction. Repeated disable/lock also invalidates pending login state. |
| Effective role-set change, including generic PATCH | Both promotion and demotion increment the version and revoke sessions atomically with any accompanying metadata/status edits. Role ordering, case normalization, or duplicate entries alone do not count as a change. |
| Active-account email/display-name edit | Preserve roles, status, version and sessions when those fields are omitted. |
| Enable/unlock | Keep the security version and all prior revocations. Fresh login is required; old sessions do not revive. |
| Delete | Change status, discard password hash, increment version, revoke sessions and insert the lifecycle audit in one transaction. |
| Restore | Set a fresh hash, leave disabled, increment version, revoke sessions and insert the lifecycle audit in one transaction. |
| Explicit user-session revocation | Increment the version and revoke sessions in one transaction, including when no current sessions exist. A new login based on current state remains permitted. |
| Logout | Revoke only the verified requesting session; separate fresh logins for that user are not revoked. |
| Login/session-touch metadata | Update login/last-seen timestamps; do not change account eligibility or the security version. |

`PatchUser` loads current state under SQLite's writer lock and applies only the
fields supplied by the caller. Omitted fields never come from an earlier API
snapshot. Explicit edits to the same field still use ordinary last-writer-wins
semantics; there is no new ETag or version-precondition API. The existing full
`UpdateUser` datastore helper delegates to the same transaction/revocation logic;
it is not used to implement HTTP PATCH.

Metadata PATCH on an already disabled/locked account defensively repeats session
revocation/version advancement. A failed revocation rolls back roles, status,
metadata, timestamps and the security version. Last-admin checks remain inside
the same write transaction. Post-commit password/status/profile/role audit events
retain their existing best-effort policy; deletion/restoration audit insertion
remains transactional. No response claims failed audit writes are durable.

## Concurrent login and session validation

Migration adds `auth_version INTEGER NOT NULL DEFAULT 0` to users when absent.
It is additive and idempotent, preserves existing accounts and sessions, and
persists across restart. Password hashes and security versions are never included
in user JSON. Existing startup session-persistence policy remains unchanged.
Run migration through normal startup before serving requests with the new binary.

Login checks the password outside the database write lock. It then calls
`CreateAuthenticatedSession`, whose single `INSERT ... SELECT` requires an active
account with the exact password hash and security version observed during that
check. Account writes and session insertion are ordered by SQLite's writer lock:

- If insertion happens first, the later security transaction revokes it.
- If the security transaction happens first, insertion from the old state is
  rejected with the ordinary generic invalid-login response and no session cookie.
- A disable/enable, role-change/revert, restoration or explicit revocation cannot
  recreate the old version, even if the final status and password match.
- Database insertion failures return a generic server error with request-ID
  logging, without a successful login redirect, cookie or success audit event.

The low-level `CreateSession` helper remains for trusted prepared data/test
fixtures; production browser login exclusively uses the guarded insertion.
Session validation reads the session and user in one SQL snapshot, then applies
existing token-binding, revocation, expiry, active-status and touch checks. It
cannot combine an earlier unrevoked session with newly changed user roles.

Revocation governs authorization checks made after its commit. Requests already
authorized may finish; this does not cancel in-flight streams or recall delivered
content. A login inserted before revocation may finish sending a now-invalid
cookie; that cookie cannot authenticate after the revocation commit. No positive
authorization cache delays these database checks.

These changes do not add cross-host grants or virtual-host delivery. Central/vendor
origin separation, the grant protocol, parent-bound vendor jar policy, and rollout
security/compatibility tests remain separate prerequisites.
