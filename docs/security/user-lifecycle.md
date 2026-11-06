# Local user lifecycle

## Database foundation

The database supports transactional soft deletion and restoration. API routes
and admin UI controls are a subsequent implementation batch; these operations
are not yet exposed over HTTP.

Deletion uses the existing persistent `status` column with value `deleted`.
No schema migration or rewrite of existing accounts is needed. `disabled_at`
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
The transaction acquires SQLite's writer lock before checking administrator
state, serializing concurrent deletions. Database failures fail closed. Existing
login and session authentication already require `status == active`.

Ordinary update, password-setting, and enable/disable/lock methods cannot modify
a deleted account. Restoration requires a fresh password hash, preserves its
identity and roles, leaves it **disabled**, and revokes any additional sessions
that appeared while deleted. An administrator must explicitly enable it before
login. Restoration never clears a session's revocation timestamp. Repeated
restoration of an account that is not deleted is a conflict.

The caller must enforce administrative permissions and browser CSRF checks;
database methods are not an authorization boundary. The forthcoming API must
derive the actor ID from authentication, never from a request body. Restoring
privileged roles must require the corresponding administrative authority.

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

The existing password-change and disable/lock flows still need their separate
atomic-session-revocation work in this checkout. This foundation does not alter
those transaction semantics or add cross-host grants or virtual-host delivery.
