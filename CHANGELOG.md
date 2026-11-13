# Changelog

Odo is an MVP. Validate each resource before relying on it.

## 0.1.0 (unreleased)

### Added

- **Virtual-host proxying.** Turn it on with `APP_PROXY_URL_MODE=virtual_host`;
  it is allowed in production. Each vendor host gets a readable proxy hostname
  such as `www-jstor-org.proxy.example.edu`, and with it its own browser
  origin, separate from Odo's login and from other vendors. Setup:
  [docs/virtual-host-proxying.md](docs/virtual-host-proxying.md).
  - **Registry:** a hostname registry with readable names and collision
    rejection. Saving a resource registers its exact `proxy` hosts; nothing is
    enrolled automatically from traffic.
  - **Handoff:** launching a resource hands the patron from central to the
    vendor host automatically. A resource's other hosts receive grants in the
    same handoff, one redirect each. Unreachable hosts are skipped.
  - **Delivery:** per patron and resource, vendor cookies stay server-side and
    never reach the browser. GET/HEAD/POST/PUT/PATCH/DELETE are supported as
    the resource allows. Redirects and HTML links to the same resource are
    rewritten.
  - **Restarts:** host grants persist across restarts, stored as token hashes
    and fully re-validated on every use.
  - **Migration:** old path-mode bookmarks redirect to launch.
- **Pseudonymous access logs.** Logs never contain patron user or session IDs.
  [docs/security/patron-log-pseudonymization.md](docs/security/patron-log-pseudonymization.md)
  - **Patron key:** patrons appear as a `patron=pk_…` key derived with
    `APP_LOG_PSEUDONYM_SECRET`.
  - **Rotation:** never, per session, or every N days, weeks or months. Set it
    in Settings or with `PUT /api/v1/settings/log-pseudonymization`
    (admin, reason required, audited).
  - **Re-identification:** `POST /api/v1/logs/access/reidentify`. It requires
    the new `logs:reidentify` scope, which `admin` alone does not satisfy, and
    a stated reason. Every lookup is audited before results are returned.
  - **Vendor lines:** in virtual-host mode they record host, resource and
    request class, never paths or queries.
- **Launch denial reasons.** "launch target is not allowed" responses include
  a `reason`, and the access log records a precise `denial_reason`.
- **User management.** Deleting and restoring users, with atomic session
  revocation on password, status and role changes.
- **Server limits.** Graceful shutdown (up to 8 s for in-flight requests) and
  limits on request headers and idle connections.

### Changed

- Vendor pages in virtual-host mode send `Referrer-Policy: strict-origin`. This
  fixes third-party map tiles (OpenStreetMap), which refuse requests without a
  Referer. Odo's own pages keep `no-referrer`.
- In virtual-host mode, the Resources page links straight to `/launch`.
- The container health check sends the configured central host, so it passes
  with `APP_HOST_GUARD=true`.

### Security

- Changing an account with any non-default role now requires `admin` scope.
  This covers password, status, sessions, edits and deletion. Previously
  `users:write`, which includes the `security_admin` role, could reset an
  administrator's password.
- Central login uses `__Host-` cookies and checks the request origin when the
  host guard is on.

### Upgrade notes

- **New production requirement:** `APP_LOG_PSEUDONYM_SECRET`, at least 32
  random bytes, kept separate from `APP_KEY_HASH_SECRET` and stable. Production
  refuses to start without it.
- **Log format:** access-log lines replace `user_id` / `session_id` with
  `patron`. Update any log parsing.
- **Deprecated flag:** `APP_EXPERIMENTAL_HANDOFF=true` still works as a
  deprecated alias for `APP_PROXY_URL_MODE=virtual_host`.
- **Removed placeholders:** `APP_VIRTUAL_HOST_BASE_DOMAIN` and
  `APP_VIRTUAL_HOST_ENCODING` were never read and are gone from the docs. Use
  `APP_PROXY_BASE_DOMAIN`.
- **Database:** migrations run automatically. Back up `odo.db` first.

### Known limitations

- **Instances:** virtual-host mode supports a single instance. Vendor cookie
  jars are lost on restart.
- **Rewriting:** URLs built by JavaScript or in CSS are not rewritten.
- **Bot protection:** vendors that use it may block the proxy.

## 0.0.5 and earlier

Released as tags without notes.
