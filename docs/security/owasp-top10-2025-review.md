# OWASP Top 10:2025 Security Review for Odo

## Summary

- **Review date:** 2026-08-06
- **Git commit:** `7bda6a9647cfbd01d45f5a641e2a24c846dd7545`
- **Scope reviewed:** `cmd/odo`, `internal/api`, `internal/auth`, `internal/db`, `internal/proxy`, `internal/resources`, `internal/accesslog`, `internal/audit`, `internal/config`, `internal/ui`, OpenAPI, sample resource and SAML configuration, tracked data files, dependency manifests, container and systemd packaging, install/uninstall scripts, and deployment documentation.
- **Commands run:** `rg --files`; targeted `rg`, `sed`, `file`, `strings`, `git ls-files`, and `git status` inspection; Go 1.23.12 container runs of `go test ./...`, `go vet ./...`, `go mod verify`, and `go list -m all`.
- **Command results:** tests passed; vet passed; all modules verified; module inventory completed. `govulncheck`, `staticcheck`, and `gosec` were not installed in the available Go image and were not run. The host had no Go executable, so Go commands were run in the project container image.
- **Overall risk after remediation:** **Medium.** The proxy now connects only to IPs validated at dial time, production configuration fails closed, runtime databases are no longer tracked, and production Odo-owned security/session cookies are consistently `Secure`. The repository owner confirmed that the removed databases contained synthetic/development data only. The remaining medium findings should be addressed before pilot where noted.
- **Remediation review:** `scripts/install-linux.sh` and `scripts/uninstall-linux.sh` had pre-existing uncommitted user changes and were not modified.

This is a remediation record, not a production-readiness certification. See the [readiness stages](../../README.md#readiness-and-security) for controlled demos, design-partner testing, Internet-facing pilots, and production use. Evidence under fixed findings describes the original review state; fix and resolution entries describe remediation.

The container build file is now named `Dockerfile`; `Containerfile` references below retain the filename used at review time.

### MVP blockers

**No MVP blockers remain.** The three implementation blockers are remediated, and the repository owner confirmed that the formerly tracked SQLite databases contained synthetic/development data only. No credential rotation or history rewrite was required for real user data; neither action was performed.

### Should fix before Internet-facing pilot

- Configure reverse-proxy login rate limiting and operational alerting; local per-process throttling is implemented (ODO-2025-004).
- Add application-page security headers and document proxy-response header policy (ODO-2025-007).
- Add dependency scanning, update automation, immutable container inputs, and release provenance (ODO-2025-008).
- Complete security-event coverage without storing patron research trails (ODO-2025-009).
- Add HTTP server read/write/idle timeouts and graceful shutdown (ODO-2025-010).

### Later hardening

- Strengthen the systemd sandbox (`ProtectSystem=strict`, `ProtectKernel*`, `ProtectControlGroups`, `RestrictSUIDSGID`, `LockPersonality`, `MemoryDenyWriteExecute`, and an appropriate `SystemCallFilter`) after compatibility testing.
- Resource create, update, and validation endpoints now enforce a 1 MiB request body limit. Add limits to remaining login/JSON administration endpoints and extend structured error codes.
- Add an explicit retention policy and optional keyed pseudonymization for user, session, and IP identifiers in access/audit logs.
- Pin container base images by digest and build from a minimal context.

## Findings Table

| ID | OWASP category | Severity | Status | Short title | Affected files | Recommended fix |
|---|---|---:|---|---|---|---|
| ODO-2025-001 | A06 | High | Fixed | DNS rebinding/TOCTOU gap in SSRF defense | `internal/proxy/safety.go`, `internal/proxy/proxy.go` | Validated-IP dialer implemented; retain regression coverage |
| ODO-2025-002 | A08, A04 | High | Fixed | Runtime SQLite databases containing auth data are tracked | `data/app.db`, `data/odo.db`, `.gitignore` | Retain CI checks preventing runtime databases from being committed |
| ODO-2025-003 | A02 | High | Fixed | Production security requirements warn but do not fail closed | `cmd/odo/main.go`, `cmd/odo/main_test.go` | Production startup validation implemented; retain regression coverage |
| ODO-2025-004 | A07 | Medium | Fixed (local process) | Login has no brute-force throttling | `internal/api/auth_handlers.go`, `internal/api/login_throttle.go` | Retain regression tests; configure edge rate limiting and alerting |
| ODO-2025-005 | A04, A07 | Medium | Fixed | Proxy and CSRF cookies are not consistently `Secure` | `internal/cookiepolicy/policy.go`, `internal/proxy/session.go`, `internal/api/server.go` | Retain production/development cookie-policy regression coverage |
| ODO-2025-006 | A10 | Medium | Fixed | Internal errors are returned verbatim | `internal/api`, `internal/httperror`, `internal/accesslog`, `internal/config`, `internal/proxy` | Retain safe-response and request-ID regression coverage |
| ODO-2025-007 | A02, A05 | Medium | Confirmed | Application HTML lacks baseline security headers | `internal/api/server.go` | Add CSP, frame protection, nosniff, referrer and permissions policies |
| ODO-2025-008 | A03 | Medium | Confirmed | Supply-chain controls and immutable build inputs are absent | `go.mod`, `go.sum`, `Containerfile`, repository CI | Add scanning/update CI, digest pinning, SBOM and signed provenance |
| ODO-2025-009 | A09 | Medium | Confirmed | Security logging is incomplete and can retain identifiers | `internal/api/server.go`, `internal/accesslog/accesslog.go`, `internal/db/db.go` | Add safe auth/SSRF events, retention/redaction, and alert integration |
| ODO-2025-010 | A10 | Low | Confirmed | HTTP server lacks explicit timeouts and graceful shutdown | `cmd/odo/main.go` | Use `http.Server` timeouts, header limits, signal shutdown |

## Findings by Category

### A01:2025 - Broken Access Control

Review checklist covered protected `/api/v1` routes, public endpoints, `/admin`, `/resources`, `/odo`, role/scope enforcement, object operations, missed-rewrite recovery, anonymous rules, and browser/API response behavior.

**No finding observed.** `requireAPIAuthentication` defaults all `/api/v1/*` endpoints to authenticated except exact `GET /api/v1` and `GET /api/v1/health` (`internal/api/server.go:1811-1836`). Each management handler is additionally registered with scopes. User roles are translated server-side, unsafe session-authenticated API calls require `X-Odo-CSRF`, `/admin` requires an admin-like role, `/resources` requires a current active user, and `/odo` requires a session unless a validated explicit anonymous rule matches. Missed-rewrite recovery rejects protected application paths and runs target plus login/anonymous checks before recovery.

The legacy unauthenticated fallback at `internal/api/server.go:1903-1909` is currently unreachable for protected API routes because the outer API middleware denies anonymous requests, and `/admin` subsequently rejects unauthenticated contexts. Remove this dead fallback and the misleading “management API is unprotected” startup warning to avoid a future routing refactor accidentally making it live.

Tests to add: enumerate every registered `/api/v1` route as anonymous, viewer, each staff role, scoped API key, and admin; assert exact 401/403 behavior; fuzz missed-rewrite and encoded-path variants; verify anonymous rules cannot authorize a different method, host, or path.

### A02:2025 - Security Misconfiguration

#### ODO-2025-003 — Production security requirements warn but do not fail closed

- **Severity:** High
- **Status:** Fixed
- **Evidence:** the default listener is `:8080`; production checks only call `logger.Warn`; missing key-hash secret falls back to plain SHA-256; and proxy login can be explicitly disabled (`cmd/odo/main.go:18-36,59-64`). The container advertises `APP_ENV=development`, listens on all interfaces, and embeds writable configuration (`Containerfile:15-25`). Deployment examples contain literal `change-me` values and enable trusted proxy headers without a trusted-proxy CIDR mechanism.
- **Affected files:** `cmd/odo/main.go`, `Containerfile`, `deploy/odo.env.example`, `packaging/systemd/odo.env.example`, `docs/deploy-container.md`, `docs/install-linux-vm.md`.
- **Risk:** a production deployment can start in a materially unsafe state and be exposed through an unnoticed packaging or environment mistake.
- **Recommended fix:** validate a typed configuration before opening the database/listener. In production, reject missing/invalid HTTPS public URL, missing hash secret, placeholder secrets, disabled login, development local HTTP, and ambiguous trust-proxy settings. Default the runtime image to production and loopback or require an explicit acknowledgement for public binding. Do not make `/etc/odo` writable by the service unless runtime edits are required.
- **Test to add:** table-driven startup validation for every unsafe combination; container smoke test asserting production defaults and non-root read-only configuration.
- **Fix implemented:** production startup now rejects missing/non-HTTPS `APP_PUBLIC_URL`, missing or placeholder key-hash/bootstrap secrets, absent admin bootstrap paths, explicitly disabled proxy login, empty/temporary database paths, and inconsistent trusted-proxy/public-URL settings. An active unexpired stored admin key or an explicit strong local-admin bootstrap permits omission of the environment bootstrap API key. Development remains permissive.
- **Tests added:** fail-closed cases for each required setting, valid stored-key configuration, explicit local-admin bootstrap, and development behavior.
- **Remaining risk:** the container intentionally defaults to development and deployment still depends on operators selecting production; add a production container smoke test and reject additional organization-specific placeholder values as needed.

#### ODO-2025-007 — Application HTML lacks baseline security headers

- **Severity:** Medium
- **Status:** Confirmed
- **Evidence:** HTML handlers set only `Content-Type`; the outer middleware does not set CSP, `X-Content-Type-Options`, frame protection, `Referrer-Policy`, or `Permissions-Policy` (`internal/api/server.go:326-367,432-470,1769-1809`). The admin UI uses DOM `textContent`/input values for dynamic data, which reduces current XSS exposure, but it contains a large inline script that requires an intentional CSP design.
- **Affected files:** `internal/api/server.go`, `internal/ui/admin.go`.
- **Risk:** clickjacking and reduced browser defense-in-depth increase the impact of a future rendering defect. Proxy responses need a separate compatibility-aware policy.
- **Recommended fix:** apply strict headers to Odo-owned pages/APIs; move inline admin JavaScript to a static asset or use a nonce/hash CSP. Set HSTS at the TLS terminator. Do not blindly apply the same CSP to proxied vendor pages; document and test that boundary.
- **Test to add:** header assertions for login, admin, resources, OpenAPI, APIs, and separate expected behavior for proxied content.

### A03:2025 - Software Supply Chain Failures

#### ODO-2025-008 — Supply-chain controls and immutable build inputs are absent

- **Severity:** Medium
- **Status:** Confirmed
- **Evidence:** `go.mod`/`go.sum` exist and `go mod verify` passed, but no CI configuration, Dependabot/Renovate policy, vulnerability scan, SBOM, signature/provenance workflow, or vendoring policy was found. `Containerfile` uses mutable tags (`golang:1.23-alpine`, `alpine:3.21`), runs `go mod download` after copying only `go.mod` rather than both checksummed manifests, and copies the entire build context.
- **Affected files:** `go.mod`, `go.sum`, `Containerfile`, absent `.github/` automation.
- **Risk:** known-vulnerable or substituted dependencies/base images may reach releases without a blocking signal; builds are not strongly reproducible or attributable.
- **Recommended fix:** run tests, vet, `govulncheck`, dependency review, container scanning, and secret scanning in CI; enable controlled update PRs; copy `go.mod` and `go.sum` before download; pin release base images by digest; generate an SBOM and sign binaries/images with provenance.
- **Test to add:** CI policy test that fails on vulnerable production dependencies above the project threshold and verifies release attestations.

`go list -m all` recorded direct dependencies `modernc.org/sqlite v1.34.4` and `golang.org/x/crypto v0.24.0` plus their transitive graph. This review did not infer vulnerability status from version age alone; `govulncheck` was unavailable and should be run before pilot.

### A04:2025 - Cryptographic Failures

#### ODO-2025-002 — Runtime SQLite databases containing authentication data are tracked

- **Severity:** High
- **Status:** Fixed
- **Evidence at review time:** Git tracked `data/app.db` and `data/odo.db`. Both are SQLite databases; inspection found user names/IDs, audit events, session IDs and hashes, user-agent/IP hashes, and authentication table schemas. `.gitignore` did not ignore database files. Passwords use bcrypt and API/session tokens are hashed, so plaintext credential storage was not observed, but committed password hashes permit offline guessing and the data represents an avoidable disclosure.
- **Affected files:** `data/app.db`, `data/odo.db`, `.gitignore`.
- **Risk:** a public clone exposes identity/activity metadata and password verifiers. If these are not purely synthetic, users and credentials are compromised regardless of later deletion from the tip.
- **Recommended fix:** determine provenance immediately; revoke sessions/API keys and reset passwords if any data is real; remove DB files from the current tree and, after impact review, repository history; add `data/*.db`, SQLite WAL/SHM files, and local environment files to ignore rules; distribute migrations or deterministic synthetic fixtures instead.
- **Test to add:** CI secret/data-artifact scan rejecting SQLite databases, key material, and runtime state.
- **Fix implemented:** `data/app.db` and `data/odo.db` were removed from Git tracking without deleting the user's local copies. Ignore rules now cover database/WAL/SHM extensions and repository runtime directories. Linux deployment documentation continues to use `/var/lib/odo/odo.db`.
- **Tests/checks added:** Git ignore matching and tracked-file status were checked; the full Go suite remains green.
- **Resolution:** the repository owner confirmed the removed SQLite files contained synthetic/development data only. No credential rotation or history rewrite was required for real user data, and neither was performed. Retain CI checks preventing runtime databases from being committed again.

#### ODO-2025-005 — Proxy and CSRF cookies are not consistently `Secure`

- **Severity:** Medium
- **Status:** Fixed
- **Evidence at review time:** `odo_proxy_sid`, which selects the in-memory vendor cookie jar, was always created with `Secure: false` (`internal/proxy/session.go:63-70` at the reviewed commit). The readable CSRF cookie also omitted `Secure`; the main browser-session cookie conditionally used TLS or an HTTPS `APP_PUBLIC_URL`.
- **Affected files:** `internal/proxy/session.go`, `internal/api/server.go`.
- **Risk:** an HTTP request can disclose or overwrite the proxy-session identifier, potentially exposing a patron's authenticated vendor state. Inconsistent cookie policy makes reverse-proxy mistakes more damaging.
- **Recommended fix:** inject a centralized cookie policy into both stores and force `Secure` in production; validate that production public URL is HTTPS; consider `__Host-` cookie names; retain `HttpOnly` for session cookies and use a standard CSRF construction for the readable token.
- **Test to add:** assert `Secure`, `HttpOnly`, `SameSite`, path, and expiry under direct TLS, trusted reverse proxy, production, and development cases.
- **Fix implemented:** `internal/cookiepolicy` now applies one policy to browser-session, proxy-session, CSRF, and cookie-clearing paths. Direct TLS, a configured HTTPS public URL, or explicitly trusted forwarded HTTPS produces `Secure` cookies. Production startup already rejects a missing or non-HTTPS public URL. Main and proxy sessions remain `HttpOnly`; the CSRF cookie remains JavaScript-readable for the existing double-submit flow. All use `SameSite=Lax` and `Path=/`; proxy and CSRF cookies now have bounded expiry.
- **Tests added:** centralized policy tests cover production HTTPS, local HTTP development, direct TLS, and trusted/untrusted forwarded HTTPS. API and proxy tests assert purpose-specific `Secure`, `HttpOnly`, `SameSite`, path, and expiry behavior while existing login, logout, CSRF, and proxy-session regressions remain in the full suite.
- **Remaining risk:** `__Host-` prefixes, stricter `SameSite`, and narrower paths remain optional future hardening and require compatibility review.

Positive observations: passwords use bcrypt; API keys and sessions use `crypto/rand`; API-key comparison is constant-time for the bootstrap key; stored API keys use HMAC-SHA-256 when configured; raw stored API tokens and password plaintext were not observed in database models or logs.

### A05:2025 - Injection

No standalone confirmed injection finding was observed. SQL uses placeholders rather than concatenated user input. Resource host/rule validation rejects IP literals, wildcards, local/internal names, non-HTTPS anonymous patterns, unsupported methods, and malformed rule shapes. Admin UI dynamic values are generally assigned through `textContent` or form `.value`; static markup uses `innerHTML` without interpolating resource values. Odo-owned HTML interpolations use escaping. Request-header configuration supports removal/preservation, not arbitrary attacker-selected values.

The security-header finding ODO-2025-007 applies as defense-in-depth. Add fuzz tests for JSON decoding, header names, proxy URL encodings, rewrite rules, and log control characters. Add explicit maximum lengths/counts for IDs, titles, patterns, rewrite strings, JSON payloads, and login forms to limit parser/memory abuse.

### A06:2025 - Insecure Design

#### ODO-2025-001 — DNS rebinding/TOCTOU gap in SSRF defense

- **Severity:** High
- **Status:** Fixed
- **Evidence:** `ValidateTargetURL` resolves the hostname and rejects any non-public result (`internal/proxy/safety.go:89-112`), but returns the hostname URL. The default `http.Transport` subsequently resolves that hostname again when `client.Do` connects (`internal/proxy/proxy.go:29-41,140-142`). The validated IP is neither retained nor used by the dialer. Redirects are returned rather than automatically followed, which correctly limits redirect-based SSRF.
- **Affected files:** `internal/proxy/safety.go`, `internal/proxy/proxy.go`, `internal/api/server.go`.
- **Risk:** an allowed attacker-controlled hostname can return a public address during validation and a private/link-local address during connection, reaching internal services through Odo. Resource allowlisting reduces who can introduce such a hostname but does not remove the impact of a compromised or malicious configured domain.
- **Recommended fix:** resolve once per connection attempt, reject if any candidate is unsafe, connect to a selected validated IP via a custom `DialContext`, and preserve the original hostname for TLS SNI/certificate verification and the HTTP Host header. Disable unintended proxy-environment behavior if present. Do not globally cache DNS longer than intended; repeat validation for fresh connections and control connection reuse across resource/security boundaries.
- **Test to add:** deterministic resolver/dialer test that returns public then loopback/private addresses; IPv4/IPv6, link-local, CGNAT and special-range cases; connection reuse; redirects; and TLS hostname verification.
- **Fix implemented:** the default outbound transport now resolves on each new connection, rejects the complete answer set if any address is unsafe, and dials a validated numeric IP. The request URL retains the vendor hostname, preserving the HTTP Host header and Go's TLS SNI/certificate verification. Automatic upstream redirect following remains disabled (an effective per-fetch limit of zero); returned redirects are passed through target/resource validation before Odo rewrites them. Blocked-target diagnostics contain only a stable type/reason and target hostname.
- **Tests added:** public IPv4 and IPv6 dialing, numeric validated dial target, DNS rebinding between pre-check and connect, private/loopback/link-local/unique-local/multicast/unspecified/documentation ranges, invalid schemes, blocked redirect diagnostics, and diagnostic privacy.
- **Remaining risk:** DNS and network policy are process-local; deployments should also apply egress firewall policy. Connection reuse intentionally avoids repeat DNS lookup until Go opens a new connection, so keep-alive lifetime remains part of the operational threat model.

Design positives: proxy targets must match active resource rules; targets default to HTTPS/443; IP literals, localhost, `.local`, and `.internal` are rejected; all resolved addresses are screened; redirects are not automatically followed; cookie jars are isolated by random proxy-session ID; response bodies and request bodies have size controls in the proxy path.

### A07:2025 - Authentication Failures

#### ODO-2025-004 — Login has no brute-force throttling

- **Severity:** Medium
- **Status:** Fixed for local per-process browser login; edge controls and operational alerting remain deployment requirements.
- **Evidence at review time:** `loginPost` had no attempt limiter before user lookup/password verification. Failed attempts were audited with supplied usernames, but logging alone did not constrain attempts.
- **Affected files:** `internal/api/auth_handlers.go`, `internal/api/login_throttle.go`, `internal/api/server.go`, deployment documentation.
- **Fix implemented:** mutex-protected account/source throttling before database/bcrypt work. Limits are 5 account failures or 20 source failures in a fixed 10-minute window, with cooldowns of up to 60 seconds and one probe at a time after cooldown. Rejected attempts do not extend lockouts. Successful session creation clears account failures; source failures expire. Pending attempts reserve capacity, and storage is capped at 10,000 combined keys with expiry pruning.
- **Responses and events:** existing generic credential-failure body is preserved for unknown, disabled, locked, and incorrect-password accounts; throttled responses use HTTP 429 with the same body. Failed-login details no longer include supplied usernames. Threshold crossings and sampled throttling events contain no account/source identifiers or credentials.
- **Tests added:** threshold, cooldown, non-extension, window expiry, account normalization, source isolation, success reset, generic responses, audit privacy, forwarded-header spoofing, capacity/pruning, and concurrent reservation tests.
- **Remaining limitations:** state resets on process restart; connection-peer source keys aggregate users behind a reverse proxy. Attackers can still cause temporary denial or capacity pressure. Configure reverse-proxy rate limiting and alerting before pilot; recommend distributed throttling if multi-node/HA support is added. No constant-time authentication claim is made. See the [policy and deployment limits](login-throttling.md).

Positive observations: authentication failures use a generic message, disabled/locked users cannot log in, sessions have absolute and idle expiry, sessions are rotated on login and revocable, user disablement invalidates use, bearer keys support scopes/status/expiry/revocation, and unsafe cookie-authenticated API methods require CSRF tokens.

### A08:2025 - Software and Data Integrity Failures

ODO-2025-002 was the confirmed integrity/data-handling finding for this category and is resolved as described above.

Resource imports are validated before persistence, SQL updates are parameterized, revisions and key/user/resource mutations receive audit records, and the installer preserves an existing environment unless explicitly forced. However, administrative resource configuration intentionally controls proxy destinations, anonymous access, rewrites, and header behavior; it is therefore security policy, not ordinary content. Add atomic import semantics (validate the complete set, detect ambiguous/conflicting rules, then commit in one transaction), actor identity and before/after digests to audit events, an approval/export workflow for pilot changes, and signed release/config provenance where operationally appropriate.

Tests to add: partial-import failure/rollback, duplicate and conflicting domain precedence, anonymous-rule widening detection, audit attribution, and concurrent update behavior.

### A09:2025 - Logging and Alerting Failures

#### ODO-2025-009 — Security logging is incomplete and can retain identifiers

- **Severity:** Medium
- **Status:** Confirmed
- **Evidence:** failed/successful login, CSRF failure, admin API calls, API-key and user/resource changes are audited. However, invalid/revoked/expired API-key attempts and blocked SSRF/private-IP decisions are not consistently durable audit events, successful logout has no explicit audit event, and audit events have no actor/request-ID columns. Access entries retain remote IP, user ID and session ID; combined/JSON formats retain full Referer and User-Agent in the output (`internal/accesslog/accesslog.go:125-205,227-287`). There is no documented retention, alert destination, or query-string/search-term policy across reverse-proxy logs.
- **Affected files:** `internal/api/server.go`, `internal/accesslog/accesslog.go`, `internal/db/db.go`, deployment docs.
- **Risk:** operators may miss credential attacks and SSRF probes, while logs can create a patron research/activity dataset with unclear retention and access controls.
- **Recommended fix:** define a structured security-event schema with actor, outcome, reason code, request ID, and coarse source identifier; add safe events for logout, invalid/revoked/expired keys, throttling, blocked targets/private IPs, bootstrap use, and security-sensitive config changes. Never log bearer/cookie values, request bodies, raw proxied URLs/query strings, or search terms. Key/pseudonymize identifiers where correlation is needed, set retention/access policy, and connect severity-based alerts.
- **Test to add:** golden tests proving Authorization, Cookie, query, body, search terms, and configured secrets never appear; tests for every expected security event and log-injection control characters.

### A10:2025 - Mishandling of Exceptional Conditions

#### ODO-2025-006 — Internal errors are returned verbatim

- **Severity:** Medium
- **Status:** Fixed for Odo-generated internal error responses.
- **Evidence at review time:** handlers passed `err.Error()` to clients for database and other internal failures; authorization helpers could also expose store errors. Some config results embedded filesystem/database errors in HTTP 200 responses.
- **Affected files:** `internal/api`, `internal/httperror`, `internal/accesslog`, `internal/config`, `internal/resources`, `internal/proxy`.
- **Fix implemented:** shared error handling returns `internal_error`, a stable generic message, and `request_id` for JSON 500/502 responses. Odo browser pages receive generic HTML with the ID. Known-safe validation/credential errors remain useful; raw user-conflict SQL and config file/parser errors no longer reach clients. Auth/session-store errors propagate as internal failures rather than invalid credentials.
- **Request IDs:** every routed response has `X-Request-ID`. A single inbound `X-Request-ID` or legacy `Request-ID` is reused only if it contains 1–64 ASCII letters, digits, underscores, or hyphens; otherwise Odo generates an ID. IDs are correlation labels, not trusted identities.
- **Logging:** application error logs retain the internal cause, request ID, registered route/fixed fallback, method, and status. No request headers/bodies or raw request URLs are added. URL error wrappers omit target URLs, including query strings/userinfo, while preserving the cause. Access logs share the request ID.
- **Tests added:** closed-database login/resource/API-key/user/config/SAML/auth/session failures; config read/import failures; generic browser pages; upstream failures; useful 400/409 responses; request-ID validation/reuse/generation; matching response/log IDs; and exclusion of request secrets/query strings from new error logs.
- **Remaining limitations:** this does not sanitize vendor-origin proxy response bodies, replace responses after streaming starts, or add panic recovery. Config imports remain nontransactional. Internal causes are intentionally retained in restricted server logs; audit and optional access-log privacy/retention work remains under ODO-2025-009. See [error responses and request IDs](error-responses.md).

#### ODO-2025-010 — HTTP server lacks explicit timeouts and graceful shutdown

- **Severity:** Low
- **Status:** Confirmed
- **Evidence:** startup calls `http.ListenAndServe` directly (`cmd/odo/main.go:77-81`), leaving read-header, read, write, idle, maximum-header, and graceful-shutdown behavior at defaults.
- **Affected files:** `cmd/odo/main.go`.
- **Risk:** slow clients can consume resources; abrupt termination can interrupt in-flight requests and log/database work.
- **Recommended fix:** construct `http.Server` with conservative `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, `IdleTimeout`, and `MaxHeaderBytes`; handle SIGTERM with a bounded `Shutdown` context. Coordinate long proxy responses with the chosen write timeout.
- **Test to add:** slow-header/body tests, oversized-header test, upstream timeout/error tests, and graceful shutdown with an in-flight request.

Other positive observations: malformed JSON/URLs usually produce controlled 4xx responses; proxy clients have overall, TLS-handshake, and response-header timeouts; redirects are not automatically followed; proxy body size is bounded; database migration/open errors stop startup.

## Consolidated Test Recommendations

1. Build an authorization matrix test generated from route registration, including encoded and unknown paths.
2. Add adversarial SSRF tests with a resolver/dialer seam, special-use networks, DNS changes, redirects, and connection reuse.
3. Add login-rate-limit and cookie-policy tests across production, direct TLS, and reverse-proxy deployments.
4. Add response-header snapshots and XSS regression tests using hostile resource, diagnostic, user, and SAML strings.
5. Add fault-injection tests for every datastore and upstream error path and verify public error sanitization.
6. Add privacy golden tests for all log formats and audit events.
7. Add config-import transaction/conflict tests and security-policy diff coverage.
8. Add CI checks for tests, vet, `govulncheck`, `staticcheck`, `gosec`, secrets, tracked databases, container vulnerabilities, SBOM, and provenance.

## Documentation Recommendations

- Publish a production security checklist that distinguishes mandatory startup invariants from optional hardening.
- Document the trust boundary for `APP_TRUST_PROXY_HEADERS`, including network controls preventing direct client access and which component strips/replaces incoming forwarding headers.
- Document the SSRF threat model, allowed destination governance, DNS behavior, and incident response for a compromised vendor domain.
- Document cookie/session behavior, required HTTPS termination, timeout/retention values, bootstrap-key retirement, password reset, and API-key rotation.
- Add a privacy-specific logging guide: default format, fields, redaction guarantees, retention, operator access, reverse-proxy configuration, and prohibition on patron query/search logging.
- Add dependency/update policy, supported Go version, vulnerability response SLA, release checksums/signatures, SBOM, and provenance verification instructions.
- Replace copyable `change-me` secrets with clearly invalid placeholders that startup rejects, and show secret-file/credential-manager patterns where supported.
