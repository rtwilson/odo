# Odo MVP Backlog

This backlog is based only on the current repository state. Items marked **Uncertain** need confirmation through manual testing, stakeholder review, or production-like usage.

## Current Implemented Features

- Single Go application with local HTTP service, embedded OpenAPI spec, and SQLite persistence.
- Versioned JSON management APIs under `/api/v1`.
- Minimal built-in admin UI at `/admin` that uses the same JSON APIs as scripts and integrations.
- Admin UI sections for dashboard, resources, config, diagnostics/logs, API keys, users, SAML provider scaffolding, and system settings.
- Resource registry with JSON import, create/update/get/delete APIs, validation, normalized resource model, tags, domain rules, roles, request header rules, cookie policy, anonymous URL rules, content rewrite rules, compatibility flags, and sample URLs.
- Plain-language resource documentation in `docs/resource-how-to.md`.
- Resource Config Builder in the admin UI for practical resource creation, validation, saving, export, and proxy testing.
- Large-resource-collection admin UI support with readable resource rows, search, filters, sorting, details, raw JSON editing, selected export, and filtered export.
- API key management with stored hashed API keys, token rotation, revocation, expiration handling, scopes, and one-time token display.
- Local users, roles, browser login, browser sessions, `/resources` patron portal, logout, password hashing, status/lock/disable handling, session revocation, and CSRF protection for unsafe browser-session admin API calls.
- Configurable session behavior: TTL, idle timeout, restart persistence behavior, secure cookie decisions, and throttled `last_seen_at` updates.
- Proxy login enforcement for `/odo` path/query proxy requests, including resource entry URLs, with explicit `anonymous_url_rule` as the only unauthenticated proxy bypass.
- Safe `next` handling for login return flows, including return to proxied resources and `/admin` only for admin-like users.
- Path-based proxy URL mode, query compatibility mode, dual parse support, and central proxy URL builder/parser abstraction.
- Virtual-host proxy mode design document and inactive config placeholders.
- Safe outbound proxy for configured resources with URL safety checks, DNS/IP safety checks, method checks, request header filtering, bounded POST bodies, redirect rewriting, and server-side vendor cookie jars.
- Partial HTML, CSS, `srcset`, inline-style, form, and redirect URL rewriting.
- Conservative JavaScript shim for same-origin `fetch()` and XHR URL rewriting.
- Optional explicit content rewrite rules for difficult resources.
- Referer-based missed-rewrite recovery for asset/API/app-data paths, canonical redirects for missed document navigations, and missed-rewrite diagnostics.
- Privacy-conscious access logging with privacy/common/combined/JSON formats and file output support.
- Recent access log, proxy diagnostic, and missed rewrite diagnostic APIs and admin UI views.
- Protected runtime metrics endpoint at `/api/v1/system/runtime`.
- SAML provider configuration CRUD APIs, admin UI controls, SP metadata generation, and placeholder SAML login/ACS routes returning not implemented.
- Linux VM installation docs, systemd unit/env examples, container deployment docs, Containerfile, Podman/Quadlet examples, install/uninstall scripts, and Makefile.
- Local load-testing setup with fake vendor server, fake resource config, k6 smoke/idle/active/spike/soak scripts, and load-test README.
- Sample resource configs for JSTOR, JSTOR/ALUKA, Economist, and UMN Libraries.

## Partially Implemented Features

- **Proxy compatibility:** HTML/CSS/form/asset rewriting and a JS shim exist, but README states full JavaScript rewriting, WebSockets, CSP rewriting, and full SPA compatibility are not implemented.
- **SAML:** Provider config APIs, admin UI, and metadata exist, but login initiation and assertion validation are placeholders.
- **Virtual-host proxying:** Design doc and config placeholders exist, but routing, host decoding, wildcard TLS/DNS support, and cookie/origin handling are not implemented.
- **Diagnostics:** Access logs, proxy diagnostics, missed rewrites, and runtime metrics exist, but the README describes some diagnostics as still growing.
- **Admin UI:** Functional and intentionally minimal, but not a polished custom dashboard. Advanced workflows are expected to use JSON APIs.
- **Load testing:** Local fake-vendor and k6 scripts exist, but they are tooling scaffolds. **Uncertain:** no CI target appears to run k6 or validate performance budgets.
- **Session cleanup:** Expired/revoked sessions are rejected and proxy cookie jars have idle cleanup, but there is no obvious persistent-session cleanup scheduler. The load-test docs call cleanup candidates future maintenance work.
- **Audit implementation:** Many audit events exist, but README still says this is not a complete audit implementation.
- **HA/storage:** SQLite is used for the MVP. README and load-test docs identify Postgres/Redis as possible future needs for larger/HA deployments.
- **OpenAPI/docs alignment:** OpenAPI is extensive, but some README wording appears stale or contradictory. Example: early README says this is not a full admin login/session system, while later sections and tests show local admin/user sessions now exist.

## Known Bugs

- **Documentation drift:** README `What It Is Not Yet` says Odo is not a full admin login/session system, but current code and later docs include local admin login/session behavior. This can confuse adopters.
- **SAML routes are visible but not functional:** They intentionally return not implemented, but users may misread the Auth/SAML UI as production-ready unless docs/UI wording remains clear.
- **Virtual-host mode accepts configuration only as fallback/warning:** `APP_PROXY_URL_MODE=virtual_host` falls back to path mode. This is documented, but operators may still assume the mode works if they miss the warning.
- **Runtime cleanup gap:** Expired/revoked login sessions can remain in SQLite. They are ignored/rejected, but accumulation may become operational noise. **Uncertain:** actual growth rate has not been measured.
- **Proxy compatibility is inherently incomplete:** Complex vendor SPAs may still fail because full JS rewriting, CSP rewriting, WebSockets, and virtual-host origin emulation are not implemented.

## P0 Issues

- Keep runtime SQLite files out of commits and release artifacts; verify `.gitignore`/workflow protects `data/*.db`.
- Fix README product-positioning drift around admin login/session support.
- Verify proxy login enforcement manually against a real configured entry URL and query-mode proxy URL after the latest changes.
- Add an automated guard or repo hygiene rule to prevent committing runtime SQLite DB files from `data/`.
- Confirm production safety defaults: `APP_PROXY_REQUIRE_LOGIN`, `APP_PUBLIC_URL`, API key secret handling, local HTTP load-test allowance, and virtual-host fallback warnings.

## P1 Issues

- Add persistent session cleanup maintenance: delete or archive expired/revoked sessions and document retention policy.
- Expand runtime metrics to include cleanup counts, DB/session counts, proxy session counts by age bucket, and recent error counters if feasible without secrets.
- Improve SAML UI/docs clarity so scaffolding cannot be mistaken for working institutional login.
- Build a first SAML implementation slice: signed metadata/cert handling, login initiation, ACS assertion validation, and tests.
- Improve proxy compatibility for difficult vendor sites: richer JS rewriting strategy, CSP policy rewriting, more SPA route/data patterns, and diagnostics that point staff to missing rules.
- Add CI or Makefile targets for load-test smoke validation against the fake vendor, separate from full performance runs.
- Add docs/tests for operational backup/restore of SQLite data and config directories.
- Add admin/operator documentation for interpreting access logs, proxy diagnostics, missed rewrites, and runtime metrics.
- Review API scope model and role mapping for least privilege and institutional support workflows.
- Add product acceptance tests for a full happy path: create resource, login as patron, open resource, recover missed asset, logout, and verify denied access.

## P2 Roadmap

- Implement virtual-host proxy mode after DNS/TLS/admin-host separation design is complete.
- Add Postgres support for larger single-node or HA deployments.
- Add Redis or equivalent shared session/cache store for HA proxy/login sessions.
- Add complete SAML/Shibboleth SP support, then evaluate OIDC only if product direction requires it.
- Add signed proxy links if needed for controlled direct access workflows.
- Add richer vendor compatibility packs or templates for common resource patterns.
- Add bulk resource import/export UX and validation reports for large resource collections.
- Add resource version history and rollback in the admin UI if config revisions are insufficient for resource admins.
- Add structured operational dashboards outside the built-in minimal admin UI, likely as a separate API client.
- Add packaging/release automation, upgrade notes, and migration checks.

## Suggested Next 10 Issues In Order

1. **Repo hygiene and release snapshot:** Verify runtime DB files are ignored, run `go test ./...`, and commit a clean baseline.
2. **Fix README session wording:** Update `What It Is Not Yet` and any stale text so docs match implemented local admin/user sessions.
3. **Manual proxy login verification:** Follow the documented manual flow for `/odo/https/www.lib.umn.edu/`, a deeper path, and `/odo?url=...`; record results and any regression.
4. **Add session cleanup maintenance:** Implement or document a simple cleanup command/job for expired/revoked sessions and stale cookie-jar candidates.
5. **Production readiness checklist:** Create a checklist covering `APP_PUBLIC_URL`, secrets, proxy login, access logs, data/config paths, reverse proxy headers, backups, and SAML status.
6. **SAML clarity pass:** Make Auth/SAML UI and docs unmistakably label login/ACS as not implemented while preserving provider config and metadata value.
7. **Fake-vendor CI smoke target:** Add a developer/CI target that starts fake vendor and Odo in safe local mode and runs `k6/smoke.js` or an equivalent Go smoke test. **Uncertain:** CI environment support for k6 may affect approach.
8. **Diagnostics usability pass:** Add examples that map common failures to diagnostics fields, especially `login_required`, anonymous rule matches, missed rewrites, and blocked hosts.
9. **Proxy compatibility backlog split:** Break “full JS-aware proxy” into smaller issues: CSP rewriting, SPA data route coverage, JS URL rewriting boundaries, WebSockets decision, virtual-host prerequisites.
10. **SAML implementation design issue:** Write the detailed technical plan for SAML login initiation and ACS validation, including certificate storage, metadata, NameID/attributes, local user mapping, sessions, and tests.
