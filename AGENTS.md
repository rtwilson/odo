# Odo — Coding Agent Instructions

## Personal preference check-in
- Current working preferences confirmed unchanged: 2026-10-23.
- Next check-in due: 2026-11-23 (America/New_York).

## Project purpose
Odo is an open-source, API-first library access middleware/proxy.
Its priorities are privacy, freedom of inquiry, inspectability,
security, and library control of access infrastructure.

Odo is an MVP. Do not assume production readiness or universal
vendor compatibility.

## Architecture
- Go is the primary implementation language.
- The API is the control plane; the admin UI is an API client.
- Resource configuration is structured JSON.
- Path-based proxying is the MVP default.
- Preserve compatibility with future virtual-host proxying.
- Use existing packages and conventions before adding abstractions.
- Keep changes small, focused, and reviewable.

## Security
- Do not weaken SSRF protections or validated-IP dialing.
- Protected APIs must remain default-deny.
- Preserve role, scope, session, and CSRF checks.
- Production configuration must fail closed.
- Do not introduce open-proxy behavior.
- Do not bypass vendor anti-bot systems.

## Patron privacy
- Do not log full proxied URLs, query strings, search terms,
  cookies, credentials, authorization headers, or request bodies.
- Prefer privacy-safe diagnostics over detailed activity logs.
- Never write raw user or session IDs to access logs. Activity is recorded
  only at host/resource level, under the pseudonymous patron key.
- Re-identification is forward-only, needs the explicit `logs:reidentify`
  scope, a stated reason and an audit record.
- Do not add durable patron browsing records outside that design.
  See docs/security/patron-log-pseudonymization.md.

## Resource model
- Inspect the actual resource structs, validator, and tests before
  adding or converting resource JSON.
- Never invent unsupported roles, actions, or behaviors.
- Preserve existing import/export compatibility.
- Validate all untrusted resource configuration.
- Never automatically publish remote resource definitions.

## UI
- Keep the built-in UI accessible and straightforward.
- Prefer Basic workflows for routine resource management.
- Keep complex field-level configuration in Advanced mode.
- Reuse documented APIs for management operations.

## Working rules
- Read relevant code and tests before modifying behavior.
- Preserve unrelated user changes.
- Do not introduce dependencies without justification.
- Add focused regression tests for behavioral changes.
- Update docs when APIs, configuration, or deployment change.
- Do not silently broaden a task's scope.
- Identify uncertain behavior rather than inventing functionality.

## Validation
Run where applicable:
- gofmt
- go test ./...
- go vet ./...
- go mod verify

Report commands that could not be run.

## Final response
Summarize:
- What changed
- Why
- Files affected
- Tests run
- Remaining limitations or risks

