# Patron log pseudonymization

Odo records which hosts and resources patrons use, so administrators can
investigate abuse, credential sharing and automated access. These records are
not tied to a named patron by default.

## What access logs contain

Lines never contain raw user or session IDs. A request made with a patron
session carries `patron=pk_<26 characters>`, an HMAC-SHA256 under
`APP_LOG_PSEUDONYM_SECRET` of the user ID, scoped by the rotation policy below.

Vendor-content lines in virtual-host mode add:
- `target_host`: the registered upstream host;
- `resource_id`;
- `request_class`: `document`, `asset`, `api` or `other`, from the browser's
  Fetch metadata.

Path mode already logs `target_host` and `resource_id`.

Lines never contain request paths, queries, search terms, cookies,
credentials, authorization headers or bodies. `remote_ip` is still logged on
every line; see [limitations](#limitations).

This applies to every access-log format. The `common` and `combined` formats
carry no patron field at all. The admin UI's recent-entries view and
`/api/v1/logs/access/recent` show the same pseudonymous entries.

## Key rotation

The rotation policy sets how long a patron's key stays the same:

| Mode | Key changes | Trade-off |
| --- | --- | --- |
| `time` (default: every 1 month) | Every N days, weeks (starting Monday) or months, aligned to UTC | Repeated use within a window is linkable; separate windows are not |
| `session` | At every login | Only one session's activity is linkable |
| `never` | Never | All of a patron's activity is linkable, indefinitely |

Limits: days 1–366, weeks 1–104, months 1–24.

The policy can be read with `GET /api/v1/settings/log-pseudonymization`
(`system:read` or `logs:read`) and is shown on the admin UI's Settings page.
Changing it requires `admin` scope and a reason of 10–500 characters:
`PUT /api/v1/settings/log-pseudonymization` with
`{"mode":"time","unit":"week","count":2,"reason":"..."}`, or the Settings form.

A change applies to new lines immediately. It is stored in the append-only
`log_pseudonym_policies` table (database triggers block updates and deletes),
together with a `log_pseudonym_policy_changed` audit event in the same
transaction. Existing lines keep their keys. In a multi-instance deployment,
other instances pick up the change at their next restart.

## Re-identification

Re-identification answers "which lines belong to this named patron?". It is a
forward lookup only: Odo derives the patron's keys from the secret. No table
maps keys back to patrons.

```
POST /api/v1/logs/access/reidentify
{"username": "alice", "from": "2026-11-01", "to": "2026-11-13",
 "reason": "suspected credential sharing, ticket 1234"}
```

- **Access:** it requires the `logs:reidentify` scope, granted explicitly to an
  API key. `admin` alone is refused, and no role includes the scope.
- **Range:** `from` and `to` are inclusive dates at most 731 days apart; the
  reason must be 10–500 characters.
- **Keys:** keys are derived under each policy that was in force during the
  range. Session mode yields one key per session of the patron that overlapped
  the range, plus the user-stable fallback for session-less lines. At most 2000
  keys are returned; narrow the range if exceeded.
- **Audit:** a `patron_log_reidentified` audit event is written before any key
  is returned. It records the caller, the target user ID, the range, the key
  count and the reason. If that write fails, the request fails.
- **Response:** the keys (with the window each covers) and any matching
  entries still in the in-memory recent buffer. Search stored log files for the
  returned keys.

## Configuration

- `APP_LOG_PSEUDONYM_SECRET` must be at least 32 bytes and not a placeholder.
  Production refuses to start without it.
  - **Development without it:** keys use a random per-process secret, so they
    stay unlinkable but cannot be re-identified after a restart.
  - **Keep it separate:** do not reuse `APP_KEY_HASH_SECRET`; holding this
    secret is the re-identification capability.
  - **Keep it stable:** changing it makes earlier keys underivable.
- **Retention:** Odo writes to stdout or `APP_ACCESS_LOG_PATH` and does not
  rotate or expire log files. Set retention in your log pipeline to match your
  library's policy.

## Limitations

- **Remote IP:** `remote_ip` remains on every line and is a direct identifier
  for many patrons. Truncating or pseudonymizing it is a separate decision.
- **Unauthenticated lines:** they carry no patron key. Anonymous URL rules
  produce such lines.
- **Old log lines:** they contain the raw `user_id` and `session_id` fields
  used before this change. They are not rewritten.
