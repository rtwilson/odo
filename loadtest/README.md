# Odo Local Load Testing

This directory contains a local-only load-testing setup for Odo. It is designed to exercise session storage, proxy rewriting, cookie jars, redirects, logging, and runtime behavior without sending traffic to real licensed vendors.

Do not load-test real vendor sites. Use the fake vendor server or another local service that you control.

## Contents

- `fake-vendor/`: local Go HTTP server that simulates a vendor site.
- `fake-vendor-resource.json`: Odo resource config for the fake vendor.
- `k6/`: smoke, idle-session, active-browsing, spike, and soak scripts.

## Start the fake vendor

```sh
go run ./loadtest/fake-vendor
```

The fake vendor listens on `127.0.0.1:9090` by default. It provides:

- `/`
- `/section/science`
- `/article/123`
- `/assets/app.css`
- `/assets/app.js`
- `/api/search?q=test`
- `/api/user/status`
- `/redirect-to-article`
- `/slow?ms=500`

It sets cookies, serves HTML/CSS/JS/JSON, includes root-relative and absolute links, makes dynamic API requests from JavaScript, and can simulate slow upstream responses.

## Start Odo for local load tests

Odo normally requires safe public HTTPS proxy targets. For this local fake vendor only, run Odo in development mode with query proxy URLs and the loopback HTTP allowance:

```sh
APP_ENV=development \
APP_ADMIN_API_KEY=devsecret \
APP_KEY_HASH_SECRET=local-secret \
APP_PROXY_REQUIRE_LOGIN=false \
APP_PROXY_URL_MODE=query \
APP_PROXY_ALLOW_LOCAL_HTTP=true \
APP_ACCESS_LOG_FORMAT=privacy \
APP_ACCESS_LOG_PATH=./data/access.log \
APP_PROXY_DEBUG=false \
go run ./cmd/odo
```

`APP_PROXY_ALLOW_LOCAL_HTTP=true` is for local development load tests only. Do not use it for production or for real vendor resources.

Debug proxy logging and debug headers can distort results. Keep `APP_PROXY_DEBUG=false` for performance runs.

## Import the fake resource

The k6 scripts import `fake-vendor-resource.json` during setup when `APP_ADMIN_API_KEY` is available. You can also import it manually:

```sh
curl -s -X POST http://127.0.0.1:8080/api/v1/resources \
  -H 'Authorization: Bearer devsecret' \
  -H 'Content-Type: application/json' \
  --data-binary @loadtest/fake-vendor-resource.json
```

## Run k6 scripts

Install k6 from <https://k6.io/docs/get-started/installation/>.

Smoke test:

```sh
APP_ADMIN_API_KEY=devsecret k6 run loadtest/k6/smoke.js
```

Active browsing, local default of 50 users for 5 minutes:

```sh
APP_ADMIN_API_KEY=devsecret k6 run loadtest/k6/active-browsing.js
```

Larger active browsing examples:

```sh
ACTIVE_USERS=100 DURATION=10m APP_ADMIN_API_KEY=devsecret k6 run loadtest/k6/active-browsing.js
ACTIVE_USERS=250 DURATION=10m APP_ADMIN_API_KEY=devsecret k6 run loadtest/k6/active-browsing.js
ACTIVE_USERS=500 DURATION=10m APP_ADMIN_API_KEY=devsecret k6 run loadtest/k6/active-browsing.js
```

Idle sessions:

```sh
IDLE_SESSIONS=1000 DURATION=10m APP_ADMIN_API_KEY=devsecret k6 run loadtest/k6/idle-sessions.js
IDLE_SESSIONS=5000 DURATION=10m APP_ADMIN_API_KEY=devsecret k6 run loadtest/k6/idle-sessions.js
IDLE_SESSIONS=10000 DURATION=10m APP_ADMIN_API_KEY=devsecret k6 run loadtest/k6/idle-sessions.js
```

If you set `TEST_USERNAME` and `TEST_PASSWORD`, `idle-sessions.js` logs in and holds browser session cookies. Without those values, it performs lightweight anonymous/session-like requests and checks runtime metrics. That fallback does not measure real login-session storage.

Spike test:

```sh
SPIKE_USERS=500 APP_ADMIN_API_KEY=devsecret k6 run loadtest/k6/spike.js
```

Soak test, local default is 100 users for 10 minutes:

```sh
APP_ADMIN_API_KEY=devsecret k6 run loadtest/k6/soak.js
```

Longer soak run:

```sh
SOAK_USERS=100 DURATION=60m APP_ADMIN_API_KEY=devsecret k6 run loadtest/k6/soak.js
```

## Runtime metrics

Odo exposes protected runtime metrics at:

```sh
curl -s http://127.0.0.1:8080/api/v1/system/runtime \
  -H 'Authorization: Bearer devsecret' | jq
```

The response contains non-secret values such as:

- `goroutines`
- `memory_alloc_bytes`
- `memory_sys_bytes`
- `open_sessions`
- `active_sessions_recent`
- `proxy_cookie_jar_sessions`
- `resource_count`
- `uptime_seconds`

Watch these alongside k6 output:

- Request failure rate.
- p95 and p99 request duration.
- Odo process memory.
- Goroutine count growth.
- Open login sessions and recent active sessions.
- Proxy cookie-jar sessions.
- Access log size and write rate.
- SQLite lock or busy errors.
- Upstream/fake-vendor latency.

## What failures usually mean

- High failures on smoke test: Odo, fake vendor, proxy URL mode, local HTTP allowance, or resource import is misconfigured.
- Rising latency with stable fake-vendor latency: Odo proxying, rewriting, logging, DB writes, or local CPU is likely the limit.
- Rising memory or proxy cookie-jar sessions after traffic stops: inspect proxy session cleanup and cookie jar retention.
- SQLite busy/locked errors: concurrent writes are exceeding the current single-node SQLite comfort zone.
- Many redirects to login: `APP_PROXY_REQUIRE_LOGIN` is enabled or test users are not logging in correctly.

## SQLite and session notes

SQLite is acceptable for single-node MVP testing. Heavy concurrent writes may expose lock contention, especially if many users log in, update sessions, or write logs at once.

Session `last_seen_at` updates should be throttled rather than written on every proxied request. Odo currently updates browser login sessions during auth checks; proxy cookie jars are in memory and have idle cleanup.

Access logs should preferably stream to a file during load tests instead of writing every event to SQLite. Use:

```sh
APP_ACCESS_LOG_FORMAT=privacy
APP_ACCESS_LOG_PATH=./data/access.log
```

Expired sessions should be ignored by authentication. Revoked sessions should not remain operational. Expired browser sessions and cookie jars tied to inactive proxy sessions are cleanup candidates for future maintenance work if long soak tests show accumulation. HA or larger production deployments may eventually need Postgres for relational state and Redis or another shared store for sessions.
