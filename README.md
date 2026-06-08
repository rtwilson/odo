# odo

`odo` is an early MVP skeleton for a Go-based, self-hostable, API-first FOSS library access middleware/proxy application.

The important architectural rule is that management and configuration happen through versioned JSON APIs. The admin UI at `/admin` uses those same APIs with `fetch`; it is not a separate control plane.

## What This MVP Is

- A single compiled Go application.
- Local HTTP service on port 8080 by default.
- Versioned JSON APIs under `/api/v1`.
- Embedded SQLite persistence using `modernc.org/sqlite`.
- Resource registry import from dropped JSON config files.
- URL/domain rule testing.
- A minimal safe outbound `GET`/`HEAD` proxy for configured and allowed targets.
- Privacy-conscious first-pass request logging that avoids logging full query strings.

## What It Is Not Yet

- A full HTML/link rewriter.
- A full admin login/session system. Management APIs use a simple bearer API key for now.
- A SAML/Shibboleth Service Provider.
- A production HA deployment.
- A complete audit implementation.

## Local Run

Run without an API key for local dev. Management endpoints are unprotected in this mode, and the app logs a startup warning:

```sh
go run ./cmd/odo
```

Run with an API key:

```sh
APP_ADMIN_API_KEY=devsecret go run ./cmd/odo
```

Open:

```text
http://127.0.0.1:8080/admin
```

## API Documentation

The current OpenAPI 3.1 spec is served by the app:

```text
http://127.0.0.1:8080/openapi.yaml
```

Environment variables:

- `APP_ADDR`, default `:8080`
- `APP_DB_PATH`, default `./data/app.db`
- `APP_CONFIG_DIR`, default `./config`
- `APP_ADMIN_API_KEY`, optional for local dev; when set, management endpoints require `Authorization: Bearer <token>`
- `APP_ACCESS_LOG_FORMAT`, default `privacy`
- `APP_ACCESS_LOG_PATH`, optional path to append access logs

## API Examples

Health:

```sh
curl -s http://127.0.0.1:8080/api/v1/health
```

Validate resource config files without writing to the database:

```sh
curl -X POST http://127.0.0.1:8080/api/v1/config/validate \
  -H 'Authorization: Bearer devsecret' | jq
```

Import resource config files:

```sh
curl -s -X POST http://127.0.0.1:8080/api/v1/config/import \
  -H 'Authorization: Bearer devsecret' | jq
```

List config revisions:

```sh
curl http://127.0.0.1:8080/api/v1/config/revisions \
  -H 'Authorization: Bearer devsecret' | jq
```

Get a config revision:

```sh
curl http://127.0.0.1:8080/api/v1/config/revisions/1 \
  -H 'Authorization: Bearer devsecret' | jq
```

List resources:

```sh
curl -s http://127.0.0.1:8080/api/v1/resources
```

Test a URL:

```sh
curl -s -X POST http://127.0.0.1:8080/api/v1/rules/test-url \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://www.jstor.org/stable/example"}'
```

Create or update a resource:

```sh
curl -s -X POST http://127.0.0.1:8080/api/v1/resources \
  -H 'Authorization: Bearer devsecret' \
  -H 'Content-Type: application/json' \
  -d @config/resources/jstor.json
```

Minimal proxy fetch:

```sh
curl -s 'http://127.0.0.1:8080/p?url=https://www.jstor.org/stable/example'
```

## Access Logging

Access logs default to privacy-filtered output on stdout. Privacy mode logs request metadata and safe proxy decisions without full query strings, target URLs, article URLs, search terms, or reading-history-like paths.

Available formats:

```sh
APP_ACCESS_LOG_FORMAT=privacy
APP_ACCESS_LOG_FORMAT=common
APP_ACCESS_LOG_FORMAT=combined
APP_ACCESS_LOG_FORMAT=json
```

Write access logs to a file by setting:

```sh
APP_ACCESS_LOG_PATH=/path/to/access.log
```

Example:

```sh
APP_ACCESS_LOG_FORMAT=json go run ./cmd/odo
```

## Proxy Safety

Odo is default-deny for proxy/access decisions. Proxy targets must be HTTPS URLs that match configured resource domains. Raw IP hosts, localhost, private networks, link-local addresses, non-global addresses, suspicious internal hostnames such as `.local` and `.internal`, URL userinfo, fragments, wildcards, and non-default ports are blocked before the proxy fetch is allowed.

`/p` now performs a minimal safe outbound `GET`/`HEAD` proxy. HTML rewriting is not implemented yet, cookies are not passed through yet, and only a small set of safe request and response headers are copied. Redirects are validated before returning a local proxied redirect to `/p?url=...`.

## Podman

Build:

```sh
podman build -t odo:dev .
```

Run with mounted data and config directories. The `:Z` suffix lets Podman relabel the mounts for SELinux on Fedora:

```sh
mkdir -p data config/resources
podman run --rm -p 8080:8080 \
  -e APP_ADMIN_API_KEY=dev-secret \
  -v "$PWD/data:/data:Z" \
  -v "$PWD/config:/config:Z" \
  odo:dev
```

## Next Steps

- Hardened API-key storage and rotation.
- SAML SP support as a first-class module.
- Signed proxy links.
- URL SSRF protections.
- Outbound proxy fetch/rewrite.
- HA with PostgreSQL and Redis.
