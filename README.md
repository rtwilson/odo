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
- Partial HTML/CSS asset URL rewriting for basic proxied page rendering.
- Privacy-conscious first-pass request logging that avoids logging full query strings.

## What It Is Not Yet

- A full JavaScript-aware browser compatibility proxy.
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

## Admin UI Resource Management

Open `http://127.0.0.1:8080/admin`. If `APP_ADMIN_API_KEY` is configured, enter that value in the Admin API Key field. Resources can be created, edited, and deleted from the UI using a raw JSON editor.

The UI uses the same `/api/v1` endpoints available to scripts and integrations; it is not a separate control plane.

Environment variables:

- `APP_ADDR`, default `:8080`
- `APP_DB_PATH`, default `./data/app.db`
- `APP_CONFIG_DIR`, default `./config`
- `APP_ADMIN_API_KEY`, optional for local dev; when set, management endpoints require `Authorization: Bearer <token>`
- `APP_ACCESS_LOG_FORMAT`, default `privacy`
- `APP_ACCESS_LOG_PATH`, optional path to append access logs
- `APP_PROXY_DEBUG`, default `false`; when `true`, `/odo` adds safe cookie/session diagnostic count headers without exposing cookie values
- `APP_PROXY_URL_MODE`, default `path`; use `query` to generate `/odo?url=...` compatibility links
- `APP_PROXY_MAX_BODY_BYTES`, default `10485760`; maximum proxied POST request body size

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

Get one resource:

```sh
curl http://127.0.0.1:8080/api/v1/resources/jstor | jq
```

Delete a resource:

```sh
curl -X DELETE http://127.0.0.1:8080/api/v1/resources/jstor \
  -H 'Authorization: Bearer devsecret' | jq
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
curl -s 'http://127.0.0.1:8080/odo/https/www.jstor.org/stable/example'
```

Admin proxy test fetch:

```sh
curl -X POST http://127.0.0.1:8080/api/v1/proxy/test-fetch \
  -H 'Authorization: Bearer devsecret' \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://www.jstor.org/"}' | jq
```

Recent access logs:

```sh
curl http://127.0.0.1:8080/api/v1/logs/access/recent \
  -H 'Authorization: Bearer devsecret' | jq
```

## Admin Troubleshooting Tools

The admin UI includes a Proxy Test panel that can test rule matching, open a target through `/odo`, or fetch a bounded body preview through the protected `/api/v1/proxy/test-fetch` endpoint.

Recent access logs are privacy-filtered and available through the admin UI. Proxy diagnostics are also exposed from the UI for checking blocked hosts, rewrite counts, and upstream status as those diagnostics grow. These tools are intended to make the access layer easier to understand and troubleshoot without exposing full target URLs, cookies, or authorization headers.

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

`/odo/https/{host}/{path}` is the preferred local/MVP public proxy route. `/odo?url=https://...` is still accepted for compatibility and manual testing. Clicked links, asset references, GET form actions, and validated upstream redirects are generated through one proxy URL builder and rewritten back through `/odo` so the patron's browser continues to talk to Odo and vendors continue to see Odo's outbound IP rather than the patron's IP.

Path mode is the default:

```sh
APP_PROXY_URL_MODE=path
```

Query compatibility mode can be selected with:

```sh
APP_PROXY_URL_MODE=query
```

Unknown local paths now return `404` instead of redirecting to `/admin`, which makes missed rewrites easier to spot during testing. Virtual-host mode may be added later for EZproxy-style URLs such as `www-economist-com.access.library.edu`.

`/odo` performs a minimal safe outbound `GET`/`HEAD`/`POST` proxy. HTML `href`, `src`, `action`, and common asset attributes are rewritten when they point to safe, allowlisted proxy targets. `srcset` is partially supported. CSS `url(...)` references are partially rewritten for `text/css` responses and inline style attributes.

Odo keeps a server-side per-session cookie jar for proxied browsing. The browser receives only an `odo_proxy_sid` cookie; upstream/vendor cookies are stored server-side and are not exposed directly to the browser. This improves continuity across proxied requests and POST form submissions, but it is not user authentication. In HA deployments, the in-memory session store would need Redis or another shared session store.

POST form submissions are forwarded upstream when the target is safe and proxyable. Request bodies are size-limited by `APP_PROXY_MAX_BODY_BYTES`, and request bodies/form values are not logged. JavaScript fetch/XHR interception, WebSockets, and full SPA compatibility are future work. Only a small set of safe request and response headers are copied. Redirects are validated before returning a local proxied redirect, which defaults to `/odo/https/{host}/{path}`. Content-Security-Policy is not copied yet, and `integrity` attributes are removed when URLs are rewritten, because upstream CSP and SRI often reject proxied/transformed assets before fuller policy rewriting exists.

## Domain Rules

Resource domain rules support roles and actions. Existing configs without `action` still work: `blocked` defaults to `block`, `external` defaults to `allow`, and all other roles default to `proxy`.

Common combinations:

- `content` / `proxy`
- `asset` / `proxy`
- `api` / `proxy`
- `auth` / `proxy`
- `redirect` / `allow`
- `external` / `allow`
- `blocked` / `block`

Broad subdomain proxy rules are useful for library resources, but explicit block rules should be added for analytics, tracking, ads, or unrelated third-party domains discovered during diagnostics. More specific exact rules take precedence over broader subdomain rules, and explicit blocks win when specificity is equal or greater.

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
- Deeper JavaScript-aware proxy rewriting.
- HA with PostgreSQL and Redis.
