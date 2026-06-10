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
- A full admin login/session system. Management APIs use bearer API keys with hashed database storage and bootstrap/dev fallback support.
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

For stored API keys, set a hash secret:

```sh
APP_ADMIN_API_KEY=devsecret APP_KEY_HASH_SECRET='change-me-long-random-secret' go run ./cmd/odo
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

## Admin UI

Open `http://127.0.0.1:8080/admin`. The admin UI is organized into sections for Dashboard, Resources, Config, Proxy Test, Diagnostics / Logs, API Keys, Auth / SAML, and Settings / System.

Enter an `APP_ADMIN_API_KEY` bootstrap token or stored API key in the global Admin API Key field for protected actions. The key is kept only in the page runtime and is not stored in browser storage. Resources can still be created, edited, and deleted using a raw JSON editor.

API key management is available in the API Keys section. Newly created or rotated tokens are shown once with a copy warning and are not persisted by the UI. The UI uses the same documented `/api/v1` endpoints available to scripts and integrations; it is not a separate control plane.

The Resources section includes a Resource Config Builder for authoring structured JSON resource configs. It can generate JSON, validate it through `/api/v1/resources/validate`, save it through the normal resource API, and export a `resource-<id>.json` file.

Environment variables:

- `APP_ADDR`, default `:8080`
- `APP_DB_PATH`, default `./data/app.db`
- `APP_CONFIG_DIR`, default `./config`
- `APP_PUBLIC_URL`, optional public base URL used for generated SAML SP metadata defaults
- `APP_ADMIN_API_KEY`, optional bootstrap/dev fallback for creating and managing stored API keys
- `APP_KEY_HASH_SECRET`, recommended secret used to HMAC stored API key tokens; if unset, local dev uses SHA-256 with a startup warning
- `APP_ACCESS_LOG_FORMAT`, default `privacy`
- `APP_ACCESS_LOG_PATH`, optional path to append access logs
- `APP_PROXY_DEBUG`, default `false`; when `true`, `/odo` adds safe cookie/session diagnostic count headers without exposing cookie values
- `APP_PROXY_URL_MODE`, default `path`; use `query` to generate `/odo?url=...` compatibility links
- `APP_PROXY_MAX_BODY_BYTES`, default `10485760`; maximum proxied POST request body size
- `APP_PROXY_INJECT_JS_SHIM`, default `true`; injects a small same-origin `fetch()`/XHR rewrite shim into proxied HTML
- `APP_PROXY_REFERER_RECOVERY`, default `true`; recovers missed local asset/script paths when a proxied Referer identifies the upstream host

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

## API Key Management

`APP_ADMIN_API_KEY` remains a bootstrap/dev fallback. For ongoing use, create database-backed API keys and send them as `Authorization: Bearer <token>`. Odo stores only a hash and short prefix, never the full token after creation. The full token is shown only when a key is created or rotated.

Create a stored key:

```sh
curl -X POST http://127.0.0.1:8080/api/v1/api-keys \
  -H 'Authorization: Bearer devsecret' \
  -H 'Content-Type: application/json' \
  -d '{"name":"Local admin","scopes":["admin"]}' | jq
```

Use the returned token:

```sh
curl http://127.0.0.1:8080/api/v1/config/revisions \
  -H 'Authorization: Bearer odo_live_...' | jq
```

Rotate or revoke a key:

```sh
curl -X POST http://127.0.0.1:8080/api/v1/api-keys/key_abc123/rotate \
  -H 'Authorization: Bearer odo_live_...' | jq

curl -X POST http://127.0.0.1:8080/api/v1/api-keys/key_abc123/revoke \
  -H 'Authorization: Bearer odo_live_...' | jq
```

Initial scopes are `admin`, `resources:read`, `resources:write`, `config:read`, `config:write`, `diagnostics:read`, `logs:read`, `auth:read`, and `auth:write`. The `admin` scope can access all management endpoints. Set `APP_KEY_HASH_SECRET` in persistent deployments so stored token hashes use HMAC-SHA256 instead of local-dev SHA-256.

## Resource Config Builder

Odo resources are JSON control-plane objects. The expanded resource config model supports entry URLs, per-resource HTTP method allowlists, cookie policy metadata, request header rules, anonymous URL rules, resource-specific content rewrite rules, compatibility hints, and domain behavior rules.

Domain rules can use behaviors:

- `proxy`: safe matching requests may be proxied.
- `cookie_domain`: host/domain may be used for cookie scope metadata.
- `redirect_only`: redirects may be allowed without proxying the host directly.
- `block`: explicit block; this wins over broader allow/proxy rules.
- `external_allow`: links may leave the proxy without being treated as failures.

Anonymous URL rules are scoped public proxy allowances, similar in intent to EZproxy `AnonymousURL`. They still pass URL safety checks and should be narrow, such as `https://cms-films.economist.com/*`.

Content rewrite rules are explicit resource-specific text substitutions for difficult vendors. They support a small set of Odo-native replacement tokens such as `{proxy_url:https://www.example.com/}`, `{proxy_http_url:https://www.example.com/}`, `{proxy_base_url}`, `{target_origin}`, and `{proxy_host_suffix}`. Use them sparingly, especially for JSON or JavaScript payloads, and validate generated JSON before saving.

Request header rules can model vendor-specific behavior such as removing `X-Requested-With` from outbound proxy requests. The included JSTOR sample at `config/resources/jstor.json` shows a more complex resource profile with method expansion, cookie policy, domain behaviors, and a header removal rule. `config/resources/jstor-aluka.json` provides a second related-resource example. `config/resources/economist.json` shows anonymous URL rules and content rewrite rules for a more app-shell-heavy resource.

The builder is not a full EZproxy parser and does not guarantee exact EZproxy directive compatibility.

## SAML SP Scaffolding

Odo is designed to act as a SAML Service Provider for campus/Shibboleth-style identity infrastructure. Full SAML login initiation and assertion validation are future work, but the MVP includes SAML provider configuration APIs, admin UI controls, and a Service Provider metadata endpoint.

Manage provider config through:

```sh
curl http://127.0.0.1:8080/api/v1/auth/saml/providers \
  -H 'Authorization: Bearer devsecret' | jq
```

The public SP metadata endpoint is:

```text
http://127.0.0.1:8080/auth/saml/metadata
```

Placeholder routes are also present for future integration:

- `GET /auth/saml/login`
- `POST /auth/saml/acs`

A sample provider config lives at `config/auth/saml/campus-shibboleth.json`. The current scaffold omits signing certificates and does not validate SAML assertions yet.

## Admin Troubleshooting Tools

The admin UI includes a Proxy Test panel that can test rule matching, open a target through `/odo`, or fetch a bounded body preview through the protected `/api/v1/proxy/test-fetch` endpoint.

Recent access logs are privacy-filtered and available through the admin UI. Proxy diagnostics are also exposed from the UI for checking blocked hosts, rewrite counts, and upstream status as those diagnostics grow. These tools are intended to make the access layer easier to understand and troubleshoot without exposing full target URLs, cookies, or authorization headers.

### Missed rewrites and referer recovery

Modern sites may generate paths dynamically in JavaScript. These can appear as local paths outside `/odo`, such as `/assets/app.js` or `/mfe-copper-roof/.../remoteEntry.js`, when they should have been proxied.

By default, Odo can infer the upstream host from a proxied `Referer` and recover the request through the normal proxy path. Recovery is still subject to URL safety checks, DNS/IP safety validation, resource allowlists, and domain rule actions.

Missed asset, script, CSS, image, and API-like URLs may be silently recovered from the proxied `Referer`. Missed top-level document navigations, such as a clicked link that lands on `/action/doAdvancedSearch`, redirect to the canonical `/odo/https/{host}/{path}` URL instead. This keeps the browser address bar and future relative URL resolution inside the proxy. Query strings are preserved in the redirect, but privacy logs and missed-rewrite diagnostics avoid recording full query strings.

Disable referer recovery with:

```sh
APP_PROXY_REFERER_RECOVERY=false
```

Use browser DevTools plus **Load Missed Rewrites** in the admin UI to inspect recovered, redirected, denied, and unrecovered missed rewrite events.

### Modern app-shell pages

Section, search, and landing pages may depend on JavaScript chunks, route manifests, JSON data routes, and API calls before the full header or navigation appears. Article pages may work earlier because they are often more server-rendered.

Odo classifies and recovers common app/data paths from a proxied `Referer`, including `_next` data routes, manifests, `mfe-` module chunks, `remoteEntry.js`, `/static/`, `/assets/`, `/api/`, and `/graphql` requests. These requests are silently proxied when they are safe and proxyable; document navigations still redirect to canonical `/odo/https/{host}/{path}` URLs. Use browser DevTools Network together with **Load Missed Rewrites** and **Load Proxy Diagnostics** to inspect section-page failures.

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

Unknown local paths now return `404` instead of redirecting to `/admin` unless referer-based recovery applies, which makes missed rewrites easier to spot during testing. Missed document navigations redirect to canonical `/odo/https/{host}/{path}` URLs, while missed assets can be silently proxied. Virtual-host mode may be added later for EZproxy-style URLs such as `www-economist-com.access.library.edu`.

`/odo` performs a minimal safe outbound `GET`/`HEAD`/`POST` proxy. HTML `href`, `src`, `action`, and common asset attributes are rewritten when they point to safe, allowlisted proxy targets. `srcset` is partially supported. CSS `url(...)` references are partially rewritten for `text/css` responses and inline style attributes.

Odo keeps a server-side per-session cookie jar for proxied browsing. The browser receives only an `odo_proxy_sid` cookie; upstream/vendor cookies are stored server-side and are not exposed directly to the browser. This improves continuity across proxied requests and POST form submissions, but it is not user authentication. In HA deployments, the in-memory session store would need Redis or another shared session store.

POST form submissions are forwarded upstream when the target is safe and proxyable. Request bodies are size-limited by `APP_PROXY_MAX_BODY_BYTES`, and request bodies/form values are not logged. Full JavaScript rewriting, WebSockets, and full SPA compatibility are future work. Only a small set of safe request and response headers are copied. Redirects are validated before returning a local proxied redirect, which defaults to `/odo/https/{host}/{path}`. Content-Security-Policy is not copied yet, and `integrity` attributes are removed when URLs are rewritten, because upstream CSP and SRI often reject proxied/transformed assets before fuller policy rewriting exists.

Odo injects a small JavaScript shim into proxied HTML pages by default. The shim rewrites same-origin `fetch()` and `XMLHttpRequest` calls back through `/odo`, which helps modern sites that render headers, search boxes, menus, and consent UI through JavaScript. This is not full JavaScript rewriting, and server-side URL validation remains authoritative. Disable it with:

```sh
APP_PROXY_INJECT_JS_SHIM=false
```

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
