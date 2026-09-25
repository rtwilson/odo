# Deploying Odo with a Container

This guide shows a small server deployment for controlled demos and restricted design-partner testing using Podman or Docker-compatible container images. It keeps TLS and public routing in a reverse proxy such as Caddy, nginx, or Apache.

This guide does not establish production readiness. Before an Internet-facing pilot, complete the [OWASP before-pilot hardening](security/owasp-top10-2025-review.md#should-fix-before-internet-facing-pilot). See [readiness stages](../README.md#readiness-and-security); `APP_ENV=production` enables safeguards, not a readiness certification.

## Build an image with Podman

From the repository root:

```sh
podman build -t odo:dev .
```

The image listens on port 8080, runs as a non-root user, stores data under `/var/lib/odo`, and reads config from `/etc/odo`.

## Run locally with Podman

```sh
podman run --rm -p 127.0.0.1:8080:8080 \
  -e APP_ENV=development \
  -e APP_ADMIN_API_KEY=devsecret \
  -e APP_KEY_HASH_SECRET=local-secret \
  odo:dev
```

Test health:

```sh
curl -s http://127.0.0.1:8080/api/v1/health
```

For browser access, create a local admin through `POST /api/v1/users` using the bootstrap key, as shown below (use the local HTTP URL and `devsecret` for this development instance). Sign in at `http://127.0.0.1:8080/login`, then open `/admin`.

Do not expose a development instance publicly.

## Run with persistent volumes

For a server deployment, keep the SQLite database and configuration outside the container:

```sh
podman volume create odo-data
sudo mkdir -p /etc/odo
sudo install -m 600 deploy/odo.env.example /etc/odo/odo.env
```

Edit `/etc/odo/odo.env` and replace every `change-me` value with a real secret.

```sh
podman run -d --name odo \
  -p 127.0.0.1:8080:8080 \
  --env-file /etc/odo/odo.env \
  -v odo-data:/var/lib/odo:Z \
  -v /etc/odo:/etc/odo:Z \
  odo:dev
```

Preferred server paths:

- `APP_DATA_DIR=/var/lib/odo`
- `APP_DB_PATH=/var/lib/odo/odo.db`
- `APP_CONFIG_DIR=/etc/odo`

`APP_DB_PATH` is still supported for compatibility, but server deployments should put the database on persistent storage.

## Run with systemd and Quadlet

A Podman Quadlet starting point is included at `deploy/podman/odo.container`.

Typical rootful install:

```sh
sudo mkdir -p /etc/containers/systemd /etc/odo
sudo cp deploy/podman/odo.container /etc/containers/systemd/odo.container
sudo cp deploy/odo.env.example /etc/odo/odo.env
sudo systemctl daemon-reload
sudo systemctl enable --now odo.service
```

Edit `/etc/odo/odo.env` before exposing the service. Use a real image name in the Quadlet file, such as an internal registry image or `localhost/odo:latest`.

## Set the public URL

Set `APP_PUBLIC_URL` to the real HTTPS URL users will open:

```env
APP_PUBLIC_URL=https://access.example.edu
```

Odo uses this value when it needs a public base URL, including SAML Service Provider defaults and secure browser cookie decisions. In production it must be an absolute HTTPS URL or Odo refuses to start. All Odo-owned browser-session, proxy-session, and CSRF cookies are marked `Secure` for that HTTPS deployment. Local HTTP development may use non-`Secure` cookies.

## Reverse proxy headers

Odo ignores forwarded headers by default. Enable them only when Odo is listening behind a trusted reverse proxy:

```env
APP_TRUST_PROXY_HEADERS=true
```

When enabled, Odo may use:

- `X-Forwarded-Proto`
- `X-Forwarded-Host`
- `X-Forwarded-For`

Do not enable this if clients can connect directly to Odo from the public internet.

## Caddy starting point

```caddyfile
access.example.edu {
    reverse_proxy 127.0.0.1:8080
}
```

## nginx starting point

```nginx
server {
    listen 443 ssl;
    server_name access.example.edu;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

## Apache starting point

```apache
<VirtualHost *:443>
    ServerName access.example.edu
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:8080/
    ProxyPassReverse / http://127.0.0.1:8080/
    RequestHeader set X-Forwarded-Proto "https"
</VirtualHost>
```

These reverse proxy snippets are starting points. Add your normal TLS, logging, header, firewall, and monitoring policy.

## Production-mode startup checks

Use production mode on a server:

```env
APP_ENV=production
APP_PROXY_REQUIRE_LOGIN=true
```

When `APP_ENV=production`, Odo refuses to start if important settings are missing or unsafe, including:

- `APP_PUBLIC_URL` is not set.
- `APP_KEY_HASH_SECRET` is not set.
- `APP_ADMIN_API_KEY=devsecret`.
- `APP_PROXY_REQUIRE_LOGIN=false`.
- The database path appears to be temporary.

## Create the first API key

Set `APP_ADMIN_API_KEY` to a strong random bootstrap secret; production mode rejects placeholders such as `change-me`. Substitute that secret in the example below. Create a stored API key, then rotate away from the bootstrap value:

```sh
curl -X POST https://access.example.edu/api/v1/api-keys \
  -H 'Authorization: Bearer <bootstrap-secret>' \
  -H 'Content-Type: application/json' \
  -d '{"name":"Initial admin","scopes":["admin"]}'
```

The returned token is shown once.

## Create a local admin and sign in

Create a local user using the stored admin API key:

```sh
curl -X POST https://access.example.edu/api/v1/users \
  -H 'Authorization: Bearer <stored-admin-token>' \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<long-random-password>","roles":["super_admin"],"status":"active"}'
```

Replace the token and password placeholders before running. Alternatively, set `APP_BOOTSTRAP_ADMIN_USERNAME` and `APP_BOOTSTRAP_ADMIN_PASSWORD` before first startup on an empty user database.

Sign in at `/login` with this local account, then open:

```text
https://access.example.edu/admin
```

Admin/staff users access `/admin` through browser sessions; regular users use `/resources`. `/logout` revokes the session and clears session/CSRF cookies. API keys remain available for automation/bootstrap and as an optional admin UI override kept only in page memory.

Backend scopes enforce API authorization. Unsafe browser-session API methods require `X-Odo-CSRF`, which the admin UI sends; bearer API-key requests do not require it.

SAML SP provider configuration and metadata exist, but SAML login initiation and ACS assertion validation return HTTP 501. Institutional SAML login and OIDC login are not implemented.

## Local login throttling

Odo limits local login failures per normalized account and connection-peer IP: 5 account failures or 20 source failures per fixed 10-minute window, with cooldowns of up to 60 seconds. State is per-process and resets on restart. Behind a reverse proxy, its clients share Odo's source bucket; forwarded client-IP headers are not used by the limiter.

Before an Internet-facing pilot or future production use, configure client-level reverse-proxy rate limiting and alerts for `login_failures_excessive` and `login_throttled`. Distributed throttling is recommended if Odo later supports multi-node deployments. See [login throttling](security/login-throttling.md) for the complete policy, memory cap, audit behavior, and limitations.
