# Deploying Odo with a Container

This guide shows a small production-oriented deployment using Podman or Docker-compatible container images. It keeps TLS and public routing in a reverse proxy such as Caddy, nginx, or Apache.

## Build an image with Podman

From the repository root:

```sh
podman build -t odo:dev .
```

The image listens on port 8080, runs as a non-root user, stores data under `/var/lib/odo`, and reads config from `/etc/odo`.

## Run locally with Podman

```sh
podman run --rm -p 8080:8080 \
  -e APP_ENV=development \
  -e APP_ADMIN_API_KEY=devsecret \
  -e APP_KEY_HASH_SECRET=local-secret \
  odo:dev
```

Test health:

```sh
curl -s http://127.0.0.1:8080/api/v1/health
```

Then open:

```text
http://127.0.0.1:8080/admin
```

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

Preferred production paths:

- `APP_DATA_DIR=/var/lib/odo`
- `APP_DB_PATH=/var/lib/odo/odo.db`
- `APP_CONFIG_DIR=/etc/odo`

`APP_DB_PATH` is still supported for compatibility, but production deployments should put the database on persistent storage.

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

Odo uses this value when it needs a public base URL, including SAML Service Provider defaults and secure browser cookie decisions. If it is unset in development, Odo can infer a local request URL. In production, Odo logs a warning.

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

## Production checks

Use production mode on a server:

```env
APP_ENV=production
APP_PROXY_REQUIRE_LOGIN=true
```

When `APP_ENV=production`, Odo logs warnings if important settings are missing or unsafe:

- `APP_PUBLIC_URL` is not set.
- `APP_KEY_HASH_SECRET` is not set.
- `APP_ADMIN_API_KEY=devsecret`.
- `APP_PROXY_REQUIRE_LOGIN=false`.
- The database path appears to be temporary.

## Create the first API key

If you start with `APP_ADMIN_API_KEY=change-me`, use it only as a bootstrap token. Create a stored API key, then rotate away from the bootstrap value:

```sh
curl -X POST https://access.example.edu/api/v1/api-keys \
  -H 'Authorization: Bearer change-me' \
  -H 'Content-Type: application/json' \
  -d '{"name":"Initial admin","scopes":["admin"]}'
```

The returned token is shown once.

## Open the admin UI

Open:

```text
https://access.example.edu/admin
```

Enter an admin API key in the page field for protected actions. The key is kept only in the page runtime and is not stored in browser storage.
