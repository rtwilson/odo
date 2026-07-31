# Installing Odo on a Linux VM

## Overview

This guide is for traditional Linux VM installs using a compiled `odo` binary, `/etc` configuration, `/var/lib` data, `/var/log` logs, and systemd. It is intended for sysadmins and library systems staff who are comfortable with SSH, systemd, reverse proxies, and command-line administration.

The standard production layout is:

- Binary: `/usr/local/bin/odo`
- Environment file: `/etc/odo/odo.env`
- Resource config: `/etc/odo/resources/`
- Auth config: `/etc/odo/auth/`
- Optional OpenAPI copy: `/etc/odo/openapi.yaml`
- Database: `/var/lib/odo/odo.db`
- App log: `/var/log/odo/odo.log`
- Access log: `/var/log/odo/access.log`
- Runtime user and group: `odo`

Odo normally listens on `127.0.0.1:8080`. Public HTTPS should be handled by a reverse proxy such as Apache/httpd, nginx, or Caddy.

## Requirements

- A Linux server with systemd.
- Root or sudo access.
- A reverse proxy such as Apache/httpd, nginx, or Caddy for public HTTPS.
- Go 1.23 or a downloaded Odo binary.
- SQLite data stored on persistent disk.
- A public hostname if exposing Odo beyond localhost.

Odo should not be exposed directly to the public Internet without a reverse proxy and TLS.

## Build or Download Odo

Build from the repository:

```bash
make build
```

This writes the binary to:

```text
bin/odo
```

If you download a release binary instead, place it at `bin/odo` before running the installer, or set `ODO_BINARY=/path/to/odo`.

## Install With Script

From the repository root:

```bash
sudo scripts/install-linux.sh
```

The installer:

- Creates the `odo` user and group if needed.
- Creates `/etc/odo`, `/etc/odo/resources`, `/etc/odo/auth`, `/var/lib/odo`, and `/var/log/odo`.
- Installs `bin/odo` to `/usr/local/bin/odo` if the binary exists.
- Installs `packaging/systemd/odo.service` to `/etc/systemd/system/odo.service`.
- Installs `/etc/odo/odo.env` only if it does not already exist.
- Runs `systemctl daemon-reload`.

To overwrite `/etc/odo/odo.env` with the example file:

```bash
sudo scripts/install-linux.sh --force
```

Use `--force` carefully. It may replace local configuration.

## Configure `/etc/odo/odo.env`

Edit:

```bash
sudo editor /etc/odo/odo.env
```

Minimum production settings:

```bash
APP_ENV=production
APP_BIND_ADDR=127.0.0.1:8080
APP_PUBLIC_URL=https://access.example.edu
APP_DATA_DIR=/var/lib/odo
APP_CONFIG_DIR=/etc/odo
APP_DB_PATH=/var/lib/odo/odo.db
APP_ACCESS_LOG_PATH=/var/log/odo/access.log
APP_ACCESS_LOG_FORMAT=privacy
APP_KEY_HASH_SECRET=change-me
APP_ADMIN_API_KEY=change-me
APP_PROXY_REQUIRE_LOGIN=true
APP_TRUST_PROXY_HEADERS=true
```

Replace every `change-me` value.

Generate strong values with:

```bash
openssl rand -base64 32
```

Use different random values for:

```bash
APP_KEY_HASH_SECRET=...
APP_ADMIN_API_KEY=...
```

`APP_KEY_HASH_SECRET` is used to protect stored API key hashes. Keep it stable after deployment. Changing it may invalidate or break verification of stored API keys, depending on the current Odo implementation.

`APP_ADMIN_API_KEY` is a bootstrap API bearer token. It is used to make the first protected API calls. It is not a browser login password.

Use it like this:

```bash
Authorization: Bearer <APP_ADMIN_API_KEY>
```

Do not type `APP_ADMIN_API_KEY` into the `/login` form.

After editing the environment file, restart Odo:

```bash
sudo systemctl restart odo
sudo systemctl status odo
```

## Database Persistence

For Linux VM installs, Odo’s SQLite database should live on persistent disk.

Recommended setting:

```bash
APP_DB_PATH=/var/lib/odo/odo.db
```

The database is persistent because it is stored under `/var/lib/odo`, not because of `APP_ENV=production`, `APP_ENV=demo`, or any other environment name.

`APP_ENV` may control defaults such as development warnings, demo behavior, logging defaults, seed data, or session behavior, but it should not be relied on for database persistence.

In other words:

```text
APP_ENV=production + APP_DB_PATH=/var/lib/odo/odo.db = persistent database
```

A demo environment may also persist data if it uses a persistent `APP_DB_PATH`.

An ephemeral path such as `/tmp`, an in-memory database, or a non-persistent container layer may lose data even if `APP_ENV=production`.

Persistence checklist:

- `/var/lib/odo` exists.
- `/var/lib/odo` is owned or writable by the `odo` service user.
- `APP_DB_PATH=/var/lib/odo/odo.db`.
- The systemd unit allows writing to `/var/lib/odo`.
- Backups include `/var/lib/odo/odo.db`.

Check:

```bash
sudo ls -ld /var/lib/odo
sudo ls -l /var/lib/odo/odo.db
sudo systemctl status odo
```

If the database file does not exist yet, start Odo once and check again.

## Start Service

```bash
sudo systemctl enable --now odo
sudo systemctl status odo
```

App logs:

```bash
journalctl -u odo -f
```

The systemd unit may also append service stdout and stderr to `/var/log/odo/odo.log`. If file access logging is enabled, access logs are written to `/var/log/odo/access.log`.

## Check Health

From the VM:

```bash
curl -s http://127.0.0.1:8080/api/v1/health
```

Expected response:

```json
{"status":"ok","time":"2026-06-11T00:00:00Z"}
```

The timestamp will vary.

You can also check the API index:

```bash
curl -s http://127.0.0.1:8080/api/v1
```

`/api/v1` is an API index. It is not the browser login page.

## Put Behind Apache/httpd

This is a minimal reverse proxy example. Add your normal TLS certificate, logging, and site policy.

For RHEL/Fedora-style systems, place the config under:

```text
/etc/httpd/conf.d/odo.conf
```

For Debian/Ubuntu-style systems, the equivalent site config is usually under:

```text
/etc/apache2/sites-available/
```

Starting point:

```apacheconf
<VirtualHost *:443>
    ServerName access.example.edu

    SSLEngine On
    SSLCertificateFile /etc/letsencrypt/live/access.example.edu/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/access.example.edu/privkey.pem

    ProxyPreserveHost On
    ProxyRequests Off

    RequestHeader set X-Forwarded-Proto "https"
    RequestHeader set X-Forwarded-Host "access.example.edu"
    RequestHeader set X-Forwarded-Port "443"

    AllowEncodedSlashes NoDecode

    ProxyPass / http://127.0.0.1:8080/ nocanon retry=0
    ProxyPassReverse / http://127.0.0.1:8080/

    ErrorLog /var/log/httpd/odo-ssl-error.log
    CustomLog /var/log/httpd/odo-ssl-access.log combined
</VirtualHost>
```

For RHEL/Fedora, validate and reload with:

```bash
sudo httpd -t
sudo systemctl reload httpd
```

If SELinux blocks proxying from httpd to Odo, enable network connections for httpd:

```bash
sudo setsebool -P httpd_can_network_connect 1
```

For a full RHEL/httpd + Let’s Encrypt webroot setup, use a separate deployment note or site-specific runbook. The important Odo settings are:

```bash
APP_PUBLIC_URL=https://access.example.edu
APP_TRUST_PROXY_HEADERS=true
```

## Put Behind nginx

Starting point:

```nginx
server {
    listen 443 ssl;
    server_name access.example.edu;

    ssl_certificate /etc/letsencrypt/live/access.example.edu/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/access.example.edu/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port 443;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

Validate and reload using your distribution’s nginx commands.

## Put Behind Caddy

Starting point:

```caddy
access.example.edu {
    reverse_proxy 127.0.0.1:8080
}
```

Set:

```bash
APP_PUBLIC_URL=https://access.example.edu
APP_TRUST_PROXY_HEADERS=true
```

## First Access: Bootstrap Key, Stored API Key, and Admin Login

Odo has two related but different administration mechanisms:

1. Bootstrap API key
2. Stored API keys
3. Local admin users

These are not interchangeable.

### Bootstrap API Key

The bootstrap API key is the value of:

```bash
APP_ADMIN_API_KEY=...
```

in:

```text
/etc/odo/odo.env
```

It is used for initial API administration and recovery.

It is not a human user account.

It is not typed into `/login`.

Use it as a bearer token:

```bash
-H 'Authorization: Bearer <APP_ADMIN_API_KEY>'
```

### Stored API Keys

Stored API keys are created through Odo’s API. They are stored hashed in the database. The full token is shown only once when created.

Stored API keys are preferred for ongoing automation and API administration.

### Local Admin Users

Local users are used for browser login.

To use the browser admin UI, a local admin user must exist.

Browser flow:

```text
https://access.example.edu/login
```

then:

```text
https://access.example.edu/admin
```

The bootstrap API key and stored API keys are for API authentication. Local users are for browser session authentication.

## Create the First Stored API Key

Use the bootstrap `APP_ADMIN_API_KEY` from `/etc/odo/odo.env`.

Example:

```bash
curl -X POST https://access.example.edu/api/v1/api-keys \
  -H 'Authorization: Bearer replace-with-bootstrap-admin-api-key' \
  -H 'Content-Type: application/json' \
  -d '{"name":"Initial admin API key","scopes":["admin"]}'
```

The returned token is shown once. Store it securely.

Example response shape:

```json
{
  "id": "key_...",
  "name": "Initial admin API key",
  "token": "odo_live_...",
  "scopes": ["admin"]
}
```

After this, use the returned `odo_live_...` token for normal API administration:

```bash
curl https://access.example.edu/api/v1 \
  -H 'Authorization: Bearer odo_live_...'
```

Once you have a stored admin API key and a local admin user, rotate the bootstrap key or keep it as an emergency-only value.

To rotate the bootstrap key:

```bash
sudo editor /etc/odo/odo.env
sudo systemctl restart odo
```

Do not commit `/etc/odo/odo.env` or any real API key to Git.

## Create the First Admin User

A browser login requires a local user.

If your Odo build includes the user-management API, create the first admin user with a stored admin API key or the bootstrap API key.

Example using a stored admin API key:

```bash
curl -X POST https://access.example.edu/api/v1/users \
  -H 'Authorization: Bearer odo_live_...' \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "admin",
    "display_name": "Odo Admin",
    "password": "replace-with-a-long-random-password",
    "roles": ["admin"],
    "status": "active"
  }'
```

If your build uses `super_admin` instead of `admin`, use:

```json
"roles": ["super_admin"]
```

Check the current API index while authenticated to see whether the user endpoint exists:

```bash
curl https://access.example.edu/api/v1 \
  -H 'Authorization: Bearer odo_live_...'
```

If `/api/v1/users` is not listed or returns `404`, this build does not expose user creation through the API. In that case, use the project’s documented first-user bootstrap mechanism, if available.

If no first-user mechanism exists yet, that is an MVP blocker. A Linux VM install needs one of the following:

- `POST /api/v1/users` protected by the bootstrap/stored admin API key
- a CLI command such as `odo users create-admin`
- a one-time setup token flow
- documented environment-based first-admin seeding

Do not assume that an API key can log in through the browser. `/login` requires a local user account.

## Log In to the Admin UI

Open:

```text
https://access.example.edu/login
```

Log in with the local admin user.

Then open:

```text
https://access.example.edu/admin
```

The admin UI should use the logged-in browser session.

If the admin UI still offers an API key input, you may paste a stored admin API key there for API-key-based administration. Normal browser administration should use the local admin login once users are configured.

Logout should be available at:

```text
https://access.example.edu/logout
```

## API Authentication Behavior

The API should be default-deny except for explicitly public endpoints.

Expected public endpoints:

```text
GET /api/v1
GET /api/v1/health
```

Possibly public, if implemented:

```text
GET /openapi.yaml
```

Protected endpoints should require a session or bearer token, for example:

```text
/api/v1/resources
/api/v1/api-keys
/api/v1/users
/api/v1/config
/api/v1/diagnostics
/api/v1/logs
/api/v1/system
/api/v1/auth/saml/providers
```

Unauthenticated API requests should return JSON `401`, not login HTML.

Browser pages may redirect to login:

```text
/admin
/resources
/odo/...
```

## Add First Resource

Open:

```text
https://access.example.edu/admin
```

Log in as an admin user.

Go to **Resources** and use the Resource Config Builder.

Resource JSON files can also live under:

```text
/etc/odo/resources/
```

They can be validated or imported from the admin UI or API.

Example API import or create flow depends on the current Odo resource API. A typical pattern is:

```bash
curl -X POST https://access.example.edu/api/v1/resources \
  -H 'Authorization: Bearer odo_live_...' \
  -H 'Content-Type: application/json' \
  --data-binary @config/resources/example.json
```

If the resource API uses a different endpoint or method, follow the OpenAPI schema or the current admin UI.

## Backup

Back up:

- `/etc/odo`
- `/var/lib/odo/odo.db`
- `/var/log/odo` if you need logs

Example:

```bash
sudo tar -czf odo-backup-$(date +%F).tgz /etc/odo /var/lib/odo/odo.db
```

Including logs:

```bash
sudo tar -czf odo-backup-with-logs-$(date +%F).tgz /etc/odo /var/lib/odo/odo.db /var/log/odo
```

Back up `/etc/odo/odo.env` carefully. It contains secrets.

## Upgrade

Build or download the new binary, then:

```bash
sudo systemctl stop odo
sudo cp odo /usr/local/bin/odo
sudo systemctl start odo
sudo systemctl status odo
```

Database migrations run automatically on startup if implemented by the current Odo build.

Before upgrading production systems, back up:

```text
/etc/odo
/var/lib/odo/odo.db
```

## Uninstall

Remove the service but keep configuration, database, and logs:

```bash
sudo scripts/uninstall-linux.sh --remove-binary
```

Purge configuration, database, and logs only when you are sure you have backups:

```bash
sudo scripts/uninstall-linux.sh --remove-binary --purge
```

The purge path asks for confirmation unless `--yes` is passed.

## Troubleshooting

### Service will not start

Check:

```bash
journalctl -u odo -n 100
sudo systemctl status odo
sudo cat /etc/odo/odo.env
```

Look for invalid environment values, missing directories, port conflicts, or permission errors.

### Health check fails locally

Confirm:

```bash
APP_BIND_ADDR=127.0.0.1:8080
```

Then check:

```bash
sudo systemctl status odo
curl -s http://127.0.0.1:8080/api/v1/health
```

### Public URL redirects or generated URLs look wrong

Set:

```bash
APP_PUBLIC_URL=https://access.example.edu
```

Restart Odo:

```bash
sudo systemctl restart odo
```

### Reverse proxy headers are ignored

Set:

```bash
APP_TRUST_PROXY_HEADERS=true
```

Only set this when Odo is reachable only through the trusted reverse proxy.

### Database errors

Check ownership and permissions:

```bash
sudo ls -ld /var/lib/odo
sudo ls -l /var/lib/odo
```

The `odo` service user must be able to read and write the database path.

### Database did not persist

Check:

```bash
grep APP_DB_PATH /etc/odo/odo.env
sudo ls -l /var/lib/odo/odo.db
```

The database is persistent only if `APP_DB_PATH` points to persistent storage. `APP_ENV=demo` is not required for persistence.

### Access log errors

Check ownership and permissions:

```bash
sudo ls -ld /var/log/odo
sudo ls -l /var/log/odo
```

### I can reach `/api/v1` but cannot log in

`/api/v1` is an API index. It is not the browser login page.

Use:

```text
https://access.example.edu/login
```

To log in through the browser, a local user must exist.

Use the bootstrap API key from `/etc/odo/odo.env` to create either:

- a stored admin API key
- a local admin user, if the user API or first-user mechanism exists

The bootstrap key is used in an HTTP `Authorization: Bearer ...` header. It is not typed into the login form.

### `/api/v1/users` does not exist

If `/api/v1/users` does not exist, the current build may not have API user creation implemented.

Check the API index while authenticated:

```bash
curl https://access.example.edu/api/v1 \
  -H 'Authorization: Bearer odo_live_...'
```

If there is no user-management endpoint, use the project’s current first-user bootstrap mechanism. If none exists, add one before treating the Linux VM install path as complete.

### `/logout` does not work

Expected browser logout path:

```text
https://access.example.edu/logout
```

Expected behavior:

- clears the session cookie
- revokes or deletes the server-side session
- redirects to `/login` or `/login?logged_out=1`

If `/logout` is missing, update Odo before using the install in a real deployment.

### Protected API endpoints are callable without authentication

This is a security bug.

Expected behavior:

- `/api/v1` and `/api/v1/health` may be public
- protected `/api/v1/*` endpoints require authentication
- unauthenticated API requests return JSON `401`
- authenticated but unauthorized API requests return JSON `403`

Do not expose Odo publicly until protected API routes require authentication.

### Apache/httpd cannot proxy to Odo on RHEL/Fedora

Check SELinux:

```bash
getsebool httpd_can_network_connect
sudo ausearch -m AVC -ts recent
```

If needed:

```bash
sudo setsebool -P httpd_can_network_connect 1
```

### Reverse proxy returns 502

Check Odo directly:

```bash
curl -I http://127.0.0.1:8080/api/v1/health
```

If direct access fails, fix Odo first.

If direct access works, check reverse proxy configuration, SELinux, firewall, and logs.

## First-Install Checklist

- [ ] Build or download `odo`.
- [ ] Run `sudo scripts/install-linux.sh`.
- [ ] Edit `/etc/odo/odo.env`.
- [ ] Replace `APP_KEY_HASH_SECRET`.
- [ ] Replace `APP_ADMIN_API_KEY`.
- [ ] Confirm `APP_DB_PATH=/var/lib/odo/odo.db`.
- [ ] Set `APP_PUBLIC_URL=https://access.example.edu`.
- [ ] Set `APP_PROXY_REQUIRE_LOGIN=true`.
- [ ] Set `APP_TRUST_PROXY_HEADERS=true` only behind a trusted reverse proxy.
- [ ] Start Odo with systemd.
- [ ] Confirm local health check.
- [ ] Configure HTTPS reverse proxy.
- [ ] Confirm public health check.
- [ ] Create stored admin API key.
- [ ] Create local admin user.
- [ ] Log in at `/login`.
- [ ] Open `/admin`.
- [ ] Confirm `/logout` works.
- [ ] Confirm protected `/api/v1/*` routes require auth.
- [ ] Import or create first resource.
- [ ] Back up `/etc/odo` and `/var/lib/odo/odo.db`.
