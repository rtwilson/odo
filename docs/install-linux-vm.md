# Installing Odo on a Linux VM

## Overview

This guide is for traditional Linux VM installs using a compiled `odo` binary, `/etc` configuration, `/var/lib` data, `/var/log` logs, and systemd. It is intended for sysadmins and library systems staff who are comfortable with SSH, systemd, and reverse proxies.

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

## Requirements

- A Linux server with systemd.
- Root or sudo access.
- A reverse proxy such as Apache, nginx, or Caddy for public HTTPS.
- Go 1.23 or a downloaded Odo binary.
- SQLite data stored on persistent disk.

Odo listens on `127.0.0.1:8080` in the systemd example. TLS stays in the reverse proxy.

## Build or Download Odo

Build from the repository:

```sh
make build
```

This writes the binary to `bin/odo`.

If you download a release binary instead, place it at `bin/odo` before running the installer, or set `ODO_BINARY=/path/to/odo`.

## Install With Script

From the repository root:

```sh
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

```sh
sudo scripts/install-linux.sh --force
```

## Configure /etc/odo/odo.env

Edit:

```sh
sudo editor /etc/odo/odo.env
```

Minimum production settings:

```env
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

Replace every `change-me` value. `APP_ADMIN_API_KEY` is useful as a bootstrap token, but stored API keys are better for ongoing administration.

## Start Service

```sh
sudo systemctl enable --now odo
sudo systemctl status odo
```

App logs:

```sh
journalctl -u odo -f
```

The systemd unit also appends service stdout and stderr to `/var/log/odo/odo.log`. If file access logging is enabled, access logs are written to `/var/log/odo/access.log`.

## Check Health

From the VM:

```sh
curl -s http://127.0.0.1:8080/api/v1/health
```

Expected response:

```json
{"status":"ok","time":"2026-06-11T00:00:00Z"}
```

## Put Behind Apache

Starting point:

```apache
<VirtualHost *:443>
    ServerName access.example.edu

    ProxyPreserveHost On
    RequestHeader set X-Forwarded-Proto "https"
    RequestHeader set X-Forwarded-Host "access.example.edu"

    ProxyPass / http://127.0.0.1:8080/
    ProxyPassReverse / http://127.0.0.1:8080/
</VirtualHost>
```

Add your normal TLS certificate, logging, and site policy.

## Put Behind nginx

Starting point:

```nginx
server {
    listen 443 ssl;
    server_name access.example.edu;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

## Put Behind Caddy

Starting point:

```caddyfile
access.example.edu {
    reverse_proxy 127.0.0.1:8080
}
```

## Create First API Key

Use the bootstrap `APP_ADMIN_API_KEY` from `/etc/odo/odo.env`:

```sh
curl -X POST https://access.example.edu/api/v1/api-keys \
  -H 'Authorization: Bearer change-me' \
  -H 'Content-Type: application/json' \
  -d '{"name":"Initial admin","scopes":["admin"]}'
```

The returned token is shown once. Store it securely, then update `/etc/odo/odo.env` to remove or rotate the bootstrap value when you are ready.

## Add First Resource

Open:

```text
https://access.example.edu/admin
```

Enter an admin API key, go to **Resources**, and use the Resource Config Builder. See [Adding Resources in Odo](resource-how-to.md) for the plain-language resource workflow.

Resource JSON files can also live under `/etc/odo/resources/` and be validated or imported from the admin UI or API.

## Backup

Back up:

- `/etc/odo`
- `/var/lib/odo/odo.db`
- `/var/log/odo` if you need logs

Example:

```sh
sudo tar -czf odo-backup-$(date +%F).tgz /etc/odo /var/lib/odo/odo.db
```

Including logs:

```sh
sudo tar -czf odo-backup-with-logs-$(date +%F).tgz /etc/odo /var/lib/odo/odo.db /var/log/odo
```

## Upgrade

Build or download the new binary, then:

```sh
sudo systemctl stop odo
sudo cp odo /usr/local/bin/odo
sudo systemctl start odo
sudo systemctl status odo
```

Database migrations run automatically on startup.

## Uninstall

Remove the service but keep configuration, database, and logs:

```sh
sudo scripts/uninstall-linux.sh --remove-binary
```

Purge configuration, database, and logs only when you are sure you have backups:

```sh
sudo scripts/uninstall-linux.sh --remove-binary --purge
```

The purge path asks for confirmation unless `--yes` is passed.

## Troubleshooting

- Service will not start: run `journalctl -u odo -n 100` and check `/etc/odo/odo.env`.
- Health check fails locally: confirm `APP_BIND_ADDR=127.0.0.1:8080` and that `systemctl status odo` shows the service running.
- Public URL redirects or SAML metadata look wrong: set `APP_PUBLIC_URL=https://access.example.edu`.
- Reverse proxy headers are ignored: set `APP_TRUST_PROXY_HEADERS=true` only when Odo is reachable only through the trusted reverse proxy.
- Database errors: check ownership and permissions on `/var/lib/odo`.
- Access log errors: check ownership and permissions on `/var/log/odo`.
