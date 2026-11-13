# Virtual-host proxying: setup guide

In virtual-host mode each vendor host gets its own proxy hostname, for example:

```text
https://www-jstor-org.proxy.library.example.edu/stable/123
```

Path mode puts every vendor under the Odo origin
(`/odo/https/www.jstor.org/...`). Virtual-host mode gives each vendor's pages,
scripts, cookies and redirects their own browser origin, separate from Odo's
login and admin pages and from other vendors.

The trade-off is infrastructure: virtual-host mode needs wildcard DNS and a
wildcard TLS certificate.

Path mode remains the default. Virtual-host mode is new in 0.1.0. Validate each
resource before relying on it; see [limitations](#limitations).

How it works is described in
[virtual-host routing](architecture/virtual-host-routing.md),
[hostname registry](architecture/hostname-registry.md) and
[automatic handoff](architecture/automatic-handoff.md).

## 1. Choose names

You need two names:

| Setting | Example | Purpose |
| --- | --- | --- |
| `APP_PUBLIC_URL` | `https://odo.library.example.edu` | Central Odo origin: login, Resources, admin, launch |
| `APP_PROXY_BASE_DOMAIN` | `proxy.library.example.edu` | Parent of all vendor proxy hostnames |

Vendor hosts appear one label below the base: `www.jstor.org` becomes
`www-jstor-org.proxy.library.example.edu`.

**Name rules:**
- Both names must be domains you control. Do not use a public suffix.
- The central URL must be `https` on port 443, with no path or query.
- The central host may sit outside the proxy base or beneath it.
- Keep the base short. Vendor labels can be up to 63 characters, and full
  names must fit in 253.

**What Odo accepts:** only the exact central host and registered vendor labels.
Every other name under the base gets HTTP 421.

## 2. Wildcard DNS

Point the central name and a wildcard for the base at your reverse proxy:

```text
odo.library.example.edu.          A     203.0.113.10
*.proxy.library.example.edu.      A     203.0.113.10
```

(or AAAA / CNAME equivalents). Wildcard DNS only routes traffic; it never
authorizes anything. Odo admits a vendor name only when it is registered.

## 3. Wildcard TLS (DNS-01)

You need a certificate covering the central name and
`*.proxy.library.example.edu`. Public CAs issue wildcard certificates only via
the ACME **DNS-01** challenge, so your ACME client needs API access to your DNS
provider.

### Caddy with a DNS provider plugin

1. Build Caddy with your provider's module (for example
   `xcaddy build --with github.com/caddy-dns/<provider>`).
2. Use a site block like this:

```caddyfile
odo.library.example.edu, *.proxy.library.example.edu {
	tls {
		dns <provider> {env.DNS_API_TOKEN}
	}
	# Preserve the original Host (Caddy's default) and overwrite forwarding headers.
	reverse_proxy 127.0.0.1:8080
}
```

### Certbot plus another reverse proxy

```sh
certbot certonly --dns-<provider> \
  -d odo.library.example.edu -d '*.proxy.library.example.edu'
```

Configure renewal hooks to reload your proxy. DNS-01 renewal needs the same
DNS API credentials every 60–90 days, so test `certbot renew --dry-run`.

## 4. Reverse proxy requirements

- **Port:** terminate TLS on port 443. Odo rejects any other port.
- **Host header:** forward the client's original `Host` unchanged. Odo decides
  central vs. vendor routing from it.
- **Forwarding headers:** overwrite, never append, `X-Forwarded-For` and
  `X-Forwarded-Proto`. Set `APP_TRUST_PROXY_HEADERS=true` only when the proxy
  does this and Odo is unreachable except through it.
- **Admin and API paths:** do not add path-based rules that send vendor
  hostnames to Odo's admin or API paths. Odo already refuses them with 421.
- **Edge logging:** do not log full request URIs or headers. Vendor paths and
  queries can contain search terms. Caddy logs nothing unless you add a `log`
  directive. If you need edge logs, remove the URI and headers with your proxy's
  log filter.

## 5. Configure Odo

```sh
APP_ENV=production
APP_PUBLIC_URL=https://odo.library.example.edu
APP_PROXY_URL_MODE=virtual_host
APP_HOST_GUARD=true
APP_PROXY_BASE_DOMAIN=proxy.library.example.edu
APP_PROXY_REQUIRE_LOGIN=true
APP_TRUST_PROXY_HEADERS=true
# Production defaults; restarts keep patrons signed in and their host grants valid.
APP_SESSION_PERSIST_ON_RESTART=true
APP_KEY_HASH_SECRET=<random>
APP_LOG_PSEUDONYM_SECRET=<random, at least 32 bytes>
```

**Startup fails closed.** A missing or invalid host guard, central URL or base
domain stops startup, or makes every request return 503. Odo never falls back
silently to path mode.

`APP_EXPERIMENTAL_HANDOFF=true` from earlier test builds still works. It is a
deprecated alias for `APP_PROXY_URL_MODE=virtual_host`, logs a warning, and is
rejected if it conflicts with another `APP_PROXY_URL_MODE`.

## 6. Register vendor hostnames

A vendor host is reachable only once it has a registry entry.

- **Exact rules:** saving a resource (admin UI, API or config import) registers
  each exact `proxy` domain rule automatically.
- **Subdomain rules:** hosts covered only by a subdomain rule are never
  discovered automatically. Add an exact rule, or reconcile with explicit
  approval:

```sh
curl -X POST https://odo.library.example.edu/api/v1/proxy-hostnames/reconcile \
  -H "Authorization: Bearer $ODO_KEY" -H 'Content-Type: application/json' \
  -d '{"approved_hosts":["library.example.org"]}'
```

If a launch fails with `{"reason":"hostname_not_registered"}`, the host passes
resource policy but has no registry entry. See
[hostname registry](architecture/hostname-registry.md).

## 7. Verify

1. `https://odo.library.example.edu/api/v1/health` returns 200.
2. An unregistered name such as `https://nothing-here.proxy.library.example.edu/`
   returns 421.
3. Sign in, open **Resources**, and launch a resource. The browser should land
   on its `*.proxy...` hostname after a brief "Connecting securely…" page.
4. Settings / System shows `proxy_url_mode: virtual_host`.
5. Access logs show `route=handoff_vendor_content`, the target host, the
   resource and a pseudonymous `patron=` key. They never show paths or queries;
   see [patron log pseudonymization](security/patron-log-pseudonymization.md).

## Migrating from path mode

- **Bookmarks:** old `/odo/https/...` and `/odo?url=...` bookmarks are
  validated and redirected to launch. They are never served on the central
  origin, so vendor scripts never run next to Odo's login cookies.
- **Resources page:** links go straight to `/launch`.
- **Hashed names:** registries created before readable names still use hashed
  `h-...` labels. They keep working. Switch them with
  `POST /api/v1/proxy-hostnames/reconcile {"migrate_readable":true}`.
  Patrons then launch once more.

## Single instance and restarts

Virtual-host mode supports exactly **one Odo instance**. In-progress handoffs
and vendor cookie jars are held in process memory. Do not run replicas behind
a load balancer.

**Across a restart:**
- **Odo login sessions:** survive, with `APP_SESSION_PERSIST_ON_RESTART=true`.
- **Host grants:** survive. They are stored as token hashes and fully
  re-validated on every use.
- **Vendor cookies:** are lost, because vendor cookie jars stay in memory.
  Vendors that authenticate by IP re-establish their session on the next
  request. Vendors that need an interactive vendor login ask for it again.
- **In-progress launches:** restart automatically on the next page load.

The container image stops gracefully: in-flight requests get up to 8 seconds.

## Rollback

1. Remove `APP_PROXY_URL_MODE=virtual_host` (or set it to `path`) and
   restart.
2. Keep `APP_HOST_GUARD=true`, so names under the proxy base keep getting 421.
   With the guard off, Odo would answer central pages on any hostname that
   reaches it.
3. Odo returns to path mode at `/odo/...`. Registered hostnames and stored
   grants stay in the database, inert.
4. DNS and TLS can stay in place for a later retry.

Patrons launch resources again from **Resources**.

## Limitations

- **What gets rewritten:**
  - URLs built by JavaScript are not rewritten;
  - URLs inside CSS (`url(...)`, `@import`) are not rewritten;
  - `<meta refresh>` targets are not rewritten;
  - links to hosts of other resources, or to unregistered hosts, are left
    unchanged and load directly from the vendor.
- **Extra hosts:** one handoff grants a resource's other registered hosts, at
  most six besides the one launched. Other hosts get a grant on first
  navigation.
- **Third-party assets:** maps, fonts and CDNs load directly from the third
  party. Vendor pages send `Referrer-Policy: strict-origin`, so these requests
  carry only the proxy origin.
- **Bot protection:** vendors behind bot challenges (for example Cloudflare)
  may block the proxy's IP. Odo does not work around them; ask the vendor to
  allowlist your proxy.
- **Instances:** single instance only (see above).
