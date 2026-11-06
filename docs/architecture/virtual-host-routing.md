# Virtual-host routing foundation

Virtual-host request routing is disabled. Production startup rejects
`APP_PROXY_URL_MODE=virtual_host`; development retains its warning and path-mode
fallback. This document describes implemented validation helpers and the
remaining routing boundary, not a deployable virtual-host mode.

## Trusted deployment names

`proxy.NewHostRoutingConfig` takes the configured central HTTPS origin and proxy
DNS suffix as explicit inputs. The reconciliation API uses it for
`APP_PUBLIC_URL` and `APP_PROXY_BASE_DOMAIN`. No request or forwarded header
supplies these values.

The central URL must have no credentials, query (including an empty `?`),
fragment (including an empty `#`), or path other than the optional literal `/`.
Names use the existing registry IDNA normalization. Only implicit HTTPS port or
explicit 443 is accepted; IP literals and local names are rejected. The proxy
suffix must leave room for a 54-character generated label and separating dot
within the 253-character DNS name limit. Validation performs no DNS or HTTP
requests. Reconciliation returns 503 for invalid deployment settings.

The central hostname can be outside, at, or beneath the proxy suffix. When it
is beneath the suffix, its exact identity always takes precedence over vendor
candidate classification. Deployments remain responsible for certificates
covering both central and eventual vendor names.

## Authority classification

`HostRoutingConfig.ClassifyAuthority` accepts one HTTP authority string. It
rejects URLs, credentials, whitespace/control bytes, raw Unicode, invalid DNS
names, IP literals, header lists, and ports other than 443. ASCII hostname case,
one terminal dot, and explicit 443 are normalized. IDN requests must use their
ASCII form. The unconfigured zero value rejects all authorities.

There are three outcomes:

| Authority | Result |
| --- | --- |
| Exact normalized central hostname | Central classification |
| One DNS label immediately below the configured proxy suffix | Vendor candidate label |
| Anything else, including the suffix apex unless central | Error |

An arbitrary single-label candidate is **not admitted**. It must later resolve
through exact registry lookup; labels are never decoded into upstream authority.
The opt-in boundary below uses this classifier for central-host admission only.

## Opt-in central host guard

`APP_HOST_GUARD` defaults to false. When enabled, both `APP_PUBLIC_URL` and
`APP_PROXY_BASE_DOMAIN` must pass the configuration validation above. The flag
accepts true/1/yes/on and false/0/no/off, ignoring case and surrounding whitespace.
An unknown flag value is an error. Startup validates this in development and
production; invalid settings stop startup. If a handler is constructed directly
with invalid settings, it rejects requests with generic 503 responses.

At handler construction, the settings are captured. The guard runs after
privacy logging setup and application security headers, but before API-key or
browser-session authentication, cookies, registry lookup, and application
routing. Only the configured central authority reaches those handlers. All
vendor candidates, including registered hosts, and unknown or malformed
authorities receive generic 421 responses with no-store. Rejection creates no
cookies or mappings, reads no application database, and fetches no content.
Rejected requests use a fixed `host_rejected` access-log route instead of their
arbitrary submitted path.

For absolute-form requests, both request Host and URL authority must classify
as the same central hostname, and the absolute URL must use HTTPS without
userinfo or opaque syntax. Equivalent case, terminal dot, and port 443 remain
accepted. Forwarded and X-Forwarded-Host are ignored in both directions: they
cannot admit a rejected Host or override an accepted one.

Enabling the guard does not enable virtual-host routing or isolate vendor
scripts still served through central-origin path mode. Existing path/query
traffic on the central host remains available. Without the opt-in flag,
existing deployments retain their prior host behavior.

Reverse proxies must preserve the external central Host. Health probes using
`127.0.0.1`, localhost, a backend name, or a vendor host will be rejected; send
the configured central Host explicitly. For example:

```sh
curl -H 'Host: odo.example' http://127.0.0.1:8080/api/v1/health
```

Adapt container, load-balancer, and service health checks before enabling this
flag. TLS/DNS setup and trusted-edge controls remain deployment responsibilities.

## Central authentication cookie boundary

With `APP_HOST_GUARD=true`, central browser login issues `__Host-odo_session`
and `__Host-odo_csrf`. Both use Secure, Path=/, no Domain, and SameSite=Lax.
The browser session is HttpOnly. The CSRF cookie remains readable by the admin
UI so it can send the existing `X-Odo-CSRF` header; prefixing does not replace
that check.

Session lookup and CSRF derivation accept only the active session-cookie name.
There is no fallback to `odo_session` while guarded mode is enabled. Logout
revokes the active browser session and clears the active session/CSRF cookies
with the same prefix and attributes. The UI receives its active CSRF cookie
name through page metadata; its inline script stays static for CSP hashing.

When the guard is disabled, existing `odo_session` and `odo_csrf` behavior
remains unchanged, including on HTTPS deployments. Guard mode is a startup
setting: sign out before switching it and sign in again afterward. Existing
cookies and sessions from the other namespace are not automatically migrated
or revoked. In particular, disabling the guard can expose still-valid legacy
sessions again if their cookies remain in the browser.

These prefixes prevent sibling hosts from setting central cookies through a
parent Domain attribute in conforming browsers. They do not isolate vendor
scripts served on the same central origin through path mode. The Origin checks
below address sibling origins; cross-host grants/revocation remain pending.

## Guarded central Origin checks

With the host guard enabled, unsafe requests (POST, PUT, PATCH, DELETE) to
`/login`, `/logout`, `/api/v1`, and `/api/v1/...` must carry exactly one Origin
header matching the configured central HTTPS origin. Comparison uses the same
normalized hostname and default-443 authority rules as host admission. Origin
must contain only scheme and authority: paths (even `/`), credentials, queries,
fragments, `null`, duplicate values, and sibling/vendor origins are rejected.
Referer and Sec-Fetch-Site do not substitute for a missing Origin.

Host admission runs first, then Origin checking, then authentication and normal
application processing. Origin failures return generic 403 with no-store, no
cookies, and no database access. Rejected requests use the fixed access-log
route `origin_rejected`; Origin header values are not logged. Existing management
session CSRF-token checks remain required after Origin acceptance. Login and
logout now require the central Origin too; they do not gain management-API
bearer exemptions.

Bearer management clients may omit Origin on API requests. If they supply an
Origin, it must pass the same check. Authentication still validates the key,
and an invalid key never falls back to cookie authentication. Browser sessions
cannot use this exemption without supplying a separately valid management key.

Guarded `GET /logout` and `HEAD /logout` return 405 with `Allow: POST` without
revoking sessions or clearing cookies. Built-in logout forms already use POST.
Command-line login/logout callers must supply the central Origin explicitly.
Other safe requests and vendor POST workflows under `/odo` are unchanged. The
guard-disabled legacy behavior is unchanged. No cross-origin CORS allowance is
introduced. SAML handlers remain unimplemented and are not enabled by this work.

These checks do not protect central credentials from vendor code served through
central-origin path mode. Production virtual-host migration still requires
separating those origins before vendor-host routing is enabled.

## Required request boundary before enabling traffic

Future vendor dispatch must preserve the guard's ordering before cookie/session
processing, API-key authentication, and application routing. It must continue
rejecting authority disagreement and ignoring untrusted forwarded host values.
The edge must preserve validated Host, overwrite
forwarded headers, and prevent untrusted direct backend access.

Only the configured central host may reach login, admin, management APIs, source
notices, and central continuations. Vendor candidates require exact registry
lookup and independent current resource, method, session/grant, and DNS safety
checks. Unknown, inactive, or rejected hosts must fail without credential
processing, target fetches, or registry enrollment. A vendor's own `/about`,
`/login`, or `/api` path belongs to its vendor origin, not Odo's central mux.

Central credential isolation, same-site request protections, cross-host grant
handoff and revocation, and path-mode origin separation remain release gates.
The current local login continuation is not a cross-host grant. Host dispatch,
DNS/TLS deployment guidance, and vendor compatibility validation remain pending.
