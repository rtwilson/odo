# Future Virtual-Host Proxying

Odo currently uses path-based proxy URLs by default:

```text
/odo/https/www.jstor.org/stable/123
```

Path mode is the MVP default because it is easy to run behind ordinary reverse proxies, does not require wildcard DNS, and works well for many resources while Odo is still building out compatibility features.

## Why virtual-host mode may be needed

Some vendor sites assume that every page, script, fetch call, cookie, and redirect stays on a browser origin that looks like the vendor host. Path mode keeps everything under the Odo origin, which is simpler, but difficult modern sites may eventually need host-based proxy URLs such as:

```text
https://www-jstor-org.access.example.edu/stable/123
```

Virtual-host mode can improve compatibility for sites that are sensitive to origins, same-site cookies, absolute redirects, or JavaScript URL construction.

## Required DNS

A virtual-host deployment would need wildcard DNS for the proxy host space:

```text
*.access.example.edu
```

The admin host must remain separate from proxied resource hosts. For example:

```text
admin.access.example.edu
www-jstor-org.access.example.edu
```

## Required TLS

Virtual-host mode would require a wildcard TLS certificate that covers the proxied host space:

```text
*.access.example.edu
```

Odo does not manage DNS or TLS certificates. Those remain the responsibility of the reverse proxy and site operations team.

## Host encoding

The simple readable format could be:

```text
www-jstor-org.access.example.edu
```

That form is convenient, but it may not represent every valid vendor host safely or reversibly. A future safer encoding may use a prefix and base32 payload:

```text
h--base32payload.access.example.edu
```

The reserved config placeholders are:

```env
APP_VIRTUAL_HOST_BASE_DOMAIN=access.example.edu
APP_VIRTUAL_HOST_ENCODING=dash
```

These settings are not active until `virtual_host` mode is implemented.

## Cookie and origin implications

Virtual-host mode changes browser origin behavior. That can help vendor compatibility, but it also means Odo must be precise about:

- Cookie domain rewriting.
- SameSite behavior.
- Redirect targets.
- Content Security Policy.
- JavaScript-generated URLs.
- Keeping admin and API hosts out of proxied resource hostnames.

Vendor cookies should still remain controlled by Odo's proxy/session model and must not be allowed to escape into unrelated resource hosts.

## Reverse proxy considerations

A reverse proxy would need to route both the admin host and wildcard resource hosts to Odo while preserving enough host information for Odo to recover the upstream target.

Starting shape:

```text
admin.access.example.edu        -> 127.0.0.1:8080
*.access.example.edu            -> 127.0.0.1:8080
```

`APP_TRUST_PROXY_HEADERS=true` should only be enabled when Odo is reachable only through that trusted reverse proxy.

## Migration plan

The intended progression is:

1. `path`: Default and recommended MVP mode.
2. `dual`: Generate path URLs while accepting both path and query compatibility URLs.
3. `virtual_host`: Future mode after wildcard DNS, wildcard TLS, host decoding, redirects, cookies, diagnostics, and admin-host separation are implemented.
4. Virtual-host preferred: Possible later deployment default for institutions that need difficult-site compatibility.

Do not deploy `virtual_host` mode yet. Odo currently logs a warning and falls back to path mode if `APP_PROXY_URL_MODE=virtual_host` is configured.
