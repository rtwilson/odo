# Hostname registry foundation

Virtual-host request routing remains disabled. This implements canonical
hostname identity, SQLite storage, and explicit resource reconciliation from
the proposed virtual-host ADR.

`proxy.RegistryHostname` normalizes DNS names with the non-transitional IDNA
lookup profile, including label, length and bidirectional-text checks. Names
become lowercase ASCII without a terminal dot or optional HTTPS port 443.
URL components, other ports, IP literals, local names, the central hostname,
and names in the proxy suffix are rejected. The proxy suffix and central
hostname are explicit trusted inputs, not values taken from request headers.

The canonical label is `h-` followed by lowercase, unpadded base32 of the
normalized hostname's SHA-256 digest. It is a fixed 54-character lookup key,
not a reversible encoding. The resulting proxy FQDN must fit DNS length limits.

`db.RegisterProxyHostname` explicitly enrolls one hostname. No HTTP handler
calls it, and no request or vendor response automatically enrolls a host.
The additive, idempotent database migration creates `proxy_hostnames`, with
unique hostname and label columns. Repeat enrollment preserves identity;
conflicts fail without overwriting another mapping. Records have no delete
operation, so identities remain reserved when resources are removed.

`db.LookupProxyHostname` performs an exact label lookup. A successful lookup
does not authorize access or establish DNS safety. Future routing must apply
current resource/method/anonymous policy and validated-IP dialing independently.

`db.ReconcileProxyHostnames` is an explicit administrative operation.
It enrolls active exact proxy domains and explicitly approved
concrete hosts covered by current domain policy. Subdomain rules do not trigger
host discovery or enroll their base automatically. Global domain-rule precedence
is preserved, including blocks. Anonymous URL exceptions do not enroll hosts.
Resource rules must match the canonical ASCII hostname under existing resource
matching semantics; reconciliation does not change that policy engine.

Each reconciliation reads resources and inserts mappings within one transaction.
A conflict rolls back all new mappings from that batch. The returned list contains
that batch's candidates, not every previously enrolled identity. Removed or
disabled resources never remove stored identities.

`db.ProxyHostnameResourceIDs` derives many-to-many associations from current
resource definitions, without a duplicate relationship table. Resource edits,
disablement, deletion, and new blocks therefore affect the next inspection
without reconciliation. This is a domain-policy inspection only: it omits
URL-specific anonymous exceptions, method restrictions, login and DNS checks.
It is not a routing admission decision or an authorization grant.

## Protected reconciliation API

`POST /api/v1/proxy-hostnames/reconcile` requires `resources:write` using existing
API-key or browser-session authentication. Browser sessions also require the
existing `X-Odo-CSRF` header. No new scopes are introduced.

Set `APP_PUBLIC_URL` to the central HTTPS origin and `APP_PROXY_BASE_DOMAIN` to
the proxy DNS suffix before using this API. These settings identify trusted
deployment names for registry validation only; they do not enable virtual-host
routing. Missing or invalid settings return 503. Host and forwarded headers
never supply these names. No deployment configuration is changed by the API.

The request body is a JSON object, at most 64 KiB, with an optional
`approved_hosts` array of up to 100 hostnames. Unknown fields, trailing JSON,
invalid hostnames, and candidates rejected by domain policy return 400.

```json
{"approved_hosts":["cdn.vendor.example"]}
```

An empty object enrolls only configured exact proxy domains. Successful responses
are `Cache-Control: no-store` and use this shape:

```json
{"hostnames":[{"hostname":"cdn.vendor.example","label":"h-<base32-digest>"}]}
```

The label shown is illustrative; actual labels contain the full digest. Results
include this reconciliation's candidates, not all retained identities. A storage
failure or identity conflict returns 500 with the batch rolled back. Reconciliation
performs no DNS lookup or HTTP fetch. Existing authentication audit events record
the API operation, not the submitted body.

Aliases, registry listing/inspection APIs, and routing integration are pending.
SQLite contention may return an error;
there is no retry policy in this foundation. Before a future rollback, stop Odo
and back up the database. The previous binary ignores the additional table;
retain it to preserve hostname identities if development resumes.
