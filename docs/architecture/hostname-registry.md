# Hostname registry foundation

Production virtual-host request routing remains disabled; only the
development/test `APP_EXPERIMENTAL_HANDOFF` mode routes registered names (see
[virtual-host routing](virtual-host-routing.md#experimental-vendor-content-delivery)).
This implements canonical
hostname identity, SQLite storage, and explicit resource reconciliation from
the proposed virtual-host ADR.

`proxy.RegistryHostname` normalizes DNS names with the non-transitional IDNA
lookup profile, including label, length and bidirectional-text checks. Names
become lowercase ASCII without a terminal dot or optional HTTPS port 443.
URL components, other ports, IP literals, local names, the central hostname,
and names in the proxy suffix are rejected. The proxy suffix and central
hostname are explicit trusted inputs, not values taken from request headers.

## Readable proxy names

New registrations use EZproxy-style readable labels: the canonical hostname
with each `.` replaced by `-`, so `www.jstor.org` is served at
`www-jstor-org.<proxy base>` and `infoweb.newsbank.com` at
`infoweb-newsbank-com.<proxy base>`. Canonicalization happens first
(lowercase, one trailing dot removed, optional `:443` removed, IDNs converted
to ASCII), and existing hyphens are kept: `my-vendor.example` becomes
`my-vendor-example`.

The label is a lookup key, never decoded. Odo does not turn hyphens back into
dots: `a-b-example` can name `a-b.example` or `a.b-example`, so the upstream
always comes from the stored registry row. An unregistered readable name is
rejected like any unknown label (421).

A host uses the hashed fallback label instead (`h-` followed by lowercase,
unpadded base32 of the hostname's SHA-256 digest, 54 characters) when:

- its readable label would exceed 63 characters, or make the proxy FQDN exceed
  253 characters under the configured suffix;
- its first label is an IDN A-label (`xn--…`), which would read as a different
  punycode label once flattened (a later IDN label stays readable:
  `www.bücher.example` becomes `www-xn--bcher-kva-example`);
- its readable label is already held by another host, or was retired.

Collisions therefore never share or repoint a name. The first host enrolled
under a readable label keeps it permanently; a later host that would produce
the same label gets its own fallback label. Within one reconciliation batch
hosts are processed in hostname order. If the fallback label is unavailable
too, enrollment fails closed. Labels whose proxy FQDN would equal the central
hostname are rejected. Arbitrary aliases are not supported; the fallback label
is the documented form for exceptional hosts.

Admission accepts a stored mapping only if its label is either the host's
current readable label or its fallback label, and the request authority is
exactly `<label>.<proxy base>`. Handoff tickets and grants bind the hostname,
label and full proxy authority, so a grant can never be presented on another
name.

### Migrating hashed names

Deployments that enrolled hosts before readable names keep their hashed
labels: registration, resource saves and plain reconciliation never change an
existing mapping. To move to readable names, an administrator calls the
reconcile API with `{"migrate_readable":true}` (optionally with
`approved_hosts`). In one transaction, each candidate whose readable label is
free is relabeled and its old label is written to
`proxy_hostname_retired_labels`; database triggers then refuse that label for
any insert or update, so an old name can never be routed or reassigned. A host
whose readable label is taken keeps its current label. Any error rolls back the
whole batch, including tombstones. Repeating the migration is a no-op.

Deployment impact: after migration, old `h-…` proxy URLs return 421, and
outstanding pending handoffs, tickets and grants bound to the old authority are
rejected (a page navigation restarts the handoff at central and lands on the
readable name; subresources get 401). Patrons re-launch once; vendor cookie
jars are unaffected. DNS and TLS must cover the proxy suffix with a wildcard
already, so no DNS change is needed. Migrate during a quiet period.

`db.RegisterProxyHostname` explicitly enrolls one hostname. No HTTP handler
calls it, and no request or vendor response automatically enrolls a host.
The additive, idempotent database migration creates `proxy_hostnames`, with
unique hostname and label columns. Repeat enrollment preserves identity;
conflicts fail without overwriting another mapping. Records have no delete
operation, so identities remain reserved when resources are removed.

`db.LookupProxyHostname` performs an exact label lookup. A successful lookup
does not authorize access or establish DNS safety. Future routing must apply
current resource/method/anonymous policy and validated-IP dialing independently.

`db.ReconcileProxyHostnames` is an explicit administrative operation. When
virtual-host settings are configured, a successful resource create, update or
config import also runs it with no approved hosts, because saving an exact
`proxy` domain is the administrator's approval of that host. Hosts covered only
by subdomain rules still need `approved_hosts`. An enrollment failure does not
undo the saved resource; it logs a warning and the reconcile API reports
details.
It enrolls active exact proxy domains and explicitly approved
concrete hosts covered by current domain policy. Subdomain rules do not trigger
host discovery or enroll their base automatically. Global domain-rule precedence
is preserved, including blocks. Anonymous URL exceptions do not enroll hosts.
Resource rules must match the canonical ASCII hostname under existing resource
matching semantics; reconciliation does not change that policy engine.

Each reconciliation reads resources and inserts mappings within one transaction.
A readable-name collision is resolved by the fallback label described above; any
other conflict rolls back all new mappings from that batch. The returned list contains
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
The central origin must have no credentials, query, or fragment, and no path
except an optional literal `/`; even empty `?`/`#` suffixes are rejected.
See [host validation](virtual-host-routing.md) for the shared configuration rules.

The request body is a JSON object, at most 64 KiB, with an optional
`approved_hosts` array of up to 100 hostnames. Unknown fields, trailing JSON,
invalid hostnames, and candidates rejected by domain policy return 400.

```json
{"approved_hosts":["cdn.vendor.example"]}
```

An empty object enrolls only configured exact proxy domains. Successful responses
are `Cache-Control: no-store` and use this shape:

```json
{"hostnames":[{"hostname":"cdn.vendor.example","label":"cdn-vendor-example"}]}
```

Each result shows the host's stored label, which may be a legacy or fallback
`h-…` label. Results include this reconciliation's candidates, not all retained
identities. Add `"migrate_readable":true` to relabel legacy names (see
[migrating hashed names](#migrating-hashed-names)). A storage failure or
unresolvable identity conflict returns 500 with the batch rolled back. Reconciliation
performs no DNS lookup or HTTP fetch. Existing authentication audit events record
the API operation, not the submitted body.

## Protected identity inspection API

`GET /api/v1/proxy-hostnames/{label}` requires `resources:read`. It accepts API-key
or browser-session authentication; this read-only operation needs no CSRF header.
An unknown label returns 404 only after authentication and permission checks.
The operation never enrolls a host or performs DNS/HTTP requests. It works without
current deployment settings, so retained identities remain inspectable.

A successful response is `Cache-Control: no-store` and has this shape:

```json
{"hostname":"cdn.vendor.example","label":"cdn-vendor-example","resource_ids":["vendor"]}
```

`resource_ids` contains current domain-policy associations in resource-ID order.
It becomes an empty array when policy blocks the host or no active resources
remain associated. The stored identity still returns 200. These associations
are inspection metadata, not permission to route requests. There is no `allowed`
or production-readiness claim in this response.

Arbitrary aliases are not supported; use the fallback label for exceptional
hosts.
SQLite contention may return an error;
there is no retry policy in this foundation. Before a future rollback, stop Odo
and back up the database. The previous binary ignores the additional table;
retain it to preserve hostname identities if development resumes.
