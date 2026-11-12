# Launch URL parsing contract

`GET /launch`, `proxy.ParseLaunchQuery`, and a browser-bound local login
continuation are implemented. Virtual-host routing remains disabled.

The existing path/query URL strategy now preserves vendor query parameters named
`url`: only `/odo`, `/odo/`, and legacy `/p` treat that parameter as the proxy
envelope. In `/odo/https/{host}/...`, it remains vendor data. URL generation and
path parsing also preserve an empty trailing target `?`. These are prerequisites
for routing parsed launch targets without changing their query data.

## Canonical encoded form

Encode the entire absolute HTTPS target once as the value of `url`:

```text
/launch?url=https%3A%2F%2Fvendor.example%2Fsearch%3Fa%3D1%26b%3D2
```

The parser accepts the request's `RawQuery`, starting exactly with `url=`.
When the remainder does not begin literally with `https://`, it parses the
outer query strictly, requiring one `url` value and no other keys. Duplicate
parameters, empty outer segments, malformed escapes, raw outer semicolons, and
double-encoded target URLs are rejected. The outer value is decoded once.

## Raw-prefix compatibility form

If the bytes after `url=` begin literally with `https://`, the complete remainder
is the target. No outer query decoding occurs:

```text
/launch?url=https://vendor.example/search?a=1&b=2
```

Both `a` and `b` belong to the vendor query. A later `&url=` also belongs to
the vendor data; it is not a second launch parameter. This branch is selected
once before decoding. It cannot support separate launch envelope parameters.
Callers and intermediaries must preserve the raw input; encoded form is preferred.

## Preserved data and limits

| Target data | Behavior |
| --- | --- |
| Escaped path, including `%2F` and escape case | Preserved through `EscapedPath` |
| Vendor `&`, `=`, `?`, nested URLs | Retained in `RawQuery` |
| Vendor `+`, `%2B`, `%20`, `%25`, `%252F` | Preserved without decoding the vendor query |
| Vendor query semicolons | Preserved; encode them in the outer encoded envelope |
| Unicode path | Encoded by Go's URL serialization; existing escaped path data is preserved |
| Unicode vendor query | Retained in `RawQuery` |
| Empty trailing target `?` | Preserved through `ForceQuery` |
| Literal target fragment, including trailing `#` | Rejected |

The complete raw query, including `url=`, is limited to 16 KiB. This is a byte
limit before outer decoding; encoded and raw forms can therefore carry different
maximum target lengths. Unescaped ASCII spaces and control characters are
rejected. Spaces in target data must use `%20` or an appropriate vendor query
encoding. Malformed escapes are rejected in both the target path and query;
query validation never replaces or re-encodes the vendor data.

A literal browser `#` is not sent to the server. The parser can reject a fragment
carried inside an encoded target, but cannot recover a browser fragment omitted
from the request. Use canonical encoding; fragment destinations remain unsupported.

The existing target syntax checks reject credentials, IP literals, local names,
and non-default ports. HTTPS is required even when development local HTTP is
enabled. All parse failures return a generic error without target data.

Parsing performs no DNS lookup or HTTP fetch. A successful parse is not an
authorization grant or an SSRF safety decision.

## Launch endpoint

`GET /launch` applies existing DNS safety and resource-policy checks, including
the target's GET permission. It requires the same browser session as proxy
traffic unless proxy login is disabled or an explicit anonymous exception
applies. Bearer management keys do not substitute for a patron browser session.
The default login requirement continues to depend on whether users exist.

On success it returns 302 to the URL produced by the existing URL strategy:
path output by default and in dual mode, query output when configured. No
upstream HTTP request occurs. Launch creates no vendor session cookie, cookie
jar, or registry mapping. The subsequent proxy request independently rechecks
policy and retains validated-IP dialing.

Responses have `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.
Odo's privacy access log records the local route without target path or query
data. Reverse-proxy logs must also omit launch queries. `/launch` and its
subpaths are reserved against vendor Referer recovery.

Malformed envelopes return 400. Unsafe or disallowed targets return a generic
403 without resource details. For browser document navigation, a missing login
starts the continuation below. Non-document requests (for example, requests
accepting JSON) still return 401 JSON with
`{"error":"login_required","login_url":"/login"}` without allocating state.
Operational failures return the standard generic 500 response. Only GET is
supported.

## Browser login continuation

After target validation, an unsigned browser receives a 302 to
`/login?next=<encoded-local-continuation>`. The local return path is
`/launch/continue?token=<opaque-random-token>`; it contains no vendor URL.
`safeNextPath` accepts only this exact endpoint and a canonical 32-byte random
token, not arbitrary `/launch` destinations or external URLs. The existing login
flow returns to that local path after authentication. SAML login remains
unimplemented; this does not add SAML or cross-host authentication.

The destination lives in a mutex-protected in-memory store with a five-minute
logical lifetime and a global maximum of 1,024 pending launches. New entries
sweep expired records; an expired redemption also removes its record. Idle
expired records may remain in bounded process memory until the next operation.
Nothing is stored in SQLite. Restarting Odo discards pending launches, and
multiple instances do not share them. Anonymous visitors create these
records, so a full store evicts its oldest launch rather than refusing new
ones (a refusal would let anyone deny launch-then-login to every patron). An
evicted patron still signs in normally and lands on the resource list; reopen
the original launch URL to continue.

Each continuation is bound to a random browser nonce cookie: host-only,
HttpOnly, Path=/, SameSite=Lax, and Secure when required by existing cookie
policy. HTTPS uses `__Host-odo_launch_nonce`; local HTTP development uses
`odo_launch_nonce`. Reusing the nonce permits multiple pending tabs. Tokens and
nonces are stored only as hashes alongside the pending destination.

`GET /launch/continue` requires a current browser session and the matching nonce
before atomically consuming the token. Missing, expired, replayed, malformed,
or browser-mismatched continuations fail with generic 404; an unsigned browser
with a well-formed token and nonce receives 401 without consuming it. After
consumption, DNS safety, resource policy, GET permission and proxy access are
checked again. A new denial consumes the continuation and returns 403. No
vendor HTTP request is made. Responses are no-store/no-referrer; tokens and
targets must also be scrubbed from reverse-proxy logs. Only GET is supported.

This continuation supports the existing path/query deployment. It is not a
virtual-host grant or handoff ticket. Host admission, central-origin isolation,
cross-host tickets, and grant revocation remain separate release gates.
