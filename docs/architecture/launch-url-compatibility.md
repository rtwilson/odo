# Launch URL parsing contract

This batch implements `proxy.ParseLaunchQuery` only. There is no `/launch`
handler or login continuation yet. Existing `/odo` and `/login` behavior is
unchanged, and virtual-host routing remains disabled.

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
authorization grant or an SSRF safety decision: the future launch handler must
apply DNS safety and current resource policy, method and session checks. Any
later upstream fetch must retain validated-IP dialing. Login continuation,
destination revalidation, privacy-safe logging, and the HTTP endpoint are pending.
