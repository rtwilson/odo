# Internal errors and request IDs

Every request handled by Odo receives an `X-Request-ID` response header. Odo reuses a single inbound `X-Request-ID` (or legacy `Request-ID`) only when it is 1–64 ASCII letters, digits, underscores, or hyphens. Repeated, empty, oversized, or invalid header values are not accepted. Otherwise Odo generates `req_` followed by 128 random bits in hexadecimal; if randomness is unavailable, a timestamp and process-local counter provide a fallback. IDs are correlation labels, not credentials or proof of caller identity.

Odo-generated internal failures return a stable JSON response, with the appropriate HTTP 500 or 502 status:

```json
{
  "error": "internal_error",
  "message": "An internal error occurred.",
  "request_id": "req_..."
}
```

Internal failures on `/login`, `/admin`, and `/resources` use a generic HTML page containing the same request ID. Credential failures, login throttling, and known-safe 4xx validation responses retain their existing useful messages. User conflicts return `user already exists` rather than a database constraint error. SAML's intentional HTTP 501 placeholders remain explicit about the unimplemented functionality.

Application error logs retain the internal cause with `request_id`, `method`, `route`, and `status`. Routes use registered patterns or a fixed fallback, not request URLs. URL error wrappers omit their target URL while preserving the underlying cause; the helper does not log request headers or bodies. Default privacy access logs use the same request ID. Give operators the ID when reporting a failure; restrict access to server logs because internal causes can contain filesystem paths, database details, or network addresses.

Database failures during authentication/session lookup now return sanitized HTTP 500 errors instead of being treated as invalid credentials or login redirects. Config import/validation filesystem and database failures likewise return sanitized HTTP 500 responses instead of embedding internal details in HTTP 200 results. Import remains nontransactional: some resources may already have been imported when an error is returned. Malformed resource JSON receives a stable validation message; field-level validation remains useful.

This policy covers Odo-generated errors, including its proxy transport/redirect errors. Vendor-origin response bodies/statuses still pass through the proxy, and a failure after streaming has started cannot replace the response already sent. Existing audit logging and optional combined/JSON access-log fields have separate privacy/retention concerns tracked in ODO-2025-009. This change does not add panic recovery or resolve other outstanding pilot-hardening items.
