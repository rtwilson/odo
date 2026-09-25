# Local login throttling

Odo applies an in-memory limiter to `POST /login` before user lookup and password verification. It does not change API-key authentication, proxy access, user status, or SAML routes.

## Policy

- Account keys use trimmed, lowercase usernames. This normalization is for throttling only; account lookup behavior is unchanged. Case variants share a bucket, including any distinct accounts whose names differ only by case.
- Source keys use the connection peer IP from `RemoteAddr`, without its port. IPv4-mapped IPv6 addresses are canonicalized. Invalid addresses share an `unknown` bucket.
- `X-Forwarded-For` and `Forwarded` do not affect source keys, even with `APP_TRUST_PROXY_HEADERS=true`: Odo has no existing trusted client-IP extraction policy.
- The first 5 credential failures per account or 20 per source in a fixed 10-minute window receive normal HTTP 401 failures. Reaching either threshold starts a cooldown of up to 60 seconds, ending sooner if the failure window expires.
- After cooldown, one attempt at a time is admitted for that bucket. Another credential failure starts another bounded cooldown. Rejected attempts neither add failures nor extend the cooldown or window.
- Successful session creation clears account failures, but does not clear source failures. Internal errors release attempt reservations without counting as credential failures.
- In-flight attempts reserve capacity before database/bcrypt work. Concurrent requests can therefore receive HTTP 429 while those reservations are occupied, even before failures are confirmed.
- Wrong passwords, nonexistent accounts, and disabled/locked accounts all use the same failure body: `{"error":"invalid username or password"}`. Throttled requests return that same body with HTTP 429 and no session cookies. This does not claim constant-time authentication; the existing password-check behavior is unchanged.

## Memory and audit events

The limiter stores at most 10,000 account/source entries combined, using fixed-size hashed keys and a mutex. Expired entries without in-flight attempts are pruned on incoming login attempts at most once per minute; a requested expired key is removed immediately. Entries with no failures or pending attempts are removed after completion. No cleanup goroutine is required, and memory remains capped when idle.

If capacity is exhausted, attempts requiring new keys receive the same generic HTTP 429. Active counters are not evicted, preventing key churn from bypassing lockouts. Expiry releases capacity; an ongoing attack can still affect login availability.

Audit events are:

- `login_failed`: one per admitted credential failure, with the login path only.
- `login_failures_excessive`: when an account or source first reaches its threshold.
- `login_throttled`: at most once per blocked key per minute, or once per minute for capacity exhaustion. Detail contains only the login path and `account`, `source`, or `capacity` as the reason.

These events contain no usernames, source IPs, passwords, cookies, user agents, or request bodies. Existing successful-login audit events remain unchanged. Operators must configure monitoring, alerting, and retention; recording events does not deliver alerts.

## Deployment limits

State is per Odo process and resets on restart. Pair it with reverse-proxy rate limiting before an Internet-facing pilot or any future production use. Apply edge limits using a trusted client-address policy, prevent direct public access to Odo, and avoid logging submitted credentials or request bodies.

Behind a reverse proxy, all clients connecting through the same proxy IP share Odo's source bucket. A noisy client can therefore affect other users; edge rate limiting is essential, and source attribution needs further design before high-volume deployment. Account throttling can also temporarily deny legitimate users during an active attack; it does not permanently lock user records.

If Odo later supports multi-node/HA deployments, use coordinated distributed throttling at the edge or a shared limiter. This implementation adds neither Redis nor distributed state and does not establish production readiness.
