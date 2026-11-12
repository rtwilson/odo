# Automatic experimental virtual-host handoff

This completes the partial direct-launch behavior at commit `c4cbb4b` on
`proxybyvhost`. That version confirmed on GET only for launches marked
same-origin; bookmarks and expired grants still required Continue. All normal
launches now use the same automatic, CSRF-protected POST. GET no longer mints
a ticket. This supersedes descriptions of mandatory manual confirmation or
same-origin-only GET confirmation in earlier design checkpoints.

## Navigation

1. Central `/launch` validates the resource and destination. If signed out, it
   stores the destination in the existing bounded login-continuation store,
   sends an opaque continuation to `/login`, and resumes after one login.
2. Central creates pending handoff state bound to the live parent session,
   central browser nonce, exact registered vendor host and target. Its vendor
   preflight redirect contains only the opaque handoff ID.
3. Vendor preflight checks for an existing valid host grant for the **same
   central parent session** and target. If present, it discards the unnecessary
   pending handoff and goes straight to the destination. Central never reads a
   vendor cookie. Otherwise preflight binds the vendor nonce and returns the
   existing single-use return proof to central.
4. Central GET validates the proof and browser bindings, then renders a small
   first-party page. One static, CSP-hashed script POSTs the existing form
   fields using same-origin fetch: handoff ID, return proof and session-derived
   CSRF. The server still validates Origin, CSRF, both browser bindings, live
   parent/resource authorization and expiry before atomically issuing a ticket.
5. With `Accept: application/json`, successful POST returns `{"next": ...}`
   naming the exact vendor ticket endpoint. It does not return the destination.
   The script replaces the current history entry with that URL. Other POST
   clients retain the existing 303 response. There is no Continue button.
6. Redemption consumes the ticket and sets the existing host-only grant. A new
   `?finish=<opaque>` control hop verifies the browser accepted that cookie.
   Its single-use continuation is bound to the exact grant token and stored as
   hashes in the existing bounded continuation store. Missing cookies stop here.
7. The existing same-resource sibling chain remains capped at six extra hosts;
   each sibling now verifies its own grant cookie too. The final redirect
   preserves the stored destination path and opaque query. Delivery rechecks
   live policy and session state and strips all browser credentials upstream.

A direct vendor GET with an expired/missing grant uses central
`/launch/handoff/start?token=<opaque>`. The upstream URL stays server-side;
legacy bookmark migration also uses this opaque start. The start token alone
never authorizes anything: it is consumed once, then repeats resource checks
and the full login/nonce/proof/CSRF protocol. Its empty-nonce continuation
cannot be substituted for a browser-bound login or grant-verification token.
The initial user-supplied `/launch?url=...` and final destination still contain
their ordinary URL/path/query; intermediate controls carry opaque tokens only.

## Browser controls and failure bounds

- Central pages retain no-store, no-referrer, frame denial, default-src 'none',
  base-uri 'none' and object-src 'none'. Confirmation allows only the exact
  static script hash and `connect-src 'self'`; there are no third-party assets.
- The script makes one attempt with a 15-second timeout and no automatic retry.
  A restored page does not POST again. `history.replaceState` removes the
  proof-bearing query before POST, and `location.replace` removes the page from
  the normal navigation history. Replayed or expired controls fail explicitly.
- A host-only HttpOnly Secure attempt cookie bounds failed returns to two per
  minute on that vendor host. The third returns 508; a successfully authorized
  delivery clears it. It is a loop counter, not an authorization credential.
  If all cookies are blocked, the login/nonce checks stop the flow. If only
  grants are blocked, the finish hop stops it before another resource request.
- POST failure, timeout, unavailable cookies, stale state and disabled JavaScript
  produce instructions to allow the required feature and launch again. No
  script, Origin or CSRF check is weakened to accommodate blocked features.
- Non-document requests still do not start an interactive handoff. Revoked or
  expired central sessions require a fresh login; valid central sessions do not.

## Validation and limits

`handoff_navigation_test.go` covers the JSON POST flow, signed-in and login-first
entry, consecutive launches, grant expiry, live-grant reuse, parent mismatch,
revocation, missing cookies, token-type substitution, opaque query preservation,
replay, loop bounds and CSRF/Origin spoofing. Existing tests retain independent
host grants, sibling hosts, ticket replay, account/resource revocation and
upstream cookie isolation coverage.

`handoff_chromium_test.go` is an optional real-browser regression with a private
profile, local trusted TLS fixtures, and a debugging pipe (no listening debug
port or new package). Run:

```sh
ODO_TEST_CHROMIUM=/usr/bin/chromium-browser go test ./internal/api -run TestChromiumAutomaticHandoff -count=1
```

The test submits only login credentials. Production page JavaScript must finish
handoff, repeat launches without another POST, recover from grant expiry, and
support back/forward. It also checks the query received by the fake vendor.
The normal Go suite skips this test when the browser environment variable is
unset; it does not pretend the HTTP client executes JavaScript.

Automatic continuation requires JavaScript and first-party cookies. The existing
in-memory lifetime/capacity limits and development/test-only startup restriction
remain. Resource/hostname enrollment is still explicit: this does not repair
an unregistered hostname or grant access to an unlicensed resource. Firefox,
real vendor compatibility and production deployment are not certified by the
Chromium fixture. Existing sibling tickets remain as defined in the earlier
same-resource implementation; this task does not redesign their bindings.
