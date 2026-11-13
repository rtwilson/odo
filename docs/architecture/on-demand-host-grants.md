# On-demand same-resource host grants (proposal)

Status: **Proposed, not implemented.** Experimental virtual-host mode only.

## Problem

After a ticket is redeemed, the browser is walked through every other
registered host of the resource ([same-resource host
family](virtual-host-routing.md#same-resource-hosts-post-and-direct-launch)).
Each host costs two redirects: the `?sibling=` hop that sets the grant, then the
`?finish=` hop that verifies the browser stored it. Each redirect goes to a new
origin, so it also needs a new TLS connection. Measured locally (2026-11-12),
JSTOR used 15 redirects (7 sibling hosts) before the first page byte. The walk
also has these limits:

- At most six family hosts get grants. `uk.jstor.org` and newsbank's
  `stats`/`www` hosts never get one.
- A host registered after a handoff gets no grant until the next full
  handoff.
- Every hop is a point of failure. Unresolvable hosts are now skipped
  (73710cd), but still cost a live check.

## Constraints that shape the design

- **Subresources cannot be redirected through central.** An `<img>`, script
  or `fetch` aimed at a host without a grant gets 401. So any host a page
  loads assets from must already hold a grant when the page renders. This is
  why the walk happens upfront.
- Grants stay host-only `__Host-` cookies, bound to one parent session,
  resource and registered host. Nothing is shared across hosts.
- No new confirmation UI. The patron already approved this resource in this
  session.
- No automatic enrollment, and no change to resource policy semantics.

## Proposal

### Step 1: one redirect per sibling (small, independent)

Drop the `?finish=` verification on sibling hops. Verification exists so the
redeeming host can tell "the browser refused the cookie" apart from "the
grant expired" before it sends a navigation onward, which avoids restart
loops. A sibling hop needs no such protection: if a browser refuses a sibling
cookie, only that host's assets fail (401), and the existing attempt-cookie
guard still prevents loops when the patron navigates there. This halves the
walk: JSTOR goes from 15 redirects to 8. It also frees one launch
continuation per sibling.

### Step 2: navigation-only hosts on demand

Split the family by the existing domain rule `role`:

- `asset`, `api`, `auth` and `cookie` roles, plus hosts whose rule is
  `content` but which the page loads assets from, stay in the upfront walk.
  There is no reliable way to know this last group in advance, so `content`
  hosts stay upfront unless an administrator marks them navigation-only (see
  the open questions).
- Navigation-only hosts get a grant the first time the patron navigates there
  (a document request without a grant). Instead of today's full restart
  (central launch, then the confirmation page, then the ticket), the host
  sends the browser to a new central endpoint, `/launch/handoff/extend`,
  carrying the existing opaque continuation. Central checks:
  1. the central session cookie;
  2. a live grant family in that same parent session for the target's
     resource, issued within the parent's lifetime;
  3. live resource policy, GET permission and DNS safety for the target host.

  It then issues a single sibling hop for that host. The cost is two
  redirects, only for hosts the patron actually visits, with no confirmation
  page. With no live family, the current full handoff applies unchanged.

Step 2 lifts the six-host cap for navigation-only hosts, and hosts registered
mid-session work on first visit.

## Security analysis

- **Step 1:** grant issuance is unchanged; only the post-issue check moves.
  Each sibling hop is still single-use, host-bound, parent-bound and checked
  live.
- **Step 2:** `extend` mints a grant only for a resource the same parent
  session already holds a live grant for, so it cannot widen access beyond
  what the patron already approved. It is CSRF-relevant: a cross-site page
  could navigate a signed-in patron to `extend`. The result is a grant for an
  already-approved resource's host, the same thing today's walk issues
  unprompted, so the exposure does not grow. The endpoint must still be
  GET-only, carry no target in the URL (continuation only), require `Sec-Fetch-Dest:
  document`, and be rate-bounded like launch continuations.
- Logs keep fixed routes and reason codes only.

## Open questions for review

1. Should administrators be able to mark a `content` host navigation-only
   (for example a new `role: "navigation"`), or should Odo infer it? Inference
   from observed asset requests would create per-patron browsing data, so I
   would avoid it.
2. Should step 2 keep the six-host cap for the upfront asset walk? I recommend
   keeping it.
3. Ship step 1 alone first? It is low-risk and gives most of the visible
   speed-up for sites like JSTOR whose extra hosts are mostly asset hosts.

## Tests to add when implemented

- **Step 1:** a sibling chain has one redirect per host. A browser that refuses
  a sibling cookie gets 401 on that host's assets and no loop on navigation.
- **Step 2:**
  - `extend` succeeds only with a live same-parent family for the resource;
  - it fails closed for another resource, for revoked or expired parents,
    after a policy change, and for unsafe DNS;
  - it is document-only and replay-safe;
  - its logs carry no targets.
