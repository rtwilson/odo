# Browser compatibility review — 2026-11-11

Reviewed branch `proxybyvhost` at
`c58d3c4521146810ace4c5fc520d1e3f7f894071`. The starting worktree was clean.
There are no November 11 commits at this HEAD. The recent browser work is
from November 10 (dates below are America/New_York).

## Recent changes

| Commit | Date | Purpose |
| --- | --- | --- |
| c58d3c4 | Nov 10 | Browser form Origin handling and exact vendor-origin CSP allowances for login continuation and confirmation. |
| 45e7ae6 | Nov 10 | Multi-page HTTPS vendor fixture, bounded same-host HTML attribute rewriting, asset/navigation/PDF coverage. |
| 9df0f09 | Nov 10 | Post-commit resource/session hooks retire in-memory jars and grants. |
| b7bb81b | Nov 10 | Failed-response handling and resource/database/handoff concurrency hardening. |
| 8731c5e | Nov 10 | Experimental GET/HEAD delivery, safe upstream transport, re-handoff and grant renewal. |
| 343ca11 | Nov 10 | Clear server-only request fields, refresh authorized parent-session activity, retain jars across grant expiry/re-handoff. |
| 0d551e6 | Nov 10 | Live grant/resource-snapshot cookie coordinator and its authorization/isolation tests. |
| 828c18b | Nov 10 | Serialize resource snapshot use against resource writes. |
| c43de7e | Nov 7 | Retire cookie generations across resource revisions. |
| 169caf0 | Nov 7 | Transactional resource revisions and consistent snapshots. |

## Compatibility matrix

“Tested” means the bounded cases in the repository pass, not universal vendor
compatibility. Go HTTP clients do not enforce browser CSP or execute scripts.
The Chromium 156 run recorded in [virtual-host-routing.md](virtual-host-routing.md#browser-compatibility)
is historical evidence; this review did not rerun Chromium.

| Feature | Status | Evidence and limits |
| --- | --- | --- |
| Multi-page fake HTTPS vendor | Implemented and tested | `handoff_browser_compat_test.go`; locally issued vendor certificate, real safe upstream client, validated public test IP mapped to loopback only by the test dialer. |
| Root-relative assets | Implemented and tested | CSS, JS and image bodies fetched through the proxy; historical Chromium run records styling, script execution and decoded image. |
| Relative assets | Implemented but incompletely tested | Native relative URL resolution works; explicit automated coverage is strongest for relative/parent-relative navigation and root-relative assets. Add nested-page relative asset URLs. No CSS URL rewriting. |
| Same-host absolute hyperlinks | Implemented and tested | HTTPS, HTTP, scheme-relative and absolute base URLs; attribute-only rewriting, exact host/default port. Compressed and over-2-MiB HTML remain unchanged. |
| Same-host redirects | Implemented and tested | Relative and HTTPS same-host Locations, query preservation, rejected cross-host/downgrade/userinfo/reserved targets. Redirect fragments are deliberately dropped; HTML-link fragments are preserved. |
| Query and escaped paths | Implemented and tested | Opaque queries, escaped slash/space and UTF-8 cases; redirects and rewritten attributes preserve supported target bytes. |
| Vendor cookie round-trips | Implemented and tested | Server-side jar round-trip and session/resource isolation, re-handoff survival, live revocation and policy retirement. Browser cookies never become upstream credentials. JavaScript cookie interoperability is unsupported. |
| PDF Range/206 | Implemented and tested | Full bytes, prefix/open-ended/suffix ranges, matching If-Range and HEAD. Historical Chromium PDF viewer success is documented; automated tests do not exercise a viewer, multipart ranges or every conditional response. |
| External assets through Odo | Not implemented | External image URL is explicitly asserted unchanged. No registered second HTTPS vendor is fetched in this fixture. Historical browser run records the external CDN image failing to load through Odo. Direct third-party loads may work independently but bypass Odo. |
| Complete browser login → vendor navigation | Implemented but incompletely tested automatically | Historical Chromium run completed logged-out entry, login, confirmation and vendor navigation. Go tests cover login continuation, CSP headers, handoff and content in separate flows; no checked-in browser runner continuously verifies the complete flow. |

Known failing tests: none in the baseline full suite. Unsupported external
delivery is a confirmed compatibility limitation, not a currently red test.

## Priority and required change

The highest-priority confirmed remaining compatibility failure is external
asset delivery through Odo. The fixture's
`https://cdn.external.example/pixel.png` remains external even when its parent
page is proxied. Sites needing an authenticated or IP-authorized CDN can lose
images, styles or scripts; any successful direct load exposes the browser's
network identity to that third party.

This is not a safe one-line rewrite. A second hostname needs an explicit
registry mapping, its own host-bound grant and current resource/method
authorization. A first-host grant cannot authorize it. A cold subresource
currently receives 401 rather than an interactive login redirect. URL rewriting,
grant acquisition and the choice of permitted third-party origins need a
separately scoped design. Do not assume “same resource” means “same grant.”

No runtime fix was made in this review. In particular, cross-host grants,
rewriting, POST and production enablement were not added.

## Next smallest implementation prompt

> On branch `proxybyvhost`, add a focused two-host HTTPS compatibility fixture
> using the existing delivery harness. Do not change production behavior.
>
> Serve a vendor page containing one image on a distinct fake CDN hostname.
> Register each hostname explicitly using the existing resource model; read
> the structs and validator before constructing the fixture. Use local trusted
> certificates and the existing validated-IP test dialer, with no external
> network dependency or upstream TLS bypass.
>
> Assert that the current HTML response leaves the external image URL unchanged.
> Separately request that image's registered proxy authority as a subresource:
> no grant must return 401 without a redirect or upstream hit; a copied
> first-host grant must fail; after an explicit independent central handoff for
> the CDN host, its own grant must deliver the exact image bytes. Verify that
> central/browser credentials never reach either upstream, and that disabling
> the CDN policy or revoking the parent denies subsequent image requests.
> Use existing cookie-policy semantics; do not silently introduce cross-resource
> cookie sharing or a new resource field.
>
> Document the observed boundary and the remaining decision about obtaining
> grants for cold subresource hosts. Do not add automatic grants, cross-host
> HTML/JS/CSS rewriting, cross-host redirects, POST, dependencies, or production
> enablement. Run go test ./..., go test -race ./..., go vet ./..., and go mod
> verify. Stop for review after this fixture milestone.

This prompt establishes a reproducible second-host boundary before a separate
implementation changes patron authorization or external URL handling. A
repeatable real-browser login/navigation check is also needed before claiming
browser regression coverage; it should be its own small task.

## Security and documentation limits

- Existing tests cover exact-host grants, central-route isolation, live resource
  and session checks before delivery, cookie isolation, DNS rebinding/private-IP
  rejection, TLS failure, and production rejection. This review found no new
  confirmed bypass of those boundaries; passing tests are not a security audit.
- Direct external URLs, inline JavaScript/CSS URLs, compressed/large HTML and
  JavaScript-managed cookies remain compatibility/privacy limits. Vendor CSP
  and CORS headers are not forwarded; vendor content has no central-app CSP.
- Grant theft remains useful until parent expiry/revocation if the attacker
  keeps the grant active. Short-lived proofs/tickets can remain in browser
  history. Edge logging and deployment isolation still require review.
- In-memory grants/jars are not a multi-instance or persistent-state solution.
  Revocation after the final authorization check cannot retract bytes already
  streamed to a client.
- Some older architecture paragraphs and source comments still say content
  delivery is unavailable or bodies are never rewritten. The experimental
  delivery and browser compatibility sections describe the current behavior;
  do not interpret the older text as the present implementation.

## Validation

Baseline `GOCACHE=/tmp/odo-go-cache go test ./...` passed before any edits.
`GOCACHE=/tmp/odo-go-cache go vet ./...` passed; `go mod verify` reported
`all modules verified`. `GOCACHE=/tmp/odo-go-cache go test -race ./...`
passed with no race reports (API package: 260.639 seconds).
`git diff --check` passed. No requested verification command was omitted.
Only this review document was added; no Go behavior changed.
