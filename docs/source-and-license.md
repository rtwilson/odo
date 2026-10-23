# Source code and legal notices

`GET /about` is a public Odo-owned page displaying the software version, build
revision, corresponding-source link, and license notice. It needs no login and
sets no session cookies. It uses the normal application security headers and
contains no third-party scripts, fonts, analytics, or embedded remote content.
The full GNU AGPLv3 license is linked from the page and is included in the
repository as [LICENSE](../LICENSE).

The Odo login, resources, and admin pages include a discreet “Source & license”
footer link to this page. Following that local link needs no authentication and
does not contact the external source host. Proxied vendor pages receive no
Odo branding, legal notice, or footer link.

## Configure a source offer

For example, a library's deployment of a modified source snapshot could use:

```env
APP_BUILD_REVISION=site-20261023-01
APP_SOURCE_URL=https://source.example.edu/odo/site-20261023-01.tar.gz
APP_LICENSE_NOTICE=Odo is licensed under GNU AGPLv3. Includes local library modifications. Provided without warranty; retain the source distribution's legal notices.
```

These are public metadata, not secrets. The notice is plain text, never HTML.
The fixed AGPLv3 license link remains visible when the notice is customized.
Source URLs must be absolute HTTPS URLs without username/password credentials.
Odo never downloads or follows the configured URL, and it does not publish the
working directory, configuration, database, or any source files automatically.
An external source link is visited only when a user chooses it; the page's
no-referrer policy prevents sending the referring page to the destination.

Point the link at a publicly obtainable, no-charge source archive or a pinned
source revision containing the version actually running. For a modified
installation, publish the fork or snapshot containing those modifications,
including the required build/install material and legal notices. A generic
upstream homepage, moving branch, or an unmodified upstream archive does not
identify a locally modified deployment. `git archive HEAD` does not include
uncommitted modifications: create a reviewed source snapshot or commit those
changes before building. Exclude deployment secrets, databases, sessions, logs,
and patron/vendor data from published artifacts.

Publishing and maintaining the matching corresponding source is the operator's
responsibility. Odo validates the metadata's shape, not the source server's
availability or the contents of its archive. The page supports a source offer;
it does not by itself establish fulfillment of every license obligation. See
section 13 and the definition of Corresponding Source in [LICENSE](../LICENSE).

## Build metadata and modified deployments

Revision selection is:

1. Explicit `APP_BUILD_REVISION`.
2. The embedded `internal/api.Commit` value, when known.
3. Go's VCS revision metadata, when available.
4. `unknown` when no revision is available.

Go's `vcs.modified` metadata is shown when present. Without an explicit revision,
known dirty builds are labeled `<revision>+modified`; production requires an
explicit snapshot identifier for them. Supply the matching source URL and a
unique revision for every modified build. If VCS metadata was omitted during
packaging, Odo cannot detect local changes; provide both settings explicitly.

`APP_SOURCE_URL` overrides the build-time source URL, including for a fork or
site-specific rebuild. Setting it to an empty string explicitly removes that
build-time default in development. With neither value, development shows
"source code URL is not configured" rather than offering unrelated upstream
source. There is deliberately no automatic upstream/latest-source fallback.

Container build arguments can pair an image with its source snapshot:

```sh
podman build \
  --build-arg ODO_VERSION=site-20261023-01 \
  --build-arg ODO_COMMIT=site-20261023-01 \
  --build-arg ODO_SOURCE_URL=https://source.example.edu/odo/site-20261023-01.tar.gz \
  -t odo:site-20261023-01 .
```

For a source build, the existing `-ldflags -X` mechanism accepts
`example.org/odo/internal/api.Version`, `example.org/odo/internal/api.Commit`,
and `example.org/odo/internal/api.SourceURL`. Environment values take precedence
for the source link and displayed revision. Even with an embedded revision,
known dirty production builds require `APP_BUILD_REVISION` at runtime.

## Startup and security boundaries

Production startup refuses an absent source URL, an unknown/dev revision, or a
known dirty build without an explicit snapshot revision. Invalid source URL
syntax is rejected in development too. Existing production environments must
configure this metadata before upgrading.

`/about` and its subpaths are reserved Odo application routes and cannot be
recovered through a proxied Referer. Making this page public does not make
management APIs public or change role, scope, CSRF, or proxy-session checks.
All metadata is escaped when rendered, and the page ignores request query
parameters and authentication headers. It sends `Cache-Control: no-store` so
metadata from an earlier deployment is not reused.

Nothing is injected into vendor HTML, JavaScript, PDFs, or other proxied bodies.
A proxied vendor's own `/about` path remains a vendor request. Source offers do
not change proxy domain rules, redirect validation, or validated-IP dialing.
