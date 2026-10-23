package api

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"os"
	"runtime/debug"
	"strings"
)

// SourceURL can be set alongside Commit with -ldflags. Never default to an
// upstream branch: a fork or modified deployment must offer its own source.
var SourceURL string

const defaultLicenseNotice = "Odo is free software under the GNU Affero General Public License, version 3. It is distributed without any warranty; see the license for its terms."

type aboutNotice struct {
	SourceURL     string
	LicenseNotice string
	Revision      string
	Modified      bool
}

func resolveBuildRevision(embedded, configured string, settings []debug.BuildSetting) (string, bool) {
	revision := strings.TrimSpace(embedded)
	modified := false
	for _, setting := range settings {
		if setting.Key == "vcs.revision" && (revision == "" || revision == "unknown") {
			revision = setting.Value
		}
		if setting.Key == "vcs.modified" && setting.Value == "true" {
			modified = true
		}
	}
	if configured = strings.TrimSpace(configured); configured != "" {
		return configured, modified
	}
	if revision == "" {
		revision = "unknown"
	}
	if modified {
		revision += "+modified"
	}
	return revision, modified
}

func readAboutNotice() (aboutNotice, error) {
	var settings []debug.BuildSetting
	if info, ok := debug.ReadBuildInfo(); ok {
		settings = info.Settings
	}
	revision, modified := resolveBuildRevision(Commit, os.Getenv("APP_BUILD_REVISION"), settings)
	source, configured := os.LookupEnv("APP_SOURCE_URL")
	if !configured {
		source = SourceURL
	}
	notice := aboutNotice{SourceURL: strings.TrimSpace(source), LicenseNotice: strings.TrimSpace(os.Getenv("APP_LICENSE_NOTICE")), Revision: revision, Modified: modified}
	if notice.LicenseNotice == "" {
		notice.LicenseNotice = defaultLicenseNotice
	}
	if notice.SourceURL != "" {
		parsed, err := url.Parse(notice.SourceURL)
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Opaque != "" {
			return aboutNotice{}, fmt.Errorf("APP_SOURCE_URL must be an absolute HTTPS URL without user credentials")
		}
	}
	return notice, nil
}

// ValidateAboutConfig checks public notice metadata without fetching the source
// URL. Operators remain responsible for publishing the matching source itself.
func ValidateAboutConfig(appEnv string) error {
	notice, err := readAboutNotice()
	if err != nil {
		return err
	}
	if appEnv != "production" {
		return nil
	}
	var problems []string
	if notice.SourceURL == "" {
		problems = append(problems, "APP_SOURCE_URL or build-time SourceURL is required in production")
	}
	revision := strings.TrimSuffix(strings.ToLower(notice.Revision), "+modified")
	if revision == "unknown" || revision == "dev" {
		problems = append(problems, "APP_BUILD_REVISION or a known build revision is required in production")
	}
	if notice.Modified && strings.TrimSpace(os.Getenv("APP_BUILD_REVISION")) == "" {
		problems = append(problems, "APP_BUILD_REVISION must identify the modified source snapshot")
	}
	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	return nil
}

func (s *Server) about(w http.ResponseWriter, r *http.Request) {
	notice, err := readAboutNotice()
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = fmt.Fprintf(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><link rel="icon" href="/favicon.ico"><title>About Odo — source and license</title><style>:root{color-scheme:dark;font-family:system-ui;background:#101316;color:#f2f4f7}main{max-width:760px;margin:0 auto;padding:28px}a{color:#8cc7ff}dd{margin:4px 0 16px;overflow-wrap:anywhere}.notice{white-space:pre-wrap}nav{margin-top:32px}</style></head><body><main><h1>About Odo</h1><p>Odo is library access middleware.</p><dl><dt>Version</dt><dd>%s</dd><dt>Build revision</dt><dd>%s</dd></dl><h2 id="source-code">Source code for this deployment</h2>`, html.EscapeString(Version), html.EscapeString(notice.Revision))
	if notice.Modified {
		_, _ = fmt.Fprint(w, `<p>This build includes working-tree modifications.</p>`)
	}
	if notice.SourceURL != "" {
		_, _ = fmt.Fprintf(w, `<p><a href="%s" rel="noreferrer noopener">Get the source code for this deployment</a></p>`, html.EscapeString(notice.SourceURL))
	} else {
		_, _ = fmt.Fprint(w, `<p>The source code URL is not configured for this deployment.</p>`)
	}
	_, _ = fmt.Fprintf(w, `<h2 id="license">License and legal notice</h2><p><a href="https://www.gnu.org/licenses/agpl-3.0.html" rel="noreferrer noopener">GNU Affero General Public License, version 3</a></p><p class="notice">%s</p><nav aria-label="Odo pages"><a href="/login">Sign in</a> · <a href="/resources">Resources</a></nav></main></body></html>`, html.EscapeString(notice.LicenseNotice))
}
