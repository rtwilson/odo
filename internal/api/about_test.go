package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"runtime/debug"
	"strings"
	"testing"
)

func TestOwnedPagesLinkToPublicSourceNotice(t *testing.T) {
	t.Setenv("APP_SOURCE_URL", "https://source.example/odo/site-snapshot.tar.gz")
	t.Setenv("APP_LICENSE_NOTICE", "DEPLOYMENT_LEGAL_SENTINEL")
	server := newTestServer(t, "secret")
	createLocalTestUserWithRoles(t, server, "admin", "correct horse battery", []string{"super_admin"})
	cookie := loginTestUser(t, server, "admin", "correct horse battery", "/admin")
	handler := server.Routes()
	for _, path := range []string{"/login", "/resources", "/admin"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			if path != "/login" {
				req.AddCookie(cookie)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK || strings.Count(rec.Body.String(), `<a href="/about">Source &amp; license</a>`) != 1 {
				t.Fatalf("page missing its source notice link: status %d", rec.Code)
			}
			if strings.Contains(rec.Body.String(), "source.example") || strings.Contains(rec.Body.String(), "DEPLOYMENT_LEGAL_SENTINEL") {
				t.Fatal("footer should link to the local notice page")
			}
		})
	}
	for _, path := range []string{"/admin", "/resources"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), "/login?") {
			t.Fatalf("page authentication changed for %s: %d", path, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/about", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "DEPLOYMENT_LEGAL_SENTINEL") {
		t.Fatal("notice link destination must be public")
	}
}

func TestAboutIsPublicEscapedAndIndependentOfSession(t *testing.T) {
	t.Setenv("APP_SOURCE_URL", "https://source.example/odo/snapshot/site-revision.tar.gz?a=1&b=2")
	t.Setenv("APP_BUILD_REVISION", `site-revision <script>revision</script>`)
	t.Setenv("APP_LICENSE_NOTICE", `Library modifications <script>notice</script> & retained legal notices`)
	server := newTestServer(t, "secret")
	server.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Fatal("public notice must not fetch its configured source URL")
		return nil, nil
	})}
	for _, method := range []string{"GET", "HEAD"} {
		req := httptest.NewRequest(method, "/about?url=https://untrusted.example/private", nil)
		req.Header.Set("Cookie", "odo_session=invalid")
		req.Header.Set("Authorization", "Bearer invalid")
		req.Header.Set("Referer", "http://localhost/odo/https/www.jstor.org/private")
		rec := httptest.NewRecorder()
		server.Routes().ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("public about status = %d", rec.Code)
		}
		if rec.Header().Get("Content-Type") != "text/html; charset=utf-8" || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("unexpected headers: %v", rec.Header())
		}
		if rec.Header().Get("Set-Cookie") != "" {
			t.Fatal("public legal notice created a session")
		}
		if rec.Header().Get("X-Frame-Options") != "DENY" || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "script-src 'none'") || rec.Header().Get("Referrer-Policy") != "no-referrer" {
			t.Fatal("about page lacks application security headers")
		}
		if method == "HEAD" {
			if rec.Body.Len() != 0 {
				t.Fatal("HEAD returned a body")
			}
			continue
		}
		body := rec.Body.String()
		for _, want := range []string{`href="https://source.example/odo/snapshot/site-revision.tar.gz?a=1&amp;b=2"`, `site-revision &lt;script&gt;revision&lt;/script&gt;`, `Library modifications &lt;script&gt;notice&lt;/script&gt; &amp; retained legal notices`, `GNU Affero General Public License, version 3`} {
			if !strings.Contains(body, want) {
				t.Errorf("missing rendered notice %q", want)
			}
		}
		for _, forbidden := range []string{"<script>", "untrusted.example", "odo_session", "Bearer invalid"} {
			if strings.Contains(body, forbidden) {
				t.Errorf("unexpected request data or markup: %q", forbidden)
			}
		}
	}
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/users", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatal("public about route weakened API authentication")
	}
}

func TestAboutDefaultsDoNotAdvertiseUnconfiguredSource(t *testing.T) {
	t.Setenv("APP_SOURCE_URL", "")
	t.Setenv("APP_LICENSE_NOTICE", "")
	rec := httptest.NewRecorder()
	newTestServer(t, "secret").Routes().ServeHTTP(rec, httptest.NewRequest("GET", "/about", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "source code URL is not configured") || !strings.Contains(rec.Body.String(), defaultLicenseNotice) {
		t.Fatalf("missing honest development defaults: %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "Get the source code for this deployment</a>") {
		t.Fatal("unconfigured deployment advertised a source offer")
	}
}

func TestAboutSourceURLBuildDefaultAndDeploymentOverride(t *testing.T) {
	t.Setenv("APP_SOURCE_URL", "")
	if err := os.Unsetenv("APP_SOURCE_URL"); err != nil {
		t.Fatal(err)
	}
	previous := SourceURL
	SourceURL = "https://source.example/odo/archive/build-revision.tar.gz"
	t.Cleanup(func() { SourceURL = previous })
	notice, err := readAboutNotice()
	if err != nil || notice.SourceURL != SourceURL {
		t.Fatalf("build source URL lost: %#v %v", notice, err)
	}
	t.Setenv("APP_SOURCE_URL", "https://source.example/fork/archive/site-snapshot.tar.gz")
	notice, err = readAboutNotice()
	if err != nil || notice.SourceURL != os.Getenv("APP_SOURCE_URL") {
		t.Fatalf("modified deployment cannot override build source: %#v %v", notice, err)
	}
}

func TestAboutSourceURLValidation(t *testing.T) {
	for _, source := range []string{"javascript:alert(1)", "data:text/html,notice", "//source.example/code", "http://source.example/code", "https://user:private@source.example/code", "https://", "https://source.example/\nprivate"} {
		t.Run(source, func(t *testing.T) {
			t.Setenv("APP_SOURCE_URL", source)
			if err := ValidateAboutConfig("development"); err == nil {
				t.Fatal("unsafe source URL accepted")
			}
			rec := httptest.NewRecorder()
			newTestServer(t, "secret").Routes().ServeHTTP(rec, httptest.NewRequest("GET", "/about", nil))
			if rec.Code != 500 || strings.Contains(rec.Body.String(), "private@") {
				t.Fatalf("invalid configuration was rendered: %d", rec.Code)
			}
		})
	}
}

func TestProductionAboutConfigurationRequiresSourceAndRevision(t *testing.T) {
	t.Setenv("APP_SOURCE_URL", "")
	t.Setenv("APP_BUILD_REVISION", "unknown")
	err := ValidateAboutConfig("production")
	if err == nil || !strings.Contains(err.Error(), "APP_SOURCE_URL") || !strings.Contains(err.Error(), "APP_BUILD_REVISION") {
		t.Fatalf("missing source metadata did not fail closed: %v", err)
	}
	t.Setenv("APP_SOURCE_URL", "https://source.example/odo/archive/site-snapshot.tar.gz")
	t.Setenv("APP_BUILD_REVISION", "site-snapshot")
	if err := ValidateAboutConfig("production"); err != nil {
		t.Fatalf("modified deployment metadata rejected: %v", err)
	}
}

func TestBuildRevisionIdentifiesModifiedSource(t *testing.T) {
	settings := []debug.BuildSetting{{Key: "vcs.revision", Value: "base-commit"}, {Key: "vcs.modified", Value: "true"}}
	revision, modified := resolveBuildRevision("unknown", "", settings)
	if revision != "base-commit+modified" || !modified {
		t.Fatalf("dirty build mislabeled: %q %t", revision, modified)
	}
	revision, modified = resolveBuildRevision("base-commit", "site-snapshot", settings)
	if revision != "site-snapshot" || !modified {
		t.Fatalf("deployment revision override lost: %q %t", revision, modified)
	}
	revision, modified = resolveBuildRevision("release-commit", "", nil)
	if revision != "release-commit" || modified {
		t.Fatalf("embedded revision lost: %q %t", revision, modified)
	}
}

func TestAboutPathCannotRecoverVendorRequests(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("Odo legal route was proxied to vendor") }))
	defer upstream.Close()
	server := newProxyFetchTestServer(t, upstream.URL)
	req := httptest.NewRequest("GET", "/about/private.js", nil)
	req.Header.Set("Referer", "http://localhost/odo/https/www.jstor.org/")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != 404 || rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("legal path was not protected: %d", rec.Code)
	}
}
