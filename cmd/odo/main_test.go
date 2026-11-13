package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"example.org/odo/internal/auth/local"
	"example.org/odo/internal/db"
)

func TestBootstrapAdminUserCreatesInitialAdmin(t *testing.T) {
	t.Setenv("APP_BOOTSTRAP_ADMIN_USERNAME", "admin")
	t.Setenv("APP_BOOTSTRAP_ADMIN_PASSWORD", "correct horse battery")
	t.Setenv("APP_BOOTSTRAP_ADMIN_EMAIL", "admin@example.edu")

	store, err := db.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	if err := store.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := bootstrapAdminUser(store, logger); err != nil {
		t.Fatalf("bootstrap admin: %v", err)
	}
	user, found, err := store.GetUserByUsername("admin")
	if err != nil || !found {
		t.Fatalf("expected bootstrap user, found=%v err=%v", found, err)
	}
	if user.Email != "admin@example.edu" || user.Status != "active" || len(user.Roles) != 1 || user.Roles[0] != "admin" {
		t.Fatalf("unexpected bootstrap user: %#v", user)
	}
	if user.PasswordHash == "" || user.PasswordHash == "correct horse battery" || !local.CheckPassword(user.PasswordHash, "correct horse battery") {
		t.Fatalf("expected hashed bootstrap password, got %q", user.PasswordHash)
	}

	if err := bootstrapAdminUser(store, logger); err != nil {
		t.Fatalf("second bootstrap should be no-op: %v", err)
	}
	count, err := store.CountUsers()
	if err != nil {
		t.Fatalf("count users: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected bootstrap to create one user, got %d", count)
	}
}

func TestProductionWarningsFlagMissingCriticalSettings(t *testing.T) {
	t.Setenv("APP_PUBLIC_URL", "")
	t.Setenv("APP_KEY_HASH_SECRET", "")
	t.Setenv("APP_PROXY_REQUIRE_LOGIN", "false")

	warnings := productionWarnings("production", filepath.Join(os.TempDir(), "odo"), filepath.Join(os.TempDir(), "odo", "odo.db"), "devsecret")
	text := strings.Join(warnings, "\n")
	for _, want := range []string{"APP_PUBLIC_URL", "APP_KEY_HASH_SECRET", "APP_ADMIN_API_KEY", "APP_PROXY_REQUIRE_LOGIN", "temporary"} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected production warnings to contain %q, got %v", want, warnings)
		}
	}
}

func TestProductionConfigurationFailsClosed(t *testing.T) {
	validEnv := func(t *testing.T) {
		t.Helper()
		t.Setenv("APP_SOURCE_URL", "https://code.example.edu/odo/archive/test-revision.tar.gz")
		t.Setenv("APP_BUILD_REVISION", "test-revision")
		t.Setenv("APP_PUBLIC_URL", "https://access.example.edu")
		t.Setenv("APP_KEY_HASH_SECRET", "a-real-key-hash-secret")
		t.Setenv("APP_LOG_PSEUDONYM_SECRET", "a-real-log-pseudonym-secret-0123456789")
		t.Setenv("APP_PROXY_REQUIRE_LOGIN", "true")
		t.Setenv("APP_TRUST_PROXY_HEADERS", "false")
		t.Setenv("APP_PROXY_URL_MODE", "path")
	}
	tests := []struct {
		name        string
		mutate      func(*testing.T)
		adminKey    string
		storedAdmin bool
		want        string
	}{
		{name: "missing source URL", mutate: func(t *testing.T) { t.Setenv("APP_SOURCE_URL", "") }, adminKey: "real-admin-key", want: "APP_SOURCE_URL"},
		{name: "unknown build revision", mutate: func(t *testing.T) { t.Setenv("APP_BUILD_REVISION", "unknown") }, adminKey: "real-admin-key", want: "APP_BUILD_REVISION"},
		{name: "missing public URL", mutate: func(t *testing.T) { t.Setenv("APP_PUBLIC_URL", "") }, adminKey: "real-admin-key", want: "APP_PUBLIC_URL"},
		{name: "HTTP public URL", mutate: func(t *testing.T) { t.Setenv("APP_PUBLIC_URL", "http://access.example.edu") }, adminKey: "real-admin-key", want: "APP_PUBLIC_URL"},
		{name: "missing hash secret", mutate: func(t *testing.T) { t.Setenv("APP_KEY_HASH_SECRET", "") }, adminKey: "real-admin-key", want: "APP_KEY_HASH_SECRET"},
		{name: "missing pseudonym secret", mutate: func(t *testing.T) { t.Setenv("APP_LOG_PSEUDONYM_SECRET", "") }, adminKey: "real-admin-key", want: "APP_LOG_PSEUDONYM_SECRET"},
		{name: "short pseudonym secret", mutate: func(t *testing.T) { t.Setenv("APP_LOG_PSEUDONYM_SECRET", "too-short") }, adminKey: "real-admin-key", want: "APP_LOG_PSEUDONYM_SECRET"},
		{name: "placeholder hash secret", mutate: func(t *testing.T) { t.Setenv("APP_KEY_HASH_SECRET", "change-me") }, adminKey: "real-admin-key", want: "APP_KEY_HASH_SECRET"},
		{name: "missing admin key", mutate: func(t *testing.T) {}, want: "APP_ADMIN_API_KEY"},
		{name: "placeholder admin key", mutate: func(t *testing.T) {}, adminKey: "change-me", want: "APP_ADMIN_API_KEY"},
		{name: "proxy login disabled", mutate: func(t *testing.T) { t.Setenv("APP_PROXY_REQUIRE_LOGIN", "false") }, adminKey: "real-admin-key", want: "APP_PROXY_REQUIRE_LOGIN"},
		// Virtual-host mode is allowed in production, but never half-configured.
		{name: "virtual host without host guard", mutate: func(t *testing.T) { t.Setenv("APP_PROXY_URL_MODE", "virtual_host") }, adminKey: "real-admin-key", want: "APP_HOST_GUARD"},
		{name: "virtual host case and spaces", mutate: func(t *testing.T) { t.Setenv("APP_PROXY_URL_MODE", " Virtual_Host ") }, adminKey: "real-admin-key", want: "APP_HOST_GUARD"},
		{name: "temporary database", mutate: func(t *testing.T) {}, adminKey: "real-admin-key", want: "APP_DB_PATH"},
		{name: "trusted headers without HTTPS public URL", mutate: func(t *testing.T) { t.Setenv("APP_PUBLIC_URL", ""); t.Setenv("APP_TRUST_PROXY_HEADERS", "true") }, adminKey: "real-admin-key", want: "APP_TRUST_PROXY_HEADERS"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validEnv(t)
			tt.mutate(t)
			dbPath := "/var/lib/odo/odo.db"
			if tt.name == "temporary database" {
				dbPath = filepath.Join(os.TempDir(), "odo.db")
			}
			err := validateProductionConfig("production", dbPath, tt.adminKey, tt.storedAdmin)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestProductionConfigurationAcceptsStoredAdminKey(t *testing.T) {
	t.Setenv("APP_SOURCE_URL", "https://code.example.edu/odo/archive/test-revision.tar.gz")
	t.Setenv("APP_BUILD_REVISION", "test-revision")
	t.Setenv("APP_PUBLIC_URL", "https://access.example.edu")
	t.Setenv("APP_KEY_HASH_SECRET", "a-real-key-hash-secret")
	t.Setenv("APP_LOG_PSEUDONYM_SECRET", "a-real-log-pseudonym-secret-0123456789")
	t.Setenv("APP_PROXY_REQUIRE_LOGIN", "true")
	t.Setenv("APP_TRUST_PROXY_HEADERS", "true")
	for _, mode := range []string{"", "path", "query", "dual"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("APP_PROXY_URL_MODE", mode)
			if err := validateProductionConfig("production", "/var/lib/odo/odo.db", "", true); err != nil {
				t.Fatalf("expected valid production config: %v", err)
			}
		})
	}
}

func TestProductionConfigurationAcceptsExplicitLocalAdminBootstrap(t *testing.T) {
	t.Setenv("APP_SOURCE_URL", "https://code.example.edu/odo/archive/test-revision.tar.gz")
	t.Setenv("APP_BUILD_REVISION", "test-revision")
	t.Setenv("APP_PUBLIC_URL", "https://access.example.edu")
	t.Setenv("APP_KEY_HASH_SECRET", "a-real-key-hash-secret")
	t.Setenv("APP_LOG_PSEUDONYM_SECRET", "a-real-log-pseudonym-secret-0123456789")
	t.Setenv("APP_PROXY_REQUIRE_LOGIN", "true")
	t.Setenv("APP_BOOTSTRAP_ADMIN_USERNAME", "initial-admin")
	t.Setenv("APP_BOOTSTRAP_ADMIN_PASSWORD", "a-strong-bootstrap-password")
	if err := validateProductionConfig("production", "/var/lib/odo/odo.db", "", false); err != nil {
		t.Fatalf("expected explicit local-admin bootstrap to be accepted: %v", err)
	}
}

func TestDevelopmentConfigurationAllowsUnsafeValues(t *testing.T) {
	// A half-configured virtual-host mode fails in every environment, like the
	// host guard itself; development is only permissive about secrets and paths.
	t.Setenv("APP_PUBLIC_URL", "")
	t.Setenv("APP_KEY_HASH_SECRET", "change-me")
	t.Setenv("APP_PROXY_REQUIRE_LOGIN", "false")
	if err := validateProductionConfig("development", filepath.Join(os.TempDir(), "odo.db"), "change-me", false); err != nil {
		t.Fatalf("development should remain permissive: %v", err)
	}
}

func TestRuntimeDefaultsPreferProductionPathsInProduction(t *testing.T) {
	if got := defaultDataDir("production"); got != "/var/lib/odo" {
		t.Fatalf("expected production data dir /var/lib/odo, got %q", got)
	}
	if got := defaultConfigDir("production"); got != "/etc/odo" {
		t.Fatalf("expected production config dir /etc/odo, got %q", got)
	}
	if got := defaultDataDir("development"); got != "./data" {
		t.Fatalf("expected development data dir ./data, got %q", got)
	}
}

func TestStartupRejectsInvalidHostGuardInAllEnvironments(t *testing.T) {
	for _, environment := range []string{"development", "production"} {
		for _, flag := range []string{"true", "typo"} {
			t.Run(environment+flag, func(t *testing.T) {
				t.Setenv("APP_HOST_GUARD", flag)
				t.Setenv("APP_PUBLIC_URL", "")
				t.Setenv("APP_PROXY_BASE_DOMAIN", "")
				if err := validateProductionConfig(environment, "/var/lib/odo/odo.db", "secret", true); err == nil {
					t.Fatal("startup accepted invalid host guard configuration")
				}
			})
		}
	}
}

func TestProductionVirtualHostSwitch(t *testing.T) {
	production := func(t *testing.T) {
		t.Setenv("APP_ENV", "production")
		t.Setenv("APP_PUBLIC_URL", "https://odo.example")
		t.Setenv("APP_KEY_HASH_SECRET", "a-real-key-hash-secret")
		t.Setenv("APP_LOG_PSEUDONYM_SECRET", "a-real-log-pseudonym-secret-0123456789")
		t.Setenv("APP_PROXY_REQUIRE_LOGIN", "true")
		t.Setenv("APP_HOST_GUARD", "true")
		t.Setenv("APP_PROXY_BASE_DOMAIN", "proxy.example")
		t.Setenv("APP_EXPERIMENTAL_HANDOFF", "")
		t.Setenv("APP_PROXY_URL_MODE", "")
		t.Setenv("APP_SOURCE_URL", "https://example.org/odo")
		t.Setenv("APP_BUILD_REVISION", "0123456789abcdef")
	}
	dbPath := "/var/lib/odo/odo.db"
	for _, tc := range []struct {
		name, mode, alias, want string
	}{
		{name: "virtual host", mode: "virtual_host"},
		{name: "deprecated alias", alias: "true"},
		{name: "alias with matching mode", mode: "virtual_host", alias: "true"},
		{name: "alias conflicting with path mode", mode: "path", alias: "true", want: "conflicts with APP_PROXY_URL_MODE=path"},
		{name: "invalid alias", alias: "maybe", want: "APP_EXPERIMENTAL_HANDOFF must be true or false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			production(t)
			t.Setenv("APP_PROXY_URL_MODE", tc.mode)
			t.Setenv("APP_EXPERIMENTAL_HANDOFF", tc.alias)
			err := validateProductionConfig("production", dbPath, "real-admin-key", true)
			if tc.want == "" && err != nil {
				t.Fatalf("valid production virtual-host configuration rejected: %v", err)
			}
			if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
	production(t)
	t.Setenv("APP_PROXY_URL_MODE", "virtual_host")
	t.Setenv("APP_PUBLIC_URL", "http://odo.example")
	if err := validateProductionConfig("production", dbPath, "real-admin-key", true); err == nil {
		t.Fatal("virtual-host mode accepted an HTTP central URL")
	}
}
