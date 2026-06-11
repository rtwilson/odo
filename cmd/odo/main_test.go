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
