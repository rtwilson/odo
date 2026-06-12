package main

import (
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"example.org/odo/internal/accesslog"
	"example.org/odo/internal/api"
	"example.org/odo/internal/auth/local"
	"example.org/odo/internal/db"
	"example.org/odo/internal/proxy"
)

func main() {
	appEnv := normalizedAppEnv()
	addr := env("APP_BIND_ADDR", env("APP_ADDR", ":8080"))
	dataDir := env("APP_DATA_DIR", defaultDataDir(appEnv))
	dbPath := env("APP_DB_PATH", filepath.Join(dataDir, "odo.db"))
	configDir := env("APP_CONFIG_DIR", defaultConfigDir(appEnv))
	adminAPIKey := os.Getenv("APP_ADMIN_API_KEY")
	accessLogFormat := env("APP_ACCESS_LOG_FORMAT", accesslog.FormatPrivacy)
	accessLogPath := os.Getenv("APP_ACCESS_LOG_PATH")
	proxyDebug := env("APP_PROXY_DEBUG", "false") == "true"
	proxyURLMode := proxy.ProxyURLMode()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{}))
	if warning := proxy.ProxyURLModeWarning(os.Getenv("APP_PROXY_URL_MODE")); warning != "" {
		logger.Warn(warning)
	}
	for _, warning := range productionWarnings(appEnv, dataDir, dbPath, adminAPIKey) {
		logger.Warn(warning)
	}

	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		logger.Error("create data directory", "err", err, "data_dir", dataDir)
		os.Exit(1)
	}

	store, err := db.Open(dbPath)
	if err != nil {
		logger.Error("open database", "err", err)
		os.Exit(1)
	}
	defer store.Close()

	if err := store.Migrate(); err != nil {
		logger.Error("migrate database", "err", err)
		os.Exit(1)
	}
	apiKeyCount, err := store.CountAPIKeys()
	if err != nil {
		logger.Error("count api keys", "err", err)
		os.Exit(1)
	}
	if adminAPIKey == "" && apiKeyCount == 0 {
		logger.Warn("APP_ADMIN_API_KEY is not set; management API is unprotected")
	}
	if os.Getenv("APP_KEY_HASH_SECRET") == "" {
		logger.Warn("APP_KEY_HASH_SECRET is not set; API keys use local-dev SHA-256 hashing")
	}
	if err := bootstrapAdminUser(store, logger); err != nil {
		logger.Error("bootstrap admin user", "err", err)
		os.Exit(1)
	}

	accessLogger, accessLogCloser, err := accesslog.Open(accessLogFormat, accessLogPath)
	if err != nil {
		logger.Error("open access log", "err", err)
		os.Exit(1)
	}
	defer accessLogCloser.Close()

	server := api.NewServerWithAccessLoggerResolverHTTPClientAndProxyDebug(store, configDir, adminAPIKey, logger, accessLogger, nil, proxy.DefaultHTTPClient(), proxyDebug)
	logger.Info("odo listening", "addr", addr, "app_env", appEnv, "data_dir", dataDir, "db", dbPath, "config_dir", configDir, "proxy_url_mode", proxyURLMode)
	if err := http.ListenAndServe(addr, server.Routes()); err != nil {
		logger.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func normalizedAppEnv() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("APP_ENV"))) {
	case "production":
		return "production"
	case "", "development":
		return "development"
	default:
		return "development"
	}
}

func defaultDataDir(appEnv string) string {
	if appEnv == "production" {
		return "/var/lib/odo"
	}
	return "./data"
}

func defaultConfigDir(appEnv string) string {
	if appEnv == "production" {
		return "/etc/odo"
	}
	return "./config"
}

func productionWarnings(appEnv, dataDir, dbPath, adminAPIKey string) []string {
	if appEnv != "production" {
		return nil
	}
	var warnings []string
	if strings.TrimSpace(os.Getenv("APP_PUBLIC_URL")) == "" {
		warnings = append(warnings, "APP_ENV=production but APP_PUBLIC_URL is not set")
	}
	if strings.TrimSpace(os.Getenv("APP_KEY_HASH_SECRET")) == "" {
		warnings = append(warnings, "APP_ENV=production but APP_KEY_HASH_SECRET is not set")
	}
	if adminAPIKey == "devsecret" {
		warnings = append(warnings, "APP_ENV=production but APP_ADMIN_API_KEY is set to devsecret")
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("APP_PROXY_REQUIRE_LOGIN")), "false") {
		warnings = append(warnings, "APP_ENV=production but APP_PROXY_REQUIRE_LOGIN is disabled")
	}
	if strings.HasPrefix(dbPath, os.TempDir()+string(os.PathSeparator)) || strings.HasPrefix(dataDir, os.TempDir()+string(os.PathSeparator)) {
		warnings = append(warnings, "APP_ENV=production but database path appears to be temporary")
	}
	return warnings
}

func bootstrapAdminUser(store *db.Store, logger *slog.Logger) error {
	count, err := store.CountUsers()
	if err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	username := os.Getenv("APP_BOOTSTRAP_ADMIN_USERNAME")
	password := os.Getenv("APP_BOOTSTRAP_ADMIN_PASSWORD")
	if username == "" || password == "" {
		logger.Warn("no local users exist; set APP_BOOTSTRAP_ADMIN_USERNAME and APP_BOOTSTRAP_ADMIN_PASSWORD to create an initial admin user")
		return nil
	}
	hash, err := local.HashPassword(password)
	if err != nil {
		return err
	}
	id, err := local.NewToken("user_", 12)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if err := store.CreateUser(db.User{
		ID:           id,
		Username:     username,
		Email:        os.Getenv("APP_BOOTSTRAP_ADMIN_EMAIL"),
		PasswordHash: hash,
		Status:       "active",
		Roles:        []string{"admin"},
		CreatedAt:    now,
		UpdatedAt:    now,
	}); err != nil {
		return err
	}
	logger.Info("created bootstrap admin user", "username", username)
	return nil
}
