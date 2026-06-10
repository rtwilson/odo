package main

import (
	"log/slog"
	"net/http"
	"os"
	"time"

	"example.org/odo/internal/accesslog"
	"example.org/odo/internal/api"
	"example.org/odo/internal/auth/local"
	"example.org/odo/internal/db"
	"example.org/odo/internal/proxy"
)

func main() {
	addr := env("APP_ADDR", ":8080")
	dbPath := env("APP_DB_PATH", "./data/app.db")
	configDir := env("APP_CONFIG_DIR", "./config")
	adminAPIKey := os.Getenv("APP_ADMIN_API_KEY")
	accessLogFormat := env("APP_ACCESS_LOG_FORMAT", accesslog.FormatPrivacy)
	accessLogPath := os.Getenv("APP_ACCESS_LOG_PATH")
	proxyDebug := env("APP_PROXY_DEBUG", "false") == "true"
	proxyURLMode := proxy.ProxyURLMode()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{}))

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
	logger.Info("odo listening", "addr", addr, "db", dbPath, "config_dir", configDir, "proxy_url_mode", proxyURLMode)
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
