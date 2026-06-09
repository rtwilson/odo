package main

import (
	"log/slog"
	"net/http"
	"os"

	"example.org/odo/internal/accesslog"
	"example.org/odo/internal/api"
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
	if adminAPIKey == "" {
		logger.Warn("APP_ADMIN_API_KEY is not set; management API is unprotected")
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
