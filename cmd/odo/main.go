package main

import (
	"log/slog"
	"net/http"
	"os"

	"example.org/odo/internal/api"
	"example.org/odo/internal/db"
)

func main() {
	addr := env("APP_ADDR", ":8080")
	dbPath := env("APP_DB_PATH", "./data/app.db")
	configDir := env("APP_CONFIG_DIR", "./config")
	adminAPIKey := os.Getenv("APP_ADMIN_API_KEY")

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

	server := api.NewServer(store, configDir, adminAPIKey, logger)
	logger.Info("odo listening", "addr", addr, "db", dbPath, "config_dir", configDir)
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
