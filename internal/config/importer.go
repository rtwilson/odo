package config

import (
	"fmt"
	"os"
	"path/filepath"

	"example.org/odo/internal/db"
	"example.org/odo/internal/resources"
)

type ImportResult struct {
	File       string `json:"file"`
	ResourceID string `json:"resource_id,omitempty"`
	Imported   bool   `json:"imported"`
	Error      string `json:"error,omitempty"`
}

func ImportResources(store *db.Store, configDir string) ([]ImportResult, error) {
	pattern := filepath.Join(configDir, "resources", "*.json")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return []ImportResult{}, nil
	}

	results := make([]ImportResult, 0, len(files))
	for _, file := range files {
		result := ImportResult{File: file}
		data, err := os.ReadFile(file)
		if err != nil {
			result.Error = err.Error()
			results = append(results, result)
			continue
		}
		resource, err := resources.Decode(data)
		if err != nil {
			result.Error = err.Error()
			results = append(results, result)
			continue
		}
		if err := store.UpsertResource(resource); err != nil {
			result.Error = fmt.Sprintf("database import failed: %v", err)
			results = append(results, result)
			continue
		}
		result.ResourceID = resource.ID
		result.Imported = true
		results = append(results, result)
	}
	return results, nil
}
