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

type ValidationResponse struct {
	Valid     bool               `json:"valid"`
	ConfigDir string             `json:"config_dir"`
	Results   []ValidationResult `json:"results"`
}

type ValidationResult struct {
	File       string   `json:"file"`
	Valid      bool     `json:"valid"`
	ResourceID string   `json:"resource_id"`
	Errors     []string `json:"errors"`
}

func ImportResources(store *db.Store, configDir string) ([]ImportResult, error) {
	files, err := resourceFiles(configDir)
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

func ValidateResources(configDir string) (ValidationResponse, error) {
	files, err := resourceFiles(configDir)
	if err != nil {
		return ValidationResponse{}, err
	}

	response := ValidationResponse{
		Valid:     true,
		ConfigDir: configDir,
		Results:   make([]ValidationResult, 0, len(files)),
	}
	for _, file := range files {
		result := ValidationResult{File: file, Valid: true, Errors: []string{}}
		data, err := os.ReadFile(file)
		if err != nil {
			result.Valid = false
			result.Errors = []string{err.Error()}
		} else {
			resource, errs := resources.DecodeAll(data)
			result.ResourceID = resource.ID
			if len(errs) > 0 {
				result.Valid = false
				result.Errors = errs
			}
		}
		if !result.Valid {
			response.Valid = false
		}
		response.Results = append(response.Results, result)
	}
	return response, nil
}

func resourceFiles(configDir string) ([]string, error) {
	return filepath.Glob(filepath.Join(configDir, "resources", "*.json"))
}
