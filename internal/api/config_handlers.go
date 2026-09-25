package api

import (
	"errors"
	"net/http"
	"strconv"

	"example.org/odo/internal/config"
)

func (s *Server) importConfig(w http.ResponseWriter, r *http.Request) {
	results, err := config.ImportResources(s.store, s.configDir)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	var failures []error
	for _, result := range results {
		if result.InternalError != nil {
			failures = append(failures, result.InternalError)
		}
	}
	if len(failures) > 0 {
		s.internalError(w, r, errors.Join(failures...))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

func (s *Server) validateConfig(w http.ResponseWriter, r *http.Request) {
	result, err := config.ValidateResources(s.configDir)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	var failures []error
	for _, item := range result.Results {
		if item.InternalError != nil {
			failures = append(failures, item.InternalError)
		}
	}
	if len(failures) > 0 {
		s.internalError(w, r, errors.Join(failures...))
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) listConfigRevisions(w http.ResponseWriter, r *http.Request) {
	revisions, err := s.store.ListConfigRevisions(25)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revisions": revisions})
}

func (s *Server) getConfigRevision(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid revision id")
		return
	}
	revision, found, err := s.store.GetConfigRevision(id)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "revision not found")
		return
	}
	writeJSON(w, http.StatusOK, revision)
}
