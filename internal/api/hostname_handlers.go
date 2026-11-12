package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"

	"example.org/odo/internal/db"
	"example.org/odo/internal/proxy"
)

func (s *Server) getProxyHostname(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	label := r.PathValue("label")
	record, found, err := s.store.LookupProxyHostname(label)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "proxy hostname not found")
		return
	}
	ids, err := s.store.ProxyHostnameResourceIDs(label)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if ids == nil {
		ids = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"hostname":     record.Hostname,
		"label":        record.Label,
		"resource_ids": ids,
	})
}

func (s *Server) reconcileProxyHostnames(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	// Registry metadata must never be derived from Host or forwarded headers.
	routing, err := proxy.NewHostRoutingConfig(os.Getenv("APP_PUBLIC_URL"), os.Getenv("APP_PROXY_BASE_DOMAIN"))
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "hostname registry deployment settings are missing or invalid")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	defer r.Body.Close()
	data, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "hostname reconciliation JSON must be at most 64 KiB")
		} else {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
		}
		return
	}
	var req *struct {
		ApprovedHosts []string `json:"approved_hosts"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil || req == nil {
		writeError(w, http.StatusBadRequest, "invalid hostname reconciliation body")
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF || len(req.ApprovedHosts) > 100 {
		writeError(w, http.StatusBadRequest, "invalid hostname reconciliation body")
		return
	}
	records, err := s.store.ReconcileProxyHostnames(routing.CentralHostname(), routing.ProxyBaseDomain(), req.ApprovedHosts)
	if errors.Is(err, db.ErrInvalidHostnameReconciliation) {
		writeError(w, http.StatusBadRequest, "hostname reconciliation rejected by hostname or resource policy")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	// Use a stable lower-case JSON contract without changing the storage type.
	type hostnameRecord struct {
		Hostname string `json:"hostname"`
		Label    string `json:"label"`
	}
	out := make([]hostnameRecord, 0, len(records))
	for _, record := range records {
		out = append(out, hostnameRecord{Hostname: record.Hostname, Label: record.Label})
	}
	writeJSON(w, http.StatusOK, map[string]any{"hostnames": out})
}

// enrollConfiguredProxyHostnames registers the exact proxy hosts that active
// resources already name, after an administrator saves or imports resources.
// Saving an exact proxy domain is the administrator's approval of that host,
// so a separate reconcile call is not required for it. Hosts covered only by
// subdomain rules still need explicit approved_hosts through the reconcile API.
// Path-only deployments (no virtual-host settings) skip enrollment. A failure
// never undoes the committed resource write; the reconcile API reports details.
func (s *Server) enrollConfiguredProxyHostnames() {
	routing, err := proxy.NewHostRoutingConfig(os.Getenv("APP_PUBLIC_URL"), os.Getenv("APP_PROXY_BASE_DOMAIN"))
	if err != nil {
		return
	}
	if _, err := s.store.ReconcileProxyHostnames(routing.CentralHostname(), routing.ProxyBaseDomain(), nil); err != nil && s.logger != nil {
		s.logger.Warn("automatic proxy hostname enrollment failed; run hostname reconciliation for details")
	}
}
