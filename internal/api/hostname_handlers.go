package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"example.org/odo/internal/db"
	"example.org/odo/internal/proxy"
)

func (s *Server) reconcileProxyHostnames(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	// Registry metadata must never be derived from Host or forwarded headers.
	public, err := url.Parse(strings.TrimSpace(os.Getenv("APP_PUBLIC_URL")))
	base := strings.TrimSpace(os.Getenv("APP_PROXY_BASE_DOMAIN"))
	if err != nil || public.Scheme != "https" || public.Host == "" || public.User != nil ||
		(public.Path != "" && public.Path != "/") || public.RawQuery != "" || public.Fragment != "" {
		writeError(w, http.StatusServiceUnavailable, "hostname registry deployment settings are missing or invalid")
		return
	}
	central, err := proxy.NormalizeRegistryHostname(public.Host)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "hostname registry deployment settings are missing or invalid")
		return
	}
	// Validate the base and the length of a generated proxy FQDN, even when
	// the resource list is empty. The configured central host may be within it.
	base, err = proxy.NormalizeRegistryHostname(base)
	if err != nil || len(base)+55 > 253 {
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
	records, err := s.store.ReconcileProxyHostnames(central, base, req.ApprovedHosts)
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
