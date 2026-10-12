package api

import (
	_ "embed"
	"net/http"
)

// faviconICO is a 16x16 monochrome O in a standard 32-bit ICO bitmap.
//
//go:embed favicon.ico
var faviconICO []byte

func (s *Server) favicon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/x-icon")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	if r.Method != http.MethodHead {
		_, _ = w.Write(faviconICO)
	}
}
