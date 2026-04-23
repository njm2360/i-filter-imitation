package proxy

import (
	"net/http"
	"strings"

	"github.com/njm2360/i-filter-imitation/internal/scan"
)

const magicHost = "proxy.invalid"

func (s *Server) serveMagicHost(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, scan.PathPrefix) {
		s.scanHandler.ServeHTTP(w, r)
		return
	}
	switch r.URL.Path {
	case "/cert.pem":
		s.serveCertPEM(w)
	case "/cert.crt":
		s.serveCertDER(w)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) serveCertPEM(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="proxy-ca.pem"`)
	w.Write(s.caCertPEM)
}

func (s *Server) serveCertDER(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="proxy-ca.crt"`)
	w.Write(s.caCertDER)
}
