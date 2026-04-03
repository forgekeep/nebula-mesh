package api

import (
	"net/http"
	"time"

	"github.com/juev/nebula-mesh/internal/pki"
)

type caInfoResponse struct {
	Fingerprint string `json:"fingerprint"`
	Name        string `json:"name"`
	NotBefore   string `json:"not_before"`
	NotAfter    string `json:"not_after"`
}

func (s *Server) handleGetCA(w http.ResponseWriter, _ *http.Request) {
	cert := s.ca.CACert()
	fp, _ := s.ca.CACertFingerprint()

	writeJSON(w, http.StatusOK, caInfoResponse{
		Fingerprint: fp,
		Name:        cert.Name(),
		NotBefore:   cert.NotBefore().Format(time.RFC3339),
		NotAfter:    cert.NotAfter().Format(time.RFC3339),
	})
}

func (s *Server) handleRotateCA(w http.ResponseWriter, _ *http.Request) {
	rotation, err := pki.NewRotation(s.ca, s.ca.CACert().Name()+"-rotated", 365*24*time.Hour)
	if err != nil {
		s.logger.Error("rotate CA", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to rotate CA")
		return
	}

	// Switch to new CA for signing
	s.ca = rotation.NewCA()

	bundle, err := rotation.TrustBundle()
	if err != nil {
		s.logger.Error("trust bundle", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to create trust bundle")
		return
	}

	newFP, _ := rotation.NewCA().CACertFingerprint()
	s.logger.Info("CA rotated", "new_fingerprint", newFP)

	writeJSON(w, http.StatusOK, map[string]string{
		"status":          "rotated",
		"new_fingerprint": newFP,
		"trust_bundle":    string(bundle),
	})
}
