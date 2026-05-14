package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/juev/nebula-mesh/internal/mobilebundle"
	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/pki"
	"github.com/juev/nebula-mesh/internal/store"
)

// handleMobileBundle implements POST /api/v1/hosts/{id}/mobile-bundle.
// Generates a self-contained mobile bundle (YAML config + certificate + key)
// for a mobile host. The private key is generated fresh and returned inline;
// it is not persisted on the server.
func (s *Server) handleMobileBundle(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	host, err := s.store.GetHost(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	if err != nil {
		s.logger.Error("get host for mobile-bundle", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get host")
		return
	}

	// Check that host is mobile
	if host.Kind != models.HostKindMobile {
		writeError(w, http.StatusBadRequest, "host must be a mobile host")
		return
	}

	// Resolve the CA that owns this host and sign with it.
	caMgr, err := s.caForHost(r.Context(), host)
	if err != nil {
		s.logger.Error("resolve host CA", "error", err, "host_id", host.ID, "ca_id", host.CAID)
		writeError(w, http.StatusInternalServerError, "failed to resolve CA")
		return
	}

	// Build the mobile bundle under CA read lock (signing requires CA private key access)
	simpleResolver := &singleCAResolver{ca: caMgr}
	s.caMu.RLock()
	bundle, err := mobilebundle.Build(r.Context(), s.store, simpleResolver, host)
	s.caMu.RUnlock()

	if errors.Is(err, mobilebundle.ErrNotMobile) {
		writeError(w, http.StatusBadRequest, "host is not a mobile host")
		return
	}
	if err != nil {
		s.logger.Error("build mobile bundle", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to build bundle")
		return
	}

	// Return YAML bundle with proper content-type
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(bundle); err != nil {
		s.logger.Error("write mobile bundle response", "error", err)
	}
}

// singleCAResolver wraps a resolved CAManager to match the resolver interface.
type singleCAResolver struct {
	ca *pki.CAManager
}

func (r *singleCAResolver) LoadByID(ctx context.Context, caID string) (*pki.CAManager, error) {
	return r.ca, nil
}
