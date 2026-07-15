package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/forgekeep/nebula-mesh/internal/mobilebundle"
	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/pki"
	"github.com/forgekeep/nebula-mesh/internal/store"
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
	ok, err := s.canAccessHost(r.Context(), host)
	if err != nil {
		s.logger.Error("authz check", "error", err)
		writeError(w, http.StatusInternalServerError, "authz check failed")
		return
	}
	if !ok {
		s.recordAuditAction(r.Context(), auditHostMobileBundleForbidden, host.ID, "non_owner")
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if rejectImportingHost(w, host) {
		return
	}

	// Check that host is mobile
	if host.Kind != models.HostKindMobile {
		writeError(w, http.StatusBadRequest, "host must be a mobile host")
		return
	}

	// Durable revocation (GHSA-339v-266x-79xr): a mobile bundle mints a fresh
	// cert just like enrollment, so refuse it for a blocked host or a disabled
	// operator's host before any CA key is decrypted. mobilebundle.Build repeats
	// this check as a backstop for the web handler.
	if err := s.checkIssuanceAllowed(r.Context(), host); err != nil {
		switch {
		case errors.Is(err, errHostBlocked), errors.Is(err, errOperatorDisabled):
			s.recordAuditAction(r.Context(), auditHostMobileBundleForbidden, host.ID, "revoked: "+err.Error())
			writeError(w, http.StatusForbidden, "mobile-bundle denied: "+err.Error())
		default:
			s.logger.Error("issuance check", "error", err, "host", host.ID)
			writeError(w, http.StatusInternalServerError, "failed to build bundle")
		}
		return
	}

	// Resolve the CA that owns this host and sign with it.
	caMgr, err := s.caForHost(r.Context(), host)
	if err != nil {
		s.logger.Error("resolve host CA", "error", err, "host_id", host.ID, "ca_id", host.CAID)
		writeError(w, http.StatusInternalServerError, "failed to resolve CA")
		return
	}
	defer caMgr.Wipe() // GHSA-8h84-fhqq-q58v: zeroise plaintext CA key on return.

	// Build the mobile bundle; wrap resolved CA in a simple resolver for builder
	resolver := &caManagerResolver{ca: caMgr}
	bundle, err := mobilebundle.Build(r.Context(), s.store, resolver, host)

	if errors.Is(err, mobilebundle.ErrNotMobile) {
		writeError(w, http.StatusBadRequest, "host is not a mobile host")
		return
	}
	if err != nil {
		s.logger.Error("build mobile bundle", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to build bundle")
		return
	}

	// Mobile-bundle issuance mints a fresh X25519 private key + cert; audit the
	// positive path so the forensic trail exists alongside host.mobile_bundle.forbidden.
	s.recordAuditAction(r.Context(), auditHostMobileBundleIssued, host.ID, "ca_id="+host.CAID)

	// Return YAML bundle with proper content-type. The bundle inlines a
	// freshly-minted X25519 private key, so suppress every layer of cache
	// between server and operator (intermediate proxies/CDNs, browser disk
	// cache). X-Content-Type-Options is set globally by the securityHeaders
	// middleware in cli/serve.go. Closes GHSA-6vgg-xhvh-38ff.
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(bundle); err != nil { // #nosec G705 -- response is application/yaml with X-Content-Type-Options: nosniff (set globally by securityHeaders middleware), not HTML; bundle is server-built YAML
		s.logger.Error("write mobile bundle response", "error", err)
	}
}

// caManagerResolver wraps a resolved CAManager to match the resolver interface.
type caManagerResolver struct {
	ca *pki.CAManager
}

func (r *caManagerResolver) LoadByID(ctx context.Context, caID string) (*pki.CAManager, error) {
	return r.ca, nil
}
