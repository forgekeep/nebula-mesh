package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/juev/nebula-mesh/internal/keystore"
	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/pki"
	"github.com/juev/nebula-mesh/internal/store"
)

// caView wraps a CA model with pre-computed display state for templates.
type caView struct {
	*models.CA
	IsExpiringSoon bool
}

// ErrCAMasterNotConfigured is returned by mintCAForOperator when the
// master keystore is not wired. Auto-provision skips silently on this error.
var ErrCAMasterNotConfigured = errors.New("ca master key not configured")

// WithMaster wires the keystore master the CA-create handler needs.
// Without it, /ui/cas/new renders an inline error pointing at the
// NEBULA_MGMT_MASTER_KEY docs instead of failing with a 500.
func (w *Web) WithMaster(m *keystore.Master) {
	w.caMaster = m
}

func (w *Web) handleCAsList(rw http.ResponseWriter, r *http.Request) {
	op := w.session.CurrentOperator(r)
	if op == nil {
		http.Redirect(rw, r, "/ui/login", http.StatusSeeOther)
		return
	}
	var (
		cas []*models.CA
		err error
	)
	if op.Role == "admin" {
		cas, err = w.store.ListCAs(r.Context())
	} else {
		cas, err = w.store.ListCAsByOwner(r.Context(), op.ID)
	}
	if err != nil {
		w.logger.Error("list cas", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	// Pre-compute IsExpiringSoon for each CA using pki.ShouldRenew threshold.
	caViews := make([]*caView, len(cas))
	for i, ca := range cas {
		caViews[i] = &caView{
			CA:             ca,
			IsExpiringSoon: pki.ShouldRenew(ca.NotBefore, ca.NotAfter),
		}
	}
	w.renderForRequest(rw, r, "cas_list.html", map[string]any{
		"Active":  "cas",
		"CAs":     caViews,
		"IsAdmin": op.Role == "admin",
	})
}

func (w *Web) handleCANewPage(rw http.ResponseWriter, r *http.Request) {
	w.renderForRequest(rw, r, "ca_new.html", map[string]any{
		"Active":      "cas",
		"Error":       "",
		"MasterReady": w.caMaster != nil,
	})
}

// mintCAForOperator generates a fresh per-operator CA with the given name
// and duration, wraps the private key under the configured master keystore,
// persists to the store, and writes a "ca.created" audit entry. Returns
// ErrCAMasterNotConfigured if w.caMaster is nil. Caller is responsible for
// any HTTP-level error mapping or redirect. The returned CA has Status set
// to models.CAStatusActive.
func (w *Web) mintCAForOperator(ctx context.Context, op *models.Operator, name string, duration time.Duration) (*models.CA, error) {
	if w.caMaster == nil {
		return nil, ErrCAMasterNotConfigured
	}

	mgr, err := pki.NewCA(name, duration)
	if err != nil {
		w.logger.Error("generate ca", "error", err)
		return nil, err
	}
	rawKey := mgr.RawKey()
	defer keystore.Zeroize(rawKey)

	dek, wrappedDEK, err := w.caMaster.GenerateDEK()
	if err != nil {
		w.logger.Error("generate dek", "error", err)
		return nil, err
	}
	defer keystore.Zeroize(dek)

	wrappedKey, err := keystore.SealWithDEK(dek, rawKey)
	if err != nil {
		w.logger.Error("seal ca key", "error", err)
		return nil, err
	}

	certPEM, err := mgr.CACertPEM()
	if err != nil {
		w.logger.Error("marshal ca cert", "error", err)
		return nil, err
	}

	fp, err := mgr.CACertFingerprint()
	if err != nil {
		w.logger.Error("fingerprint ca cert", "error", err)
		return nil, err
	}

	now := time.Now()
	ca := &models.CA{
		ID:                   uuid.New().String(),
		Name:                 name,
		OwnerOperatorID:      op.ID,
		CertPEM:              string(certPEM),
		Fingerprint:          fp,
		NotBefore:            mgr.CACert().NotBefore(),
		NotAfter:             mgr.CACert().NotAfter(),
		Status:               models.CAStatusActive,
		EncryptedKeyDEK:      wrappedDEK.Ciphertext,
		NonceDEK:             wrappedDEK.Nonce,
		EncryptedKeyMaterial: wrappedKey.Ciphertext,
		NonceKey:             wrappedKey.Nonce,
		CreatedAt:            now,
		UpdatedAt:            now,
	}

	if err := w.store.CreateCA(ctx, ca); err != nil {
		w.logger.Error("create ca", "error", err)
		return nil, err
	}

	_ = w.store.AddAuditEntry(ctx, op.Username, "ca.created", ca.ID, ca.Name)

	return ca, nil
}

// provisionDefaultCA is the idempotent onboarding-time hook for auto-provisioning
// a default CA. If op has zero active CAs, mints <op.Username>-default with a
// 10-year lifetime. Silently skips (returns nil) when the master key is not
// configured or when op already has an active CA. Returns any error from
// mintCAForOperator if minting is attempted.
func (w *Web) provisionDefaultCA(ctx context.Context, op *models.Operator) error {
	// Skip if no master key configured.
	if w.caMaster == nil {
		w.logger.Warn("auto-provision skipped: master key not configured")
		return nil
	}

	// Skip if operator already has an active CA (idempotence).
	cas, err := w.store.ListCAsByOwner(ctx, op.ID)
	if err != nil {
		w.logger.Error("list cas for provision check", "error", err)
		return err
	}
	for _, ca := range cas {
		if ca.Status == models.CAStatusActive {
			return nil
		}
	}

	// Mint the default CA with a 10-year lifetime.
	const tenYears = 10 * 365 * 24 * time.Hour
	_, err = w.mintCAForOperator(ctx, op, op.Username+"-default", tenYears)
	return err
}

func (w *Web) handleCACreate(rw http.ResponseWriter, r *http.Request) {
	op := w.session.CurrentOperator(r)
	if op == nil {
		http.Redirect(rw, r, "/ui/login", http.StatusSeeOther)
		return
	}
	if w.caMaster == nil {
		w.renderForRequest(rw, r, "ca_new.html", map[string]any{
			"Active":      "cas",
			"Error":       "CA creation requires NEBULA_MGMT_MASTER_KEY to be configured. See docs/adr/0002-per-operator-cas.md.",
			"MasterReady": false,
		})
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		w.renderForRequest(rw, r, "ca_new.html", map[string]any{
			"Active":      "cas",
			"Error":       "Name is required",
			"MasterReady": true,
		})
		return
	}
	dur := 365 * 24 * time.Hour
	if d := strings.TrimSpace(r.FormValue("duration")); d != "" {
		parsed, err := time.ParseDuration(d)
		if err != nil || parsed <= 0 {
			w.renderForRequest(rw, r, "ca_new.html", map[string]any{
				"Active":      "cas",
				"Error":       "Invalid duration (try e.g. 8760h)",
				"MasterReady": true,
			})
			return
		}
		dur = parsed
	}

	ca, err := w.mintCAForOperator(r.Context(), op, name, dur)
	if err != nil {
		if errors.Is(err, ErrCAMasterNotConfigured) {
			w.renderForRequest(rw, r, "ca_new.html", map[string]any{
				"Active":      "cas",
				"Error":       "CA creation requires NEBULA_MGMT_MASTER_KEY to be configured. See docs/adr/0002-per-operator-cas.md.",
				"MasterReady": false,
			})
			return
		}
		w.logger.Error("mint ca for operator", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}

	http.Redirect(rw, r, "/ui/cas/"+ca.ID, http.StatusSeeOther)
}

func (w *Web) handleCADetail(rw http.ResponseWriter, r *http.Request) {
	c, ok := w.loadAccessibleCA(rw, r)
	if !ok {
		return
	}
	isExpiringSoon := pki.ShouldRenew(c.NotBefore, c.NotAfter)
	w.renderForRequest(rw, r, "ca_detail.html", map[string]any{
		"Active":            "cas",
		"CA":                c,
		"IsExpiringSoon":    isExpiringSoon,
		"Error":             r.URL.Query().Get("error"),
	})
}

func (w *Web) handleCARetire(rw http.ResponseWriter, r *http.Request) {
	c, ok := w.loadAccessibleCA(rw, r)
	if !ok {
		return
	}
	if err := w.store.UpdateCAStatus(r.Context(), c.ID, models.CAStatusRetired); err != nil {
		w.logger.Error("retire ca", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	if op := w.session.CurrentOperator(r); op != nil {
		_ = w.store.AddAuditEntry(r.Context(), op.Username, "ca.retired", c.ID, c.Name)
	}
	http.Redirect(rw, r, "/ui/cas/"+c.ID, http.StatusSeeOther)
}

func (w *Web) handleCADelete(rw http.ResponseWriter, r *http.Request) {
	c, ok := w.loadAccessibleCA(rw, r)
	if !ok {
		return
	}
	if err := w.store.DeleteCA(r.Context(), c.ID); err != nil {
		// Common case: still attached to one or more networks. Surface
		// the store-layer message inline rather than a generic 500.
		http.Redirect(rw, r, "/ui/cas/"+c.ID+"?error="+
			http.StatusText(http.StatusConflict)+": "+err.Error(), http.StatusSeeOther)
		return
	}
	if op := w.session.CurrentOperator(r); op != nil {
		_ = w.store.AddAuditEntry(r.Context(), op.Username, "ca.deleted", c.ID, c.Name)
	}
	http.Redirect(rw, r, "/ui/cas", http.StatusSeeOther)
}

func (w *Web) handleCARotate(rw http.ResponseWriter, r *http.Request) {
	c, ok := w.loadAccessibleCA(rw, r)
	if !ok {
		return
	}
	newCA, err := pki.RotateAndStoreCA(r.Context(), w.store, w.caMaster, w.logger, c)
	if err != nil {
		w.logger.Error("rotate ca", "error", err)
		http.Redirect(rw, r, "/ui/cas/"+c.ID+"?error="+
			http.StatusText(http.StatusInternalServerError)+": "+err.Error(),
			http.StatusSeeOther)
		return
	}
	if op := w.session.CurrentOperator(r); op != nil {
		_ = w.store.AddAuditEntry(r.Context(), op.Username, "ca.rotated", newCA.ID,
			fmt.Sprintf("predecessor=%s", c.ID))
	}
	http.Redirect(rw, r, "/ui/cas/"+newCA.ID, http.StatusSeeOther)
}

// loadAccessibleCA wraps the GetCA + ownership check used by every
// detail / mutating handler. Writes the appropriate response (404 /
// 403) directly and returns ok=false on failure.
func (w *Web) loadAccessibleCA(rw http.ResponseWriter, r *http.Request) (*models.CA, bool) {
	id := chi.URLParam(r, "id")
	c, err := w.store.GetCA(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(rw, "CA not found", http.StatusNotFound)
		return nil, false
	}
	if err != nil {
		w.logger.Error("get ca", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return nil, false
	}
	op := w.session.CurrentOperator(r)
	if op == nil {
		http.Redirect(rw, r, "/ui/login", http.StatusSeeOther)
		return nil, false
	}
	if op.Role != "admin" && c.OwnerOperatorID != op.ID {
		http.Error(rw, "you do not own this CA", http.StatusForbidden)
		return nil, false
	}
	return c, true
}
