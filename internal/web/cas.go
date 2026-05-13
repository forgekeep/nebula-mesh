package web

import (
	"errors"
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

// CAMaster is the slim interface the Web UI needs from the keystore to
// wrap a freshly-generated CA key for storage. Mirrors the methods the
// API server uses; supplied by the same *keystore.Master singleton.
type CAMaster interface {
	GenerateDEK() (dek []byte, wrapped keystore.WrappedKey, err error)
}

// WithMaster wires the keystore master the CA-create handler needs.
// Without it, /ui/cas/new renders an inline error pointing at the
// NEBULA_MGMT_MASTER_KEY docs instead of failing with a 500.
func (w *Web) WithMaster(m CAMaster) { w.caMaster = m }

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
	w.renderForRequest(rw, r, "cas_list.html", map[string]any{
		"Active":  "cas",
		"CAs":     cas,
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

	mgr, _, err := pki.NewCA(name, dur)
	if err != nil {
		w.logger.Error("generate ca", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	rawKey := mgr.RawKey()
	defer keystore.Zeroize(rawKey)

	dek, wrappedDEK, err := w.caMaster.GenerateDEK()
	if err != nil {
		w.logger.Error("generate dek", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	defer keystore.Zeroize(dek)
	wrappedKey, err := keystore.SealWithDEK(dek, rawKey)
	if err != nil {
		w.logger.Error("seal ca key", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	certPEM, err := mgr.CACertPEM()
	if err != nil {
		w.logger.Error("marshal ca cert", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	fp, err := mgr.CACertFingerprint()
	if err != nil {
		w.logger.Error("fingerprint ca cert", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	now := time.Now()
	c := &models.CA{
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
	if err := w.store.CreateCA(r.Context(), c); err != nil {
		w.logger.Error("create ca", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	_ = w.store.AddAuditEntry(r.Context(), op.Username, "ca.created", c.ID, c.Name)
	http.Redirect(rw, r, "/ui/cas/"+c.ID, http.StatusSeeOther)
}

func (w *Web) handleCADetail(rw http.ResponseWriter, r *http.Request) {
	c, ok := w.loadAccessibleCA(rw, r)
	if !ok {
		return
	}
	w.renderForRequest(rw, r, "ca_detail.html", map[string]any{
		"Active": "cas",
		"CA":     c,
		"Error":  r.URL.Query().Get("error"),
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
