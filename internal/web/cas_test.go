package web

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/pki"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

// TestRedirectCAError_EscapesMessage verifies that store-layer error text is
// URL-escaped before it is placed in the redirect query string (#194), so
// URL-significant characters (a network name with '#', '&', spaces) cannot
// truncate or split the redirect target — and that the message still
// round-trips back to the original via Query().Get.
func TestRedirectCAError_EscapesMessage(t *testing.T) {
	const msg = "Conflict: still attached to net#1 & net 2"
	rw := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/ui/cas/abc/delete", nil)

	redirectCAError(rw, r, "abc", msg)

	loc := rw.Header().Get("Location")
	if strings.ContainsAny(loc, "# ") || strings.Contains(loc, "&") {
		t.Fatalf("unescaped URL-significant char leaked into Location: %q", loc)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("Location is not a valid URL: %v", err)
	}
	if got := u.Query().Get("error"); got != msg {
		t.Fatalf("error param round-trip mismatch: got %q, want %q", got, msg)
	}
}

func TestCAs_NonOwner_Forbidden(t *testing.T) {
	w, s := newOperatorsWeb(t)
	aliceCookie := mintSession(t, s, "alice", "user")
	bobCookie := mintSession(t, s, "bob", "user")

	// Bob mints a CA via the store directly so the test stays focused on
	// the ownership check, not on the master-key plumbing.
	ca := &models.CA{
		ID:                   "ca-bob",
		Name:                 "bob-ca",
		OwnerOperatorID:      "op-bob",
		CertPEM:              "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----",
		Fingerprint:          "fp-bob",
		NotBefore:            time.Now(),
		NotAfter:             time.Now().Add(time.Hour),
		Status:               models.CAStatusActive,
		EncryptedKeyDEK:      []byte("dek"),
		NonceDEK:             []byte("ndek"),
		EncryptedKeyMaterial: []byte("key"),
		NonceKey:             []byte("nkey"),
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	}
	if err := s.CreateCA(context.Background(), ca); err != nil {
		t.Fatal(err)
	}

	// Alice (not the owner, not admin) gets 403.
	req := httptest.NewRequest(http.MethodGet, "/ui/cas/"+ca.ID, nil)
	req.AddCookie(aliceCookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("alice GET ca: status = %d, want 403", rec.Code)
	}

	// Bob (owner) gets 200.
	req = httptest.NewRequest(http.MethodGet, "/ui/cas/"+ca.ID, nil)
	req.AddCookie(bobCookie)
	rec = httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("bob GET own ca: status = %d, want 200", rec.Code)
	}
}

func TestCAs_List_FiltersByOwnership(t *testing.T) {
	w, s := newOperatorsWeb(t)
	aliceCookie := mintSession(t, s, "alice", "user")
	adminCookie := mintSession(t, s, "root", "admin")
	mintSession(t, s, "bob", "user") // FK target for the CA below

	for _, c := range []models.CA{
		{ID: "ca1", Name: "alice-ca", OwnerOperatorID: "op-alice", Fingerprint: "fp-alice", NotAfter: time.Now().Add(time.Hour), Status: models.CAStatusActive, EncryptedKeyDEK: []byte("d"), NonceDEK: []byte("nd"), EncryptedKeyMaterial: []byte("k"), NonceKey: []byte("nk"), CreatedAt: time.Now(), UpdatedAt: time.Now()},
		{ID: "ca2", Name: "bob-ca", OwnerOperatorID: "op-bob", Fingerprint: "fp-bob", NotAfter: time.Now().Add(time.Hour), Status: models.CAStatusActive, EncryptedKeyDEK: []byte("d"), NonceDEK: []byte("nd"), EncryptedKeyMaterial: []byte("k"), NonceKey: []byte("nk"), CreatedAt: time.Now(), UpdatedAt: time.Now()},
	} {
		if err := s.CreateCA(context.Background(), &c); err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/ui/cas", nil)
	req.AddCookie(aliceCookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, "alice-ca") {
		t.Errorf("alice list: own CA missing\n%s", body)
	}
	if strings.Contains(body, "bob-ca") {
		t.Errorf("alice list: must not see bob's CA")
	}

	req = httptest.NewRequest(http.MethodGet, "/ui/cas", nil)
	req.AddCookie(adminCookie)
	rec = httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	body = rec.Body.String()
	if !strings.Contains(body, "alice-ca") || !strings.Contains(body, "bob-ca") {
		t.Errorf("admin list should show both CAs\n%s", body)
	}
}

func TestCAs_Retire_FlipsStatus(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "bob", "user")

	ca := &models.CA{
		ID: "ca-r", Name: "to-retire", OwnerOperatorID: "op-bob",
		Fingerprint: "fp-r", NotAfter: time.Now().Add(time.Hour),
		Status: models.CAStatusActive, EncryptedKeyDEK: []byte("d"), NonceDEK: []byte("nd"), EncryptedKeyMaterial: []byte("k"), NonceKey: []byte("nk"), CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateCA(context.Background(), ca); err != nil {
		t.Fatal(err)
	}

	csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/cas/"+ca.ID, []*http.Cookie{cookie})
	req := httptest.NewRequest(http.MethodPost, "/ui/cas/"+ca.ID+"/retire", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", csrfToken)
	for _, c := range updatedCookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("retire: status = %d, want 303", rec.Code)
	}

	got, err := s.GetCA(context.Background(), ca.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != models.CAStatusRetired {
		t.Errorf("status = %q, want retired", got.Status)
	}
}

func TestCAs_New_WithoutMaster_InlineError(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "bob", "user")

	csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/cas", []*http.Cookie{cookie})
	form := url.Values{"name": {"new-ca"}, "duration": {"8760h"}, "_csrf": {csrfToken}}
	req := httptest.NewRequest(http.MethodPost, "/ui/cas", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range updatedCookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("create without master: status = %d, want 200 (inline error)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "NEBULA_MGMT_MASTER_KEY") {
		t.Errorf("expected master-key hint in body, got %s", rec.Body.String())
	}
}

func TestCAImport_WebSuccessOwnershipAndAudit(t *testing.T) {
	w, s := newOperatorsWebWithMaster(t)
	cookie := mintSession(t, s, "bob", "user")
	csrfToken, cookies := getCSRFTokenFromCookies(t, w, "/ui/cas/import", []*http.Cookie{cookie})
	body, contentType := webCAImportMultipart(t, "existing-mesh", csrfToken)
	req := httptest.NewRequest(http.MethodPost, "/ui/cas/import", bytes.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	req.TLS = &tls.ConnectionState{}
	for _, currentCookie := range cookies {
		req.AddCookie(currentCookie)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body=%s", rec.Code, rec.Body.String())
	}

	cas, err := s.ListCAsByOwner(context.Background(), "op-bob")
	if err != nil {
		t.Fatal(err)
	}
	if len(cas) != 1 || cas[0].Name != "existing-mesh" {
		t.Fatalf("imported CAs = %+v", cas)
	}
	if rec.Header().Get("Location") != "/ui/cas/"+cas[0].ID {
		t.Fatalf("redirect = %q", rec.Header().Get("Location"))
	}
	entries, err := s.ListAuditEntries(context.Background(), store.AuditFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Action == "ca.imported" && entry.Resource == cas[0].ID && entry.Details == "fingerprint="+cas[0].Fingerprint {
			return
		}
	}
	t.Fatal("ca.imported audit entry not found")
}

func TestCAImport_WebTransportCSRFAndBodyLimit(t *testing.T) {
	t.Run("insecure transport rejected before body read", func(t *testing.T) {
		w, s := newOperatorsWebWithMaster(t)
		cookie := mintSession(t, s, "bob", "user")
		body := &webCountingReader{}
		req := httptest.NewRequest(http.MethodPost, "/ui/cas/import", body)
		req.Header.Set("Content-Type", "multipart/form-data; boundary=x")
		req.RemoteAddr = "203.0.113.5:1234"
		req.Host = "mesh.example.com"
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		w.ServeHTTP(rec, req)
		if rec.Code != http.StatusUpgradeRequired {
			t.Fatalf("status = %d, want 426", rec.Code)
		}
		if body.reads != 0 {
			t.Fatalf("body read %d time(s)", body.reads)
		}
	})

	t.Run("missing CSRF", func(t *testing.T) {
		w, s := newOperatorsWebWithMaster(t)
		cookie := mintSession(t, s, "bob", "user")
		body, contentType := webCAImportMultipart(t, "existing-mesh", "")
		req := httptest.NewRequest(http.MethodPost, "/ui/cas/import", bytes.NewReader(body))
		req.Header.Set("Content-Type", contentType)
		req.TLS = &tls.ConnectionState{}
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		w.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
	})

	t.Run("body over global limit", func(t *testing.T) {
		w, _ := newOperatorsWebWithMaster(t)
		req := httptest.NewRequest(http.MethodPost, "/ui/cas/import", bytes.NewReader(make([]byte, (1<<20)+1)))
		req.Header.Set("Content-Type", "multipart/form-data; boundary=x")
		req.TLS = &tls.ConnectionState{}
		rec := httptest.NewRecorder()
		w.ServeHTTP(rec, req)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413", rec.Code)
		}
	})
}

func TestCAImport_WebDuplicateRendersConflict(t *testing.T) {
	w, s := newOperatorsWebWithMaster(t)
	cookie := mintSession(t, s, "bob", "user")
	manager, err := pki.NewCA("existing-mesh", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Wipe()
	certificatePEM, err := manager.CACertPEM()
	if err != nil {
		t.Fatal(err)
	}
	privateKeyPEM := cert.MarshalSigningPrivateKeyToPEM(cert.Curve_CURVE25519, manager.RawKey())

	post := func() *httptest.ResponseRecorder {
		csrfToken, cookies := getCSRFTokenFromCookies(t, w, "/ui/cas/import", []*http.Cookie{cookie})
		body, contentType := webCAImportMultipartMaterial(t, "existing-mesh", csrfToken, certificatePEM, privateKeyPEM)
		req := httptest.NewRequest(http.MethodPost, "/ui/cas/import", bytes.NewReader(body))
		req.Header.Set("Content-Type", contentType)
		req.TLS = &tls.ConnectionState{}
		for _, currentCookie := range cookies {
			req.AddCookie(currentCookie)
		}
		rec := httptest.NewRecorder()
		w.ServeHTTP(rec, req)
		return rec
	}
	if first := post(); first.Code != http.StatusSeeOther {
		t.Fatalf("first status = %d; body=%s", first.Code, first.Body.String())
	}
	second := post()
	if second.Code != http.StatusConflict || !strings.Contains(second.Body.String(), "already imported") {
		t.Fatalf("duplicate status = %d; body=%s", second.Code, second.Body.String())
	}
}

type webCountingReader struct{ reads int }

func (r *webCountingReader) Read(_ []byte) (int, error) {
	r.reads++
	return 0, io.EOF
}

func webCAImportMultipart(t *testing.T, name, csrfToken string) ([]byte, string) {
	t.Helper()
	manager, err := pki.NewCA(name, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Wipe()
	certificatePEM, err := manager.CACertPEM()
	if err != nil {
		t.Fatal(err)
	}
	privateKeyPEM := cert.MarshalSigningPrivateKeyToPEM(cert.Curve_CURVE25519, manager.RawKey())
	return webCAImportMultipartMaterial(t, name, csrfToken, certificatePEM, privateKeyPEM)
}

func webCAImportMultipartMaterial(t *testing.T, name, csrfToken string, certificatePEM, privateKeyPEM []byte) ([]byte, string) {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("name", name); err != nil {
		t.Fatal(err)
	}
	if csrfToken != "" {
		if err := writer.WriteField("_csrf", csrfToken); err != nil {
			t.Fatal(err)
		}
	}
	certificatePart, err := writer.CreateFormFile("certificate", "ca.crt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := certificatePart.Write(certificatePEM); err != nil {
		t.Fatal(err)
	}
	keyPart, err := writer.CreateFormFile("private_key", "ca.key")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keyPart.Write(privateKeyPEM); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return body.Bytes(), writer.FormDataContentType()
}

// Task 5.1 + 5.2: Test warning badge rendering when CA is expiring soon.
func TestCAs_List_RendersExpiryWarning(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "bob", "user")

	// Create a CA with NotBefore 9 years ago and NotAfter 1 year from now.
	// This gives total lifetime = 10 years, remaining = 1 year, so ratio = 0.10 < 0.20 threshold.
	now := time.Now()
	ca := &models.CA{
		ID: "ca-expiring", Name: "ca-expiring", OwnerOperatorID: "op-bob",
		CertPEM:         "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----",
		Fingerprint:     "fp-expiring",
		NotBefore:       now.AddDate(-9, 0, 0),
		NotAfter:        now.AddDate(1, 0, 0),
		Status:          models.CAStatusActive,
		EncryptedKeyDEK: []byte("d"), NonceDEK: []byte("nd"),
		EncryptedKeyMaterial: []byte("k"), NonceKey: []byte("nk"),
		CreatedAt: now, UpdatedAt: now,
	}
	if err := s.CreateCA(context.Background(), ca); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/ui/cas", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /ui/cas: status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Expires soon") {
		t.Errorf("expiring CA list: expected warning badge 'Expires soon', got body:\n%s", body)
	}
}

// Task 5.2: Test no warning badge for fresh CA.
func TestCAs_List_NoWarningForFreshCA(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "bob", "user")

	// Fresh CA: NotAfter 10 years from now, NotBefore now.
	// Remaining = 10 years, total = 10 years, ratio = 1.0 > 0.20 threshold.
	now := time.Now()
	ca := &models.CA{
		ID: "ca-fresh", Name: "ca-fresh", OwnerOperatorID: "op-bob",
		CertPEM:         "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----",
		Fingerprint:     "fp-fresh",
		NotBefore:       now,
		NotAfter:        now.AddDate(10, 0, 0),
		Status:          models.CAStatusActive,
		EncryptedKeyDEK: []byte("d"), NonceDEK: []byte("nd"),
		EncryptedKeyMaterial: []byte("k"), NonceKey: []byte("nk"),
		CreatedAt: now, UpdatedAt: now,
	}
	if err := s.CreateCA(context.Background(), ca); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/ui/cas", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /ui/cas: status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "Expires soon") {
		t.Errorf("fresh CA list: should NOT have warning badge, got body:\n%s", body)
	}
}

// Task 5.3: Test rotate handler creates successor CA and redirects.
func TestCAs_Rotate_CreatesSuccessor(t *testing.T) {
	w, s := newOperatorsWebWithMaster(t)
	cookie := mintSession(t, s, "bob", "user")

	// Create an active CA owned by bob.
	now := time.Now()
	oldCA := &models.CA{
		ID: "ca-old", Name: "ca-old", OwnerOperatorID: "op-bob",
		CertPEM:         "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----",
		Fingerprint:     "fp-old",
		NotBefore:       now.AddDate(-5, 0, 0),
		NotAfter:        now.AddDate(5, 0, 0),
		Status:          models.CAStatusActive,
		EncryptedKeyDEK: []byte("d"), NonceDEK: []byte("nd"),
		EncryptedKeyMaterial: []byte("k"), NonceKey: []byte("nk"),
		CreatedAt: now, UpdatedAt: now,
	}
	if err := s.CreateCA(context.Background(), oldCA); err != nil {
		t.Fatal(err)
	}

	// POST /ui/cas/{id}/rotate
	csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/cas/"+oldCA.ID, []*http.Cookie{cookie})
	req := httptest.NewRequest(http.MethodPost, "/ui/cas/"+oldCA.ID+"/rotate", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", csrfToken)
	for _, c := range updatedCookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("rotate: status = %d, want 303 (redirect)", rec.Code)
	}

	// Extract redirect URL
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/ui/cas/") {
		t.Fatalf("rotate redirect: expected /ui/cas/*, got %s", loc)
	}

	// Verify DB now has 2 CAs with predecessor link.
	allCAs, err := s.ListCAsByOwner(context.Background(), "op-bob")
	if err != nil {
		t.Fatal(err)
	}
	if len(allCAs) != 2 {
		t.Fatalf("after rotate: expected 2 CAs, got %d", len(allCAs))
	}

	// Find the new CA (the one created in rotation).
	var newCA *models.CA
	for _, ca := range allCAs {
		if ca.ID != oldCA.ID {
			newCA = ca
			break
		}
	}
	if newCA == nil {
		t.Fatal("new CA not found after rotate")
		return
	}

	// Verify predecessor_id is set to oldCA.ID.
	if newCA.PredecessorID == nil || *newCA.PredecessorID != oldCA.ID {
		t.Errorf("new CA predecessor_id = %v, want %q", newCA.PredecessorID, oldCA.ID)
	}
}

// Task 5.3: Test non-owner cannot rotate CA.
func TestCAs_Rotate_NonOwner_Forbidden(t *testing.T) {
	w, s := newOperatorsWebWithMaster(t)
	aliceCookie := mintSession(t, s, "alice", "user")
	mintSession(t, s, "bob", "user")

	now := time.Now()
	ca := &models.CA{
		ID: "ca-bob", Name: "ca-bob", OwnerOperatorID: "op-bob",
		CertPEM:         "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----",
		Fingerprint:     "fp-bob",
		NotBefore:       now.AddDate(-5, 0, 0),
		NotAfter:        now.AddDate(5, 0, 0),
		Status:          models.CAStatusActive,
		EncryptedKeyDEK: []byte("d"), NonceDEK: []byte("nd"),
		EncryptedKeyMaterial: []byte("k"), NonceKey: []byte("nk"),
		CreatedAt: now, UpdatedAt: now,
	}
	if err := s.CreateCA(context.Background(), ca); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/ui/cas/"+ca.ID+"/rotate", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(aliceCookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("rotate non-owned CA: status = %d, want 403", rec.Code)
	}
}
