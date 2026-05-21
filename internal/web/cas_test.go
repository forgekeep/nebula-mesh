package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/juev/nebula-mesh/internal/models"
)

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

	req := httptest.NewRequest(http.MethodPost, "/ui/cas/"+ca.ID+"/retire", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
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

	form := url.Values{"name": {"new-ca"}, "duration": {"8760h"}}
	req := httptest.NewRequest(http.MethodPost, "/ui/cas", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("create without master: status = %d, want 200 (inline error)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "NEBULA_MGMT_MASTER_KEY") {
		t.Errorf("expected master-key hint in body, got %s", rec.Body.String())
	}
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
	req := httptest.NewRequest(http.MethodPost, "/ui/cas/"+oldCA.ID+"/rotate", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
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
