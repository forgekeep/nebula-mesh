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
		ID:              "ca-bob",
		Name:            "bob-ca",
		OwnerOperatorID: "op-bob",
		CertPEM:         "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----",
		Fingerprint:     "fp-bob",
		NotBefore:       time.Now(),
		NotAfter:        time.Now().Add(time.Hour),
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
		{ID: "ca2", Name: "bob-ca",   OwnerOperatorID: "op-bob",   Fingerprint: "fp-bob",   NotAfter: time.Now().Add(time.Hour), Status: models.CAStatusActive, EncryptedKeyDEK: []byte("d"), NonceDEK: []byte("nd"), EncryptedKeyMaterial: []byte("k"), NonceKey: []byte("nk"), CreatedAt: time.Now(), UpdatedAt: time.Now()},
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
