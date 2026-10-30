package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// Host and CA names go into Nebula v2 certificates, which Nebula cannot sign
// or load past models.MaxCertNameLen bytes. The UI used to accept any length.

func TestHostCreate_RejectsNameOverCertLimit(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)
	if err := s.CreateNetwork(context.Background(), &models.Network{
		ID: "n-long", Name: "n", CIDRs: []string{"10.0.0.0/24"}, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	rec := createHostViaForm(t, w, cookies, "n-long", strings.Repeat("a", models.MaxCertNameLen+1), "10.0.0.10")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "at most 253 bytes") {
		t.Errorf("body should name the limit; got:\n%s", rec.Body.String())
	}

	if rec := createHostViaForm(t, w, cookies, "n-long", strings.Repeat("a", models.MaxCertNameLen), "10.0.0.11"); rec.Code != http.StatusOK {
		t.Fatalf("name at limit: status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostUpdate_RejectsNameOverCertLimit(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)
	seedHostWithGroups(t, s, []string{})

	csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/hosts/h-1/edit", cookies)
	form := url.Values{
		"network_id": {"n-1"},
		"name":       {strings.Repeat("a", models.MaxCertNameLen+1)},
		"nebula_ips": {"192.168.100.10"},
		"role":       {"host"},
		"_csrf":      {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/hosts/h-1/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range updatedCookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	host, err := s.GetHost(context.Background(), "h-1")
	if err != nil {
		t.Fatal(err)
	}
	if host.Name != "web-1" {
		t.Errorf("host name = %q, want unchanged web-1", host.Name)
	}
}

func TestHandleCACreate_RejectsNameOverCertLimit(t *testing.T) {
	w, s := newOperatorsWebWithMaster(t)
	cookie := mintSession(t, s, "frank", "user")

	csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/cas", []*http.Cookie{cookie})
	form := url.Values{
		"name":     {strings.Repeat("a", models.MaxCertNameLen+1)},
		"duration": {"8760h"},
		"_csrf":    {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/cas", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range updatedCookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code == http.StatusSeeOther {
		t.Fatalf("oversized CA name was accepted, redirect to %q", rec.Header().Get("Location"))
	}
	if !strings.Contains(rec.Body.String(), "at most 253 bytes") {
		t.Errorf("body should name the limit; got:\n%s", rec.Body.String())
	}
}

// The default CA is named "<username>-default"; a long username must still
// produce a signable name instead of failing the first sign-in.
func TestProvisionDefaultCA_LongUsername(t *testing.T) {
	w, s := newOperatorsWebWithMaster(t)
	ctx := context.Background()
	op := &models.Operator{
		ID:           "op-long",
		Username:     strings.Repeat("u", models.MaxCertNameLen),
		PasswordHash: "x",
		Status:       models.OperatorStatusActive,
		Role:         "user",
		AuthProvider: models.OperatorAuthLocal,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	if err := s.CreateOperator(ctx, op); err != nil {
		t.Fatal(err)
	}

	if err := w.provisionDefaultCA(ctx, op); err != nil {
		t.Fatalf("provisionDefaultCA = %v, want nil", err)
	}
	cas, err := s.ListCAsByOwner(ctx, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(cas) != 1 {
		t.Fatalf("ListCAsByOwner returned %d CA(s), want 1", len(cas))
	}
	if name := cas[0].Name; len(name) != models.MaxCertNameLen || !strings.HasSuffix(name, "-default") {
		t.Errorf("CA name = %q (%d bytes), want %d bytes ending in -default", name, len(name), models.MaxCertNameLen)
	}
}
