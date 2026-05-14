package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/juev/nebula-mesh/internal/models"
)

// TestHostNewForm_NetworkOptionsHaveDataCIDR — issue #92. The network
// <option> elements must carry data-cidr so the client-side prefill JS
// can read the CIDR per option without round-tripping to the server.
func TestHostNewForm_NetworkOptionsHaveDataCIDR(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	ctx := context.Background()
	nets := []*models.Network{
		{ID: "n-24", Name: "small", CIDRs: []string{"10.42.0.0/24"}, CreatedAt: time.Now()},
		{ID: "n-16", Name: "medium", CIDRs: []string{"172.20.0.0/16"}, CreatedAt: time.Now()},
		{ID: "n-12", Name: "odd", CIDRs: []string{"10.0.0.0/12"}, CreatedAt: time.Now()},
	}
	for _, n := range nets {
		if err := s.CreateNetwork(ctx, n); err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest("GET", "/ui/hosts/new", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()

	for _, n := range nets {
		// data-cidrs now contains semicolon-separated list of CIDRs
		expectedCIDRs := strings.Join(n.CIDRs, ";")
		if !strings.Contains(body, `data-cidrs="`+expectedCIDRs+`"`) {
			t.Errorf("missing data-cidrs=%q on option for network %s", expectedCIDRs, n.Name)
		}
	}

	// The rows container and row add/remove handlers must be present (new repeatable rows design).
	if !strings.Contains(body, `id="nebula-ip-rows"`) {
		t.Errorf(`body should contain id="nebula-ip-rows" for repeatable IP rows`)
	}
	if !strings.Contains(body, `data-action="add-ip"`) {
		t.Errorf(`body should contain add-ip button`)
	}
	if !strings.Contains(body, `id="network-select"`) {
		t.Errorf(`body should contain id="network-select"`)
	}
	// The row remove buttons.
	if !strings.Contains(body, `data-action="remove"`) {
		t.Errorf(`body should contain remove button for rows`)
	}
}
