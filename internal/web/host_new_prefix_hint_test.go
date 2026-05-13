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
		{ID: "n-24", Name: "small", CIDR: "10.42.0.0/24", CreatedAt: time.Now()},
		{ID: "n-16", Name: "medium", CIDR: "172.20.0.0/16", CreatedAt: time.Now()},
		{ID: "n-12", Name: "odd", CIDR: "10.0.0.0/12", CreatedAt: time.Now()},
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
		if !strings.Contains(body, `data-cidr="`+n.CIDR+`"`) {
			t.Errorf("missing data-cidr=%q on option for network %s", n.CIDR, n.Name)
		}
	}

	// The hint element + the prefill JS hook must be present.
	if !strings.Contains(body, `id="nebula-ip-hint"`) {
		t.Errorf(`body should contain id="nebula-ip-hint"`)
	}
	if !strings.Contains(body, `id="network-select"`) {
		t.Errorf(`body should contain id="network-select"`)
	}
	if !strings.Contains(body, `id="nebula-ip-input"`) {
		t.Errorf(`body should contain id="nebula-ip-input"`)
	}
	// The JS must include the byte-aligned-prefix routine so refactors
	// don't silently drop it.
	if !strings.Contains(body, "computeByteAlignedPrefix") {
		t.Errorf("body should contain the computeByteAlignedPrefix JS helper")
	}
}
