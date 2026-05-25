package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// TestWebHosts_NonAdminNotUndercountedPastLimit reproduces #157 on the web side:
// with more hosts under CAs the operator does NOT own than accessibleHosts'
// 1000-row query cap, the operator's own host (sorting after that window) must
// still appear in /ui/hosts. Previously accessibleHosts applied the owned-CA
// filter in Go AFTER the SQL LIMIT, so the owner's host was dropped from the
// window before the filter ran and the operator silently saw fewer hosts than
// they owned. Mirrors the API-side TestListHosts_NonAdminNotUndercountedPastLimit.
func TestWebHosts_NonAdminNotUndercountedPastLimit(t *testing.T) {
	w, s := newSettingsWeb(t)
	ctx := t.Context()

	bob := authedSession(t, s, "bob", "user")
	// bob owns ca-b / net-b / host-b (name "host-b" sorts after "aaa-*").
	seedTenant(t, s, "op-bob", "b")

	// 1001 foreign hosts under a CA bob does NOT own, with names that sort
	// before "host-b", so a global "ORDER BY name LIMIT 1000" fills the whole
	// window with them and drops host-b.
	if err := s.CreateNetwork(ctx, &models.Network{
		ID: "n-foreign", Name: "n-foreign", CIDRs: []string{"10.9.0.0/24"}, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1001; i++ {
		if err := s.CreateHost(ctx, &models.Host{
			ID: fmt.Sprintf("hf-%04d", i), NetworkID: "n-foreign", CAID: "ca-foreign",
			Name: fmt.Sprintf("aaa-%04d", i), Role: models.HostRoleHost, Status: models.HostStatusPending,
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}); err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/ui/hosts", nil)
	req.AddCookie(bob)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("hosts list: status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "host-b") {
		t.Error("bob's own host dropped by LIMIT before ownership scoping (undercount)")
	}
	if strings.Contains(body, "aaa-") {
		t.Error("foreign hosts must not leak to a non-owner")
	}
}
