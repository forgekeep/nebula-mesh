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
	"github.com/juev/nebula-mesh/internal/store"
)

func TestHostEdit_GET_NotFound(t *testing.T) {
	w, _ := newTestWeb(t)
	cookies := loginSession(t, w)

	req := httptest.NewRequest(http.MethodGet, "/ui/hosts/unknown-id/edit", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestHostEdit_GET_AsAdmin(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	ctx := context.Background()
	network := &models.Network{
		ID:        "n-1",
		Name:      "test-net",
		CIDRs:     []string{"192.168.100.0/24"},
		CreatedAt: time.Now(),
	}
	if err := s.CreateNetwork(ctx, network); err != nil {
		t.Fatal(err)
	}

	host := &models.Host{
		ID:         "h-1",
		NetworkID:  "n-1",
		Name:       "web-1",
		NebulaIPs:  []string{"192.168.100.10"},
		Groups:     []string{"web", "prod"},
		Role:       models.HostRoleHost,
		PublicIP:   "203.0.113.1",
		ListenPort: 4242,
		Status:     models.HostStatusEnrolled,
		Advanced: &models.HostAdvanced{
			MTU:        1300,
			ListenHost: "0.0.0.0",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, host); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/ui/hosts/h-1/edit", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()

	// Verify form action points to POST handler
	if !strings.Contains(body, `action="/ui/hosts/h-1/edit"`) {
		t.Error("form action should point to /ui/hosts/{id}/edit")
	}

	// Verify form carries existing values
	if !strings.Contains(body, `value="web-1"`) {
		t.Error("form should preserve host name")
	}

	if !strings.Contains(body, `value="192.168.100.10"`) {
		t.Error("form should preserve nebula_ip")
	}

	if !strings.Contains(body, `value="1300"`) {
		t.Error("form should preserve MTU value")
	}

	// Verify role select has correct selected
	if !strings.Contains(body, `<option value="host" selected`) {
		t.Error("form should have role=host selected")
	}
}

func TestHostUpdate_POST_HappyPath_Advanced(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	ctx := context.Background()
	network := &models.Network{
		ID:        "n-1",
		Name:      "test-net",
		CIDRs:     []string{"192.168.100.0/24"},
		CreatedAt: time.Now(),
	}
	if err := s.CreateNetwork(ctx, network); err != nil {
		t.Fatal(err)
	}

	host := &models.Host{
		ID:        "h-1",
		NetworkID: "n-1",
		Name:      "web-1",
		NebulaIPs: []string{"192.168.100.10"},
		Groups:    []string{},
		Role:      models.HostRoleHost,
		Status:    models.HostStatusEnrolled,
		Advanced: &models.HostAdvanced{
			MTU: 1300,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, host); err != nil {
		t.Fatal(err)
	}

	// POST with MTU changed
	form := url.Values{
		"network_id": {"n-1"},
		"name":       {"web-1"},
		"nebula_ips": {"192.168.100.10"},
		"role":       {"host"},
		"adv_mtu":    {"1280"},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/hosts/h-1/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want 303", rec.Code)
	}

	if loc := rec.Header().Get("Location"); loc != "/ui/hosts/h-1" {
		t.Errorf("redirect location = %s, want /ui/hosts/h-1", loc)
	}

	// Verify host was updated
	updated, err := s.GetHost(ctx, "h-1")
	if err != nil {
		t.Fatal(err)
	}
	if updated.Advanced.MTU != 1280 {
		t.Errorf("MTU = %d, want 1280", updated.Advanced.MTU)
	}

	// Verify audit entry was created
	entries, err := s.ListAuditEntries(ctx, store.AuditFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	updateEntries := make([]*models.AuditEntry, 0)
	for _, e := range entries {
		if e.Action == "host.update" {
			updateEntries = append(updateEntries, e)
		}
	}
	if len(updateEntries) != 1 {
		t.Errorf("audit entries with host.update = %d, want 1", len(updateEntries))
	}
	if updateEntries[0].Details == "" {
		t.Error("audit entry Details should contain JSON diff")
	}
	if !strings.Contains(updateEntries[0].Details, "advanced.mtu") {
		t.Error("audit entry should contain advanced.mtu in diff")
	}
}

func TestHostUpdate_POST_HappyPath_Rename(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	ctx := context.Background()
	network := &models.Network{
		ID:        "n-1",
		Name:      "test-net",
		CIDRs:     []string{"192.168.100.0/24"},
		CreatedAt: time.Now(),
	}
	if err := s.CreateNetwork(ctx, network); err != nil {
		t.Fatal(err)
	}

	host := &models.Host{
		ID:        "h-1",
		NetworkID: "n-1",
		Name:      "web-1",
		NebulaIPs: []string{"192.168.100.10"},
		Groups:    []string{},
		Role:      models.HostRoleHost,
		Status:    models.HostStatusEnrolled,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, host); err != nil {
		t.Fatal(err)
	}

	// POST with name changed
	form := url.Values{
		"network_id": {"n-1"},
		"name":       {"web-2"},
		"nebula_ips": {"192.168.100.10"},
		"role":       {"host"},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/hosts/h-1/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want 303", rec.Code)
	}

	// Verify host was updated
	updated, err := s.GetHost(ctx, "h-1")
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "web-2" {
		t.Errorf("Name = %s, want web-2", updated.Name)
	}

	// Verify PendingRekey was set (cert change on name rename)
	if !updated.PendingRekey {
		t.Error("PendingRekey should be true after name change")
	}
}

func TestHostUpdate_POST_InvalidMTU(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	ctx := context.Background()
	network := &models.Network{
		ID:        "n-1",
		Name:      "test-net",
		CIDRs:     []string{"192.168.100.0/24"},
		CreatedAt: time.Now(),
	}
	if err := s.CreateNetwork(ctx, network); err != nil {
		t.Fatal(err)
	}

	host := &models.Host{
		ID:        "h-1",
		NetworkID: "n-1",
		Name:      "web-1",
		NebulaIPs: []string{"192.168.100.10"},
		Groups:    []string{},
		Role:      models.HostRoleHost,
		Status:    models.HostStatusEnrolled,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, host); err != nil {
		t.Fatal(err)
	}

	// POST with invalid MTU
	form := url.Values{
		"network_id": {"n-1"},
		"name":       {"web-1"},
		"nebula_ips": {"192.168.100.10"},
		"role":       {"host"},
		"adv_mtu":    {"99999"},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/hosts/h-1/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "99999") {
		t.Error("form should preserve submitted value on error")
	}
}

func TestHostUpdate_POST_RoleFlipToLighthouse_BumpsNetwork(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	ctx := context.Background()
	network := &models.Network{
		ID:        "n-1",
		Name:      "test-net",
		CIDRs:     []string{"192.168.100.0/24"},
		CreatedAt: time.Now(),
	}
	if err := s.CreateNetwork(ctx, network); err != nil {
		t.Fatal(err)
	}

	host := &models.Host{
		ID:        "h-1",
		NetworkID: "n-1",
		Name:      "web-1",
		NebulaIPs: []string{"192.168.100.10"},
		Groups:    []string{},
		Role:      models.HostRoleHost,
		Status:    models.HostStatusEnrolled,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, host); err != nil {
		t.Fatal(err)
	}

	initialVer, err := s.GetNetworkConfigVersion(ctx, "n-1")
	if err != nil {
		t.Fatal(err)
	}

	// POST with role changed to lighthouse
	form := url.Values{
		"network_id":  {"n-1"},
		"name":        {"web-1"},
		"nebula_ips":  {"192.168.100.10"},
		"role":        {"lighthouse"},
		"public_ip":   {"203.0.113.1"},
		"listen_port": {"4242"},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/hosts/h-1/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want 303", rec.Code)
	}

	// Verify network config version was bumped
	newVer, err := s.GetNetworkConfigVersion(ctx, "n-1")
	if err != nil {
		t.Fatal(err)
	}
	if newVer <= initialVer {
		t.Errorf("network config version = %d, want > %d (bumped on role change)", newVer, initialVer)
	}
}

func TestHostUpdate_POST_NoChanges_NoAudit(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	ctx := context.Background()
	network := &models.Network{
		ID:        "n-1",
		Name:      "test-net",
		CIDRs:     []string{"192.168.100.0/24"},
		CreatedAt: time.Now(),
	}
	if err := s.CreateNetwork(ctx, network); err != nil {
		t.Fatal(err)
	}

	host := &models.Host{
		ID:        "h-1",
		NetworkID: "n-1",
		Name:      "web-1",
		NebulaIPs: []string{"192.168.100.10"},
		Groups:    []string{},
		Role:      models.HostRoleHost,
		Status:    models.HostStatusEnrolled,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, host); err != nil {
		t.Fatal(err)
	}

	// POST with no changes
	form := url.Values{
		"network_id": {"n-1"},
		"name":       {"web-1"},
		"nebula_ips": {"192.168.100.10"},
		"role":       {"host"},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/hosts/h-1/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want 303 (idempotent redirect)", rec.Code)
	}

	// Verify no audit entry was created
	entries, err := s.ListAuditEntries(ctx, store.AuditFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	updateEntries := make([]*models.AuditEntry, 0)
	for _, e := range entries {
		if e.Action == "host.update" {
			updateEntries = append(updateEntries, e)
		}
	}
	if len(updateEntries) != 0 {
		t.Errorf("audit entries with host.update = %d, want 0 (no changes)", len(updateEntries))
	}
}

func TestHostUpdate_POST_DuplicateIP(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	ctx := context.Background()
	network := &models.Network{
		ID:        "n-1",
		Name:      "test-net",
		CIDRs:     []string{"192.168.100.0/24"},
		CreatedAt: time.Now(),
	}
	if err := s.CreateNetwork(ctx, network); err != nil {
		t.Fatal(err)
	}

	host1 := &models.Host{
		ID:        "h-1",
		NetworkID: "n-1",
		Name:      "web-1",
		NebulaIPs: []string{"192.168.100.10"},
		Groups:    []string{},
		Role:      models.HostRoleHost,
		Status:    models.HostStatusEnrolled,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, host1); err != nil {
		t.Fatal(err)
	}

	host2 := &models.Host{
		ID:        "h-2",
		NetworkID: "n-1",
		Name:      "web-2",
		NebulaIPs: []string{"192.168.100.11"},
		Groups:    []string{},
		Role:      models.HostRoleHost,
		Status:    models.HostStatusEnrolled,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, host2); err != nil {
		t.Fatal(err)
	}

	// POST host2 with IP from host1 (duplicate)
	form := url.Values{
		"network_id": {"n-1"},
		"name":       {"web-2"},
		"nebula_ips": {"192.168.100.10"},
		"role":       {"host"},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/hosts/h-2/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (duplicate IP)", rec.Code)
	}
}
