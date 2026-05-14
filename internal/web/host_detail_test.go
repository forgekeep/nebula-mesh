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

func TestHostDetail_HasEditButton(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	ctx := context.Background()
	network := &models.Network{
		ID:        "n-1",
		Name:      "test-net",
		CIDR:      "192.168.100.0/24",
		CreatedAt: time.Now(),
	}
	if err := s.CreateNetwork(ctx, network); err != nil {
		t.Fatal(err)
	}

	host := &models.Host{
		ID:        "h-1",
		NetworkID: "n-1",
		Name:      "web-1",
		NebulaIP:  "192.168.100.10",
		Role:      models.HostRoleHost,
		Status:    models.HostStatusEnrolled,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, host); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/ui/hosts/h-1", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()
	expectedHref := `href="/ui/hosts/h-1/edit"`
	if !strings.Contains(body, expectedHref) {
		t.Errorf("body should contain Edit button with %s", expectedHref)
	}
}

func TestHostDetail_RendersAdvanced(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	ctx := context.Background()
	network := &models.Network{
		ID:        "n-1",
		Name:      "test-net",
		CIDR:      "192.168.100.0/24",
		CreatedAt: time.Now(),
	}
	if err := s.CreateNetwork(ctx, network); err != nil {
		t.Fatal(err)
	}

	host := &models.Host{
		ID:        "h-1",
		NetworkID: "n-1",
		Name:      "web-1",
		NebulaIP:  "192.168.100.10",
		Role:      models.HostRoleHost,
		Status:    models.HostStatusEnrolled,
		Advanced: &models.HostAdvanced{
			MTU:        1280,
			ListenHost: "0.0.0.0",
			TunDevice:  "nebula1",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, host); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/ui/hosts/h-1", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()

	// Verify Advanced section header
	if !strings.Contains(body, ">Advanced<") {
		t.Error("body should contain Advanced section header")
	}

	// Verify MTU field
	if !strings.Contains(body, ">MTU<") {
		t.Error("body should contain MTU label")
	}
	if !strings.Contains(body, "1280") {
		t.Error("body should contain MTU value 1280")
	}

	// Verify Listen host field
	if !strings.Contains(body, ">Listen host<") {
		t.Error("body should contain Listen host label")
	}
	if !strings.Contains(body, "0.0.0.0") {
		t.Error("body should contain Listen host value 0.0.0.0")
	}

	// Verify TUN device field
	if !strings.Contains(body, ">TUN device<") {
		t.Error("body should contain TUN device label")
	}
	if !strings.Contains(body, "nebula1") {
		t.Error("body should contain TUN device value nebula1")
	}
}

func TestHostDetail_AdvancedAbsent_NoSection(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	ctx := context.Background()
	network := &models.Network{
		ID:        "n-1",
		Name:      "test-net",
		CIDR:      "192.168.100.0/24",
		CreatedAt: time.Now(),
	}
	if err := s.CreateNetwork(ctx, network); err != nil {
		t.Fatal(err)
	}

	host := &models.Host{
		ID:        "h-1",
		NetworkID: "n-1",
		Name:      "web-1",
		NebulaIP:  "192.168.100.10",
		Role:      models.HostRoleHost,
		Status:    models.HostStatusEnrolled,
		Advanced:  nil,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, host); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/ui/hosts/h-1", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()
	if strings.Contains(body, ">Advanced<") {
		t.Error("body should NOT contain Advanced section header when Advanced is nil")
	}
}

func TestHostDetail_PunchyRendering_True(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	ctx := context.Background()
	network := &models.Network{
		ID:        "n-1",
		Name:      "test-net",
		CIDR:      "192.168.100.0/24",
		CreatedAt: time.Now(),
	}
	if err := s.CreateNetwork(ctx, network); err != nil {
		t.Fatal(err)
	}

	punchyTrue := true
	host := &models.Host{
		ID:        "h-1",
		NetworkID: "n-1",
		Name:      "web-1",
		NebulaIP:  "192.168.100.10",
		Role:      models.HostRoleHost,
		Status:    models.HostStatusEnrolled,
		Advanced: &models.HostAdvanced{
			Punchy: &punchyTrue,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, host); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/ui/hosts/h-1", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()

	// Verify Punchy field
	if !strings.Contains(body, ">Punchy<") {
		t.Error("body should contain Punchy label")
	}
	if !strings.Contains(body, "true") {
		t.Error("body should contain Punchy value true")
	}
}

func TestHostDetail_PunchyRendering_False(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	ctx := context.Background()
	network := &models.Network{
		ID:        "n-1",
		Name:      "test-net",
		CIDR:      "192.168.100.0/24",
		CreatedAt: time.Now(),
	}
	if err := s.CreateNetwork(ctx, network); err != nil {
		t.Fatal(err)
	}

	punchyFalse := false
	host := &models.Host{
		ID:        "h-1",
		NetworkID: "n-1",
		Name:      "web-1",
		NebulaIP:  "192.168.100.10",
		Role:      models.HostRoleHost,
		Status:    models.HostStatusEnrolled,
		Advanced: &models.HostAdvanced{
			Punchy: &punchyFalse,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, host); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/ui/hosts/h-1", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()

	// Verify Punchy field
	if !strings.Contains(body, ">Punchy<") {
		t.Error("body should contain Punchy label")
	}
	if !strings.Contains(body, "false") {
		t.Error("body should contain Punchy value false")
	}
}

func TestHostDetail_UnsafeRoutesRendering(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	ctx := context.Background()
	network := &models.Network{
		ID:        "n-1",
		Name:      "test-net",
		CIDR:      "192.168.100.0/24",
		CreatedAt: time.Now(),
	}
	if err := s.CreateNetwork(ctx, network); err != nil {
		t.Fatal(err)
	}

	host := &models.Host{
		ID:        "h-1",
		NetworkID: "n-1",
		Name:      "web-1",
		NebulaIP:  "192.168.100.10",
		Role:      models.HostRoleHost,
		Status:    models.HostStatusEnrolled,
		Advanced: &models.HostAdvanced{
			UnsafeRoutes: []models.UnsafeRoute{
				{Route: "10.0.0.0/24", Via: "192.168.100.1"},
				{Route: "172.16.0.0/12", Via: "192.168.100.2"},
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, host); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/ui/hosts/h-1", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()

	// Verify Unsafe routes field
	if !strings.Contains(body, ">Unsafe routes<") {
		t.Error("body should contain Unsafe routes label")
	}
	if !strings.Contains(body, "10.0.0.0/24 via 192.168.100.1") {
		t.Error("body should contain first unsafe route")
	}
	if !strings.Contains(body, "172.16.0.0/12 via 192.168.100.2") {
		t.Error("body should contain second unsafe route")
	}
}
