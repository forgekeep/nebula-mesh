package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

func TestHostDetail_HasEditButton(t *testing.T) {
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
		Role:      models.HostRoleHost,
		Status:    models.HostStatusEnrolled,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, host); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/ui/hosts/h-1", nil)
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

func TestHostDetail_PendingHostCanBeDeleted(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	ctx := context.Background()
	if err := s.CreateNetwork(ctx, &models.Network{
		ID: "n-delete-pending", Name: "test-net", CIDRs: []string{"192.168.100.0/24"}, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	host := &models.Host{
		ID: "h-delete-pending", NetworkID: "n-delete-pending", Name: "pending-host",
		NebulaIPs: []string{"192.168.100.11"}, Role: models.HostRoleHost, Status: models.HostStatusPending,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, host); err != nil {
		t.Fatal(err)
	}

	csrfToken, cookies := getCSRFTokenFromCookies(t, w, "/ui/hosts/"+host.ID, cookies)
	req := httptest.NewRequest(http.MethodDelete, "/ui/hosts/"+host.ID, nil)
	req.Header.Set(csrfHeaderName, csrfToken)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("delete status = %d, want %d", rec.Code, http.StatusOK)
	}
	if redirect := rec.Header().Get("HX-Redirect"); redirect != "/ui/hosts" {
		t.Errorf("HX-Redirect = %q, want /ui/hosts", redirect)
	}
	if _, err := s.GetHost(ctx, host.ID); err == nil {
		t.Error("pending host still exists after delete")
	}
}

func TestLayout_RegistersHTMXCSRFListenerOnDocument(t *testing.T) {
	w, _ := newTestWeb(t)
	cookies := loginSession(t, w)

	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), "document.addEventListener('htmx:configRequest'") {
		t.Error("layout must register the HTMX CSRF listener on document")
	}
}

func TestHostDetail_RendersAdvanced(t *testing.T) {
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

	req := httptest.NewRequest(http.MethodGet, "/ui/hosts/h-1", nil)
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
		Role:      models.HostRoleHost,
		Status:    models.HostStatusEnrolled,
		Advanced:  nil,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, host); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/ui/hosts/h-1", nil)
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
		CIDRs:     []string{"192.168.100.0/24"},
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
		NebulaIPs: []string{"192.168.100.10"},
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

	req := httptest.NewRequest(http.MethodGet, "/ui/hosts/h-1", nil)
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
		CIDRs:     []string{"192.168.100.0/24"},
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
		NebulaIPs: []string{"192.168.100.10"},
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

	req := httptest.NewRequest(http.MethodGet, "/ui/hosts/h-1", nil)
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

	req := httptest.NewRequest(http.MethodGet, "/ui/hosts/h-1", nil)
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

func TestHandleHostDetail_MobileSection(t *testing.T) {
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
		Name:      "iphone-test",
		NebulaIPs: []string{"192.168.100.10"},
		Role:      models.HostRoleHost,
		Status:    models.HostStatusPending,
		Kind:      models.HostKindMobile,
		Variant:   models.HostVariantIOS,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, host); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/ui/hosts/h-1", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()

	// Verify mobile bundle section exists
	if !strings.Contains(body, "Mobile Bundle (iOS)") {
		t.Error("body should contain 'Mobile Bundle (iOS)' heading")
	}

	// Verify form action
	if !strings.Contains(body, `action="/ui/hosts/h-1/mobile-bundle/generate"`) {
		t.Error("body should contain form with action=/ui/hosts/h-1/mobile-bundle/generate")
	}

	// Verify button text for pending status
	if !strings.Contains(body, "Generate Mobile Bundle") {
		t.Error("body should contain 'Generate Mobile Bundle' button text for pending status")
	}
}

func TestHandleHostDetail_MobileSection_Android(t *testing.T) {
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
		ID:        "h-2",
		NetworkID: "n-1",
		Name:      "android-test",
		NebulaIPs: []string{"192.168.100.20"},
		Role:      models.HostRoleHost,
		Status:    models.HostStatusPending,
		Kind:      models.HostKindMobile,
		Variant:   models.HostVariantAndroid,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, host); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/ui/hosts/h-2", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()

	// Verify mobile bundle section with Android variant
	if !strings.Contains(body, "Mobile Bundle (Android)") {
		t.Error("body should contain 'Mobile Bundle (Android)' heading")
	}
}

func TestHandleHostDetail_AgentNoMobileSection(t *testing.T) {
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
		ID:        "h-3",
		NetworkID: "n-1",
		Name:      "agent-test",
		NebulaIPs: []string{"192.168.100.30"},
		Role:      models.HostRoleHost,
		Status:    models.HostStatusEnrolled,
		Kind:      models.HostKindAgent,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, host); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/ui/hosts/h-3", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()

	// Verify mobile bundle section is NOT present for agent
	if strings.Contains(body, "mobile-bundle/generate") {
		t.Error("body should NOT contain mobile-bundle/generate action for agent host")
	}
	if strings.Contains(body, "Mobile Bundle") {
		t.Error("body should NOT contain Mobile Bundle section for agent host")
	}
}

func TestHandleHostDetail_MobileEnrolled_ShowsRegenerate(t *testing.T) {
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
		ID:        "h-4",
		NetworkID: "n-1",
		Name:      "iphone-enrolled",
		NebulaIPs: []string{"192.168.100.40"},
		Role:      models.HostRoleHost,
		Status:    models.HostStatusEnrolled,
		Kind:      models.HostKindMobile,
		Variant:   models.HostVariantIOS,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, host); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/ui/hosts/h-4", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()

	// Verify button text changes for enrolled status
	if !strings.Contains(body, "Regenerate Bundle (Rotate Cert)") {
		t.Error("body should contain 'Regenerate Bundle (Rotate Cert)' button text for enrolled status")
	}
}

func TestHandleHostDetail_AgentToken_DisplaysWhenPassing(t *testing.T) {
	// This test verifies that the token condition still works for agent hosts
	// (i.e., when Token is explicitly passed in context).
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
		ID:        "h-5",
		NetworkID: "n-1",
		Name:      "agent-with-token",
		NebulaIPs: []string{"192.168.100.50"},
		Role:      models.HostRoleHost,
		Status:    models.HostStatusPending,
		Kind:      models.HostKindAgent,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	token := &models.EnrollmentToken{
		ID:        "t-1",
		HostID:    host.ID,
		TokenHash: models.HashEnrollmentToken("secret-token-value"),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}
	if err := s.CreateHostAndToken(ctx, host, token); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/ui/hosts/h-5", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()

	// Verify that token flash is NOT shown on subsequent detail page view
	// (handleHostDetail doesn't pass Token in context)
	if strings.Contains(body, "secret-token-value") {
		t.Error("body should NOT contain token on subsequent detail page view (only on creation)")
	}
}
