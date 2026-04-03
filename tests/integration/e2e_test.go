package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/juev/nebula-mesh/internal/api"
	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/pki"
	"github.com/juev/nebula-mesh/internal/store"
	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"
)

const testAPIKey = "e2e-test-api-key"

func setupE2E(t *testing.T) (*httptest.Server, *store.SQLiteStore, *pki.CAManager) {
	t.Helper()

	s, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	ca, _, err := pki.NewCA("e2e-test-ca", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := api.NewServer(s, ca, testAPIKey, logger)
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	return ts, s, ca
}

func apiCall(t *testing.T, ts *httptest.Server, method, path string, body any) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(data)
	}
	req, _ := http.NewRequest(method, ts.URL+path, bodyReader)
	req.Header.Set("Authorization", "Bearer "+testAPIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestE2E_FullCycle(t *testing.T) {
	ts, _, ca := setupE2E(t)

	// 1. Create network
	resp := apiCall(t, ts, "POST", "/api/v1/networks", map[string]string{
		"name": "e2e-network",
		"cidr": "192.168.100.0/24",
	})
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create network: HTTP %d: %s", resp.StatusCode, string(body))
	}
	var network models.Network
	json.NewDecoder(resp.Body).Decode(&network)
	resp.Body.Close()
	t.Logf("network created: %s (%s)", network.Name, network.ID)

	// 2. Create lighthouse
	resp = apiCall(t, ts, "POST", "/api/v1/hosts", map[string]any{
		"network_id":  network.ID,
		"name":        "lighthouse-1",
		"nebula_ip":   "192.168.100.1",
		"role":        "lighthouse",
		"public_ip":   "203.0.113.10",
		"listen_port": 4242,
	})
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create lighthouse: HTTP %d: %s", resp.StatusCode, string(body))
	}
	var lhResp struct {
		Host            *models.Host `json:"host"`
		EnrollmentToken string       `json:"enrollment_token"`
	}
	json.NewDecoder(resp.Body).Decode(&lhResp)
	resp.Body.Close()
	t.Logf("lighthouse created: %s, token: %s", lhResp.Host.Name, lhResp.EnrollmentToken)

	// 3. Create regular host
	resp = apiCall(t, ts, "POST", "/api/v1/hosts", map[string]any{
		"network_id": network.ID,
		"name":       "host-1",
		"nebula_ip":  "192.168.100.10",
		"groups":     []string{"web", "prod"},
	})
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create host: HTTP %d: %s", resp.StatusCode, string(body))
	}
	var hostResp struct {
		Host            *models.Host `json:"host"`
		EnrollmentToken string       `json:"enrollment_token"`
	}
	json.NewDecoder(resp.Body).Decode(&hostResp)
	resp.Body.Close()
	t.Logf("host created: %s, token: %s", hostResp.Host.Name, hostResp.EnrollmentToken)

	// 4. Enroll host (simulate agent enrollment)
	privKey := make([]byte, 32)
	if _, err := rand.Read(privKey); err != nil {
		t.Fatal(err)
	}
	pubKey, err := curve25519.X25519(privKey, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	pubKeyPEM := cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, pubKey)

	enrollReq := map[string]string{
		"token":          hostResp.EnrollmentToken,
		"public_key_pem": string(pubKeyPEM),
	}
	data, _ := json.Marshal(enrollReq)
	enrollResp, err := http.Post(ts.URL+"/api/v1/enroll", "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if enrollResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(enrollResp.Body)
		t.Fatalf("enroll: HTTP %d: %s", enrollResp.StatusCode, string(body))
	}
	var enrollResult struct {
		CertificatePEM   string `json:"certificate_pem"`
		CACertificatePEM string `json:"ca_certificate_pem"`
		ConfigYAML       string `json:"config_yaml"`
	}
	json.NewDecoder(enrollResp.Body).Decode(&enrollResult)
	enrollResp.Body.Close()

	if enrollResult.CertificatePEM == "" {
		t.Fatal("empty certificate PEM in enrollment response")
	}
	if enrollResult.CACertificatePEM == "" {
		t.Fatal("empty CA certificate PEM in enrollment response")
	}
	if enrollResult.ConfigYAML == "" {
		t.Fatal("empty config YAML in enrollment response")
	}
	t.Log("enrollment successful")

	// 5. Verify certificate is valid
	hostCert, _, err := cert.UnmarshalCertificateFromPEM([]byte(enrollResult.CertificatePEM))
	if err != nil {
		t.Fatalf("parse host cert: %v", err)
	}
	if hostCert.Name() != "host-1" {
		t.Errorf("cert name = %q, want host-1", hostCert.Name())
	}

	caCertPEM, _ := ca.CACertPEM()
	pool, err := cert.NewCAPoolFromPEM(caCertPEM)
	if err != nil {
		t.Fatalf("CA pool: %v", err)
	}
	_, err = pool.VerifyCertificate(time.Now(), hostCert)
	if err != nil {
		t.Fatalf("verify certificate: %v", err)
	}
	t.Log("certificate verified against CA")

	// 6. Verify host is now enrolled
	resp = apiCall(t, ts, "GET", "/api/v1/hosts/"+hostResp.Host.ID, nil)
	var enrolledHost models.Host
	json.NewDecoder(resp.Body).Decode(&enrolledHost)
	resp.Body.Close()
	if enrolledHost.Status != models.HostStatusEnrolled {
		t.Errorf("host status = %q, want enrolled", enrolledHost.Status)
	}
	if enrolledHost.CertFingerprint == "" {
		t.Error("host cert fingerprint is empty after enrollment")
	}

	// 7. Agent poll — should get updates (at least blocklist)
	fp, _ := hostCert.Fingerprint()
	pollResp, err := http.Get(ts.URL + "/api/v1/agent/updates?fingerprint=" + fp)
	if err != nil {
		t.Fatal(err)
	}
	var updates struct {
		HasUpdates bool     `json:"has_updates"`
		Blocklist  []string `json:"blocklist"`
	}
	json.NewDecoder(pollResp.Body).Decode(&updates)
	pollResp.Body.Close()
	t.Logf("poll result: has_updates=%v, blocklist=%v", updates.HasUpdates, updates.Blocklist)

	// 8. Block host
	resp = apiCall(t, ts, "POST", "/api/v1/hosts/"+hostResp.Host.ID+"/block", nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("block host: HTTP %d: %s", resp.StatusCode, string(body))
	}
	resp.Body.Close()

	// 9. Verify blocklist now contains the fingerprint
	resp = apiCall(t, ts, "GET", "/api/v1/blocklist", nil)
	var blocklist []string
	json.NewDecoder(resp.Body).Decode(&blocklist)
	resp.Body.Close()

	found := false
	for _, bl := range blocklist {
		if bl == enrolledHost.CertFingerprint {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("blocklist %v does not contain host fingerprint %s", blocklist, enrolledHost.CertFingerprint)
	}
	t.Log("host blocked, fingerprint in blocklist")

	// 10. Agent poll after block — should have blocklist update
	pollResp, err = http.Get(ts.URL + "/api/v1/agent/updates?fingerprint=" + fp)
	if err != nil {
		t.Fatal(err)
	}
	json.NewDecoder(pollResp.Body).Decode(&updates)
	pollResp.Body.Close()

	if !updates.HasUpdates {
		t.Error("expected has_updates=true after block")
	}
	if len(updates.Blocklist) == 0 {
		t.Error("expected non-empty blocklist after block")
	}
	t.Logf("post-block poll: has_updates=%v, blocklist=%v", updates.HasUpdates, updates.Blocklist)

	// 11. Try duplicate enrollment (should fail)
	enrollResp2, _ := http.Post(ts.URL+"/api/v1/enroll", "application/json", bytes.NewReader(data))
	if enrollResp2.StatusCode != http.StatusConflict {
		t.Errorf("duplicate enrollment: HTTP %d, want 409", enrollResp2.StatusCode)
	}
	enrollResp2.Body.Close()
	t.Log("duplicate enrollment correctly rejected")

	// 12. List hosts
	resp = apiCall(t, ts, "GET", "/api/v1/hosts?network_id="+network.ID, nil)
	var hosts []models.Host
	json.NewDecoder(resp.Body).Decode(&hosts)
	resp.Body.Close()
	if len(hosts) != 2 {
		t.Errorf("expected 2 hosts, got %d", len(hosts))
	}
	t.Logf("network has %d hosts", len(hosts))

	t.Log("E2E test passed: full lifecycle verified")
}
