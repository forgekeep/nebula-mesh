package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/juev/nebula-mesh/internal/api"
	agentpop "github.com/juev/nebula-mesh/internal/agent/pop"
	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/pki"
	corepop "github.com/juev/nebula-mesh/internal/pop"
	"github.com/juev/nebula-mesh/internal/store"
	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"
)

// signingKeypair returns a fresh Ed25519 keypair and its PEM-encoded public
// key — the same shape an agent would send to /api/v1/enroll under ADR 0004.
func signingKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "NEBULA ED25519 PUBLIC KEY", Bytes: pub})
	return pub, priv, string(pemBytes)
}

// signedGetUpdates issues an authenticated GET /api/v1/agent/updates poll on
// behalf of an enrolled host. The four PoP headers are filled in identically
// to what internal/agent.Poller produces.
func signedGetUpdates(t *testing.T, ts *httptest.Server, fingerprint string, signingPriv ed25519.PrivateKey) *http.Response {
	t.Helper()
	req, err := http.NewRequest("GET", ts.URL+"/api/v1/agent/updates", nil)
	if err != nil {
		t.Fatal(err)
	}
	ts2 := time.Now().UTC().Format(time.RFC3339)
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		t.Fatal(err)
	}
	nonce := base64.StdEncoding.EncodeToString(nonceBytes)
	canonical := corepop.CanonicalString(req.Method, req.URL.Path, req.URL.Host, ts2, nonce)
	sig, err := agentpop.Sign(signingPriv, canonical)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(corepop.HeaderFingerprint, fingerprint)
	req.Header.Set(corepop.HeaderTimestamp, ts2)
	req.Header.Set(corepop.HeaderNonce, nonce)
	req.Header.Set(corepop.HeaderSignature, agentpop.EncodeSignature(sig))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

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
	srv := api.NewServer(s, ca, testAPIKey, logger, api.CAConfig{})
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
	if err := json.NewDecoder(resp.Body).Decode(&network); err != nil {
		t.Fatalf("decode network: %v", err)
	}
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
	if err := json.NewDecoder(resp.Body).Decode(&lhResp); err != nil {
		t.Fatalf("decode lighthouse: %v", err)
	}
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
	if err := json.NewDecoder(resp.Body).Decode(&hostResp); err != nil {
		t.Fatalf("decode host: %v", err)
	}
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
	_, signingPriv, signingPubPEM := signingKeypair(t)

	enrollReq := map[string]string{
		"token":                  hostResp.EnrollmentToken,
		"public_key_pem":         string(pubKeyPEM),
		"signing_public_key_pem": signingPubPEM,
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
	if err := json.NewDecoder(enrollResp.Body).Decode(&enrollResult); err != nil {
		t.Fatalf("decode enrollment: %v", err)
	}
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
	if err := json.NewDecoder(resp.Body).Decode(&enrolledHost); err != nil {
		t.Fatalf("decode enrolled host: %v", err)
	}
	resp.Body.Close()
	if enrolledHost.Status != models.HostStatusEnrolled {
		t.Errorf("host status = %q, want enrolled", enrolledHost.Status)
	}
	if enrolledHost.CertFingerprint == "" {
		t.Error("host cert fingerprint is empty after enrollment")
	}

	// 7. Agent poll — should get updates (at least blocklist)
	fp, _ := hostCert.Fingerprint()
	pollResp := signedGetUpdates(t, ts, fp, signingPriv)
	var updates struct {
		HasUpdates bool     `json:"has_updates"`
		Blocklist  []string `json:"blocklist"`
	}
	if err := json.NewDecoder(pollResp.Body).Decode(&updates); err != nil {
		t.Fatalf("decode poll updates: %v", err)
	}
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
	if err := json.NewDecoder(resp.Body).Decode(&blocklist); err != nil {
		t.Fatalf("decode blocklist: %v", err)
	}
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

	// 10. Agent poll after block — now answered with 403 revoked (ADR
	// 0004 §7.1 structured revocation), agent must stop polling.
	pollResp = signedGetUpdates(t, ts, fp, signingPriv)
	if pollResp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(pollResp.Body)
		t.Errorf("post-block poll: HTTP %d, want 403, body: %s", pollResp.StatusCode, string(body))
	}
	pollResp.Body.Close()
	t.Logf("post-block poll: 403 revoked received as expected")

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
	if err := json.NewDecoder(resp.Body).Decode(&hosts); err != nil {
		t.Fatalf("decode hosts: %v", err)
	}
	resp.Body.Close()
	if len(hosts) != 2 {
		t.Errorf("expected 2 hosts, got %d", len(hosts))
	}
	t.Logf("network has %d hosts", len(hosts))

	t.Log("E2E test passed: full lifecycle verified")
}

func TestAgentUpdates_CertSaveFailure(t *testing.T) {
	ts, s, _ := setupE2E(t)

	// 1. Create network + host
	resp := apiCall(t, ts, "POST", "/api/v1/networks", map[string]string{
		"name": "save-fail-net",
		"cidr": "10.0.0.0/24",
	})
	var network models.Network
	json.NewDecoder(resp.Body).Decode(&network)
	resp.Body.Close()

	resp = apiCall(t, ts, "POST", "/api/v1/hosts", map[string]any{
		"network_id": network.ID,
		"name":       "save-fail-host",
		"nebula_ip":  "10.0.0.10",
	})
	var hostResp struct {
		Host            *models.Host `json:"host"`
		EnrollmentToken string       `json:"enrollment_token"`
	}
	json.NewDecoder(resp.Body).Decode(&hostResp)
	resp.Body.Close()

	// 2. Enroll
	privKey := make([]byte, 32)
	rand.Read(privKey)
	pubKey, _ := curve25519.X25519(privKey, curve25519.Basepoint)
	pubKeyPEM := cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, pubKey)

	_, signingPriv, signingPubPEM := signingKeypair(t)
	enrollReq := map[string]string{
		"token":                  hostResp.EnrollmentToken,
		"public_key_pem":         string(pubKeyPEM),
		"signing_public_key_pem": signingPubPEM,
	}
	data, _ := json.Marshal(enrollReq)
	enrollResp, _ := http.Post(ts.URL+"/api/v1/enroll", "application/json", bytes.NewReader(data))
	var enrollResult struct {
		CertificatePEM string `json:"certificate_pem"`
	}
	json.NewDecoder(enrollResp.Body).Decode(&enrollResult)
	enrollResp.Body.Close()

	hostCert, _, _ := cert.UnmarshalCertificateFromPEM([]byte(enrollResult.CertificatePEM))
	fp, _ := hostCert.Fingerprint()

	// 3. Modify cert timestamps to trigger renewal (set not_after to 1 minute from now)
	db := s.DB()
	res, err := db.Exec(
		`UPDATE certificates SET not_before = ?, not_after = ? WHERE host_id = ? AND is_current = 1`,
		time.Now().Add(-30*24*time.Hour), time.Now().Add(1*time.Minute), hostResp.Host.ID,
	)
	if rows, _ := res.RowsAffected(); rows != 1 {
		t.Fatalf("expected 1 updated cert row, got %d", rows)
	}
	if err != nil {
		t.Fatal(err)
	}

	// 4. Add a trigger that rejects INSERTs into certificates to cause SaveCert to fail
	_, err = db.Exec(`CREATE TRIGGER reject_cert_insert BEFORE INSERT ON certificates BEGIN SELECT RAISE(ABORT, 'simulated save failure'); END`)
	if err != nil {
		t.Fatal(err)
	}

	// 5. Agent poll — renewal triggered, save fails → expect 500
	pollResp := signedGetUpdates(t, ts, fp, signingPriv)
	defer pollResp.Body.Close()

	if pollResp.StatusCode != http.StatusInternalServerError {
		body, _ := io.ReadAll(pollResp.Body)
		t.Errorf("expected 500 when cert save fails, got %d, body: %s", pollResp.StatusCode, string(body))
	}
}

// enrollHost is a small helper used by the lighthouse auto-assignment tests
// below: it creates a host, runs the full enrollment handshake, and returns
// the host record, its cert fingerprint, its rendered config, and the
// Ed25519 signing private key needed to issue signed polls afterwards.
func enrollHost(t *testing.T, ts *httptest.Server, networkID, name, nebulaIP string, extra map[string]any) (*models.Host, string, string, ed25519.PrivateKey) {
	t.Helper()
	payload := map[string]any{
		"network_id": networkID,
		"name":       name,
		"nebula_ip":  nebulaIP,
	}
	for k, v := range extra {
		payload[k] = v
	}
	resp := apiCall(t, ts, "POST", "/api/v1/hosts", payload)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create host %s: HTTP %d: %s", name, resp.StatusCode, string(body))
	}
	var created struct {
		Host            *models.Host `json:"host"`
		EnrollmentToken string       `json:"enrollment_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode created %s: %v", name, err)
	}
	resp.Body.Close()

	privKey := make([]byte, 32)
	if _, err := rand.Read(privKey); err != nil {
		t.Fatal(err)
	}
	pubKey, err := curve25519.X25519(privKey, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	pubKeyPEM := cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, pubKey)
	_, signingPriv, signingPubPEM := signingKeypair(t)

	enrollData, _ := json.Marshal(map[string]string{
		"token":                  created.EnrollmentToken,
		"public_key_pem":         string(pubKeyPEM),
		"signing_public_key_pem": signingPubPEM,
	})
	enrollResp, err := http.Post(ts.URL+"/api/v1/enroll", "application/json", bytes.NewReader(enrollData))
	if err != nil {
		t.Fatal(err)
	}
	defer enrollResp.Body.Close()
	if enrollResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(enrollResp.Body)
		t.Fatalf("enroll %s: HTTP %d: %s", name, enrollResp.StatusCode, string(body))
	}

	var enrolled struct {
		CertificatePEM string `json:"certificate_pem"`
		ConfigYAML     string `json:"config_yaml"`
	}
	if err := json.NewDecoder(enrollResp.Body).Decode(&enrolled); err != nil {
		t.Fatalf("decode enroll %s: %v", name, err)
	}
	hostCert, _, err := cert.UnmarshalCertificateFromPEM([]byte(enrolled.CertificatePEM))
	if err != nil {
		t.Fatalf("parse cert %s: %v", name, err)
	}
	fp, err := hostCert.Fingerprint()
	if err != nil {
		t.Fatalf("fingerprint %s: %v", name, err)
	}

	return created.Host, fp, enrolled.ConfigYAML, signingPriv
}

// pollAgent runs a single signed agent updates poll for the given fingerprint
// and returns the decoded response.
func pollAgent(t *testing.T, ts *httptest.Server, fingerprint string, signingPriv ed25519.PrivateKey) struct {
	HasUpdates bool     `json:"has_updates"`
	ConfigYAML *string  `json:"config_yaml,omitempty"`
	Blocklist  []string `json:"blocklist"`
} {
	t.Helper()
	resp := signedGetUpdates(t, ts, fingerprint, signingPriv)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("poll: HTTP %d: %s", resp.StatusCode, string(body))
	}
	var out struct {
		HasUpdates bool     `json:"has_updates"`
		ConfigYAML *string  `json:"config_yaml,omitempty"`
		Blocklist  []string `json:"blocklist"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode poll: %v", err)
	}
	return out
}

// TestE2E_LighthouseAutoAssignment exercises issue #39: when a lighthouse is
// promoted, blocked, or deleted, peer agents must pick up the new lighthouse
// layout on their next poll without any manual reconfiguration.
func TestE2E_LighthouseAutoAssignment(t *testing.T) {
	ts, _, _ := setupE2E(t)

	resp := apiCall(t, ts, "POST", "/api/v1/networks", map[string]string{
		"name": "auto-lh-network",
		"cidr": "192.168.50.0/24",
	})
	var network models.Network
	if err := json.NewDecoder(resp.Body).Decode(&network); err != nil {
		t.Fatalf("decode network: %v", err)
	}
	resp.Body.Close()

	// 1. Enroll a peer host first, *before* any lighthouse exists. Its
	// enrollment-time config must contain zero lighthouses.
	_, peerFP, peerInitialCfg, peerSigning := enrollHost(t, ts, network.ID, "peer-1", "192.168.50.10", nil)
	if strings.Contains(peerInitialCfg, "203.0.113.") {
		t.Fatalf("initial peer config unexpectedly references a lighthouse public IP:\n%s", peerInitialCfg)
	}

	// 2. Initial poll immediately after enrollment — no version drift, no
	// config redelivery.
	updates := pollAgent(t, ts, peerFP, peerSigning)
	if updates.ConfigYAML != nil {
		t.Errorf("first poll: ConfigYAML must be nil (no version drift), got non-nil")
	}

	// 3. Now create and enroll a lighthouse. Enrolling a lighthouse must bump
	// the network config_version.
	_, _, _, _ = enrollHost(t, ts, network.ID, "lh-1", "192.168.50.1", map[string]any{
		"role":        "lighthouse",
		"public_ip":   "203.0.113.10",
		"listen_port": 4242,
	})

	// 4. Peer poll — the agent must now receive a config_yaml that lists the
	// newly enrolled lighthouse.
	updates = pollAgent(t, ts, peerFP, peerSigning)
	if updates.ConfigYAML == nil {
		t.Fatal("peer poll after lighthouse promotion: ConfigYAML is nil, expected fresh config")
	}
	if !strings.Contains(*updates.ConfigYAML, "192.168.50.1") || !strings.Contains(*updates.ConfigYAML, "203.0.113.10:4242") {
		t.Errorf("peer config does not advertise new lighthouse:\n%s", *updates.ConfigYAML)
	}

	// 5. Subsequent poll with no further changes — version is back in sync,
	// no config is pushed.
	updates = pollAgent(t, ts, peerFP, peerSigning)
	if updates.ConfigYAML != nil {
		t.Errorf("second poll: expected ConfigYAML=nil, got %q", *updates.ConfigYAML)
	}

	// 6. Add a second lighthouse — peer must pick up both on the next poll.
	_, _, _, _ = enrollHost(t, ts, network.ID, "lh-2", "192.168.50.2", map[string]any{
		"role":        "lighthouse",
		"public_ip":   "203.0.113.20",
		"listen_port": 4242,
	})
	updates = pollAgent(t, ts, peerFP, peerSigning)
	if updates.ConfigYAML == nil {
		t.Fatal("peer poll after second lighthouse: ConfigYAML is nil")
	}
	for _, want := range []string{"192.168.50.1", "192.168.50.2", "203.0.113.10:4242", "203.0.113.20:4242"} {
		if !strings.Contains(*updates.ConfigYAML, want) {
			t.Errorf("peer config missing %q:\n%s", want, *updates.ConfigYAML)
		}
	}

	// 7. Block one lighthouse. Peer's next poll must see a config without the
	// blocked lighthouse.
	resp = apiCall(t, ts, "GET", "/api/v1/hosts?network_id="+network.ID, nil)
	var allHosts []models.Host
	if err := json.NewDecoder(resp.Body).Decode(&allHosts); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	var lh2ID string
	for _, h := range allHosts {
		if h.Name == "lh-2" {
			lh2ID = h.ID
		}
	}
	if lh2ID == "" {
		t.Fatal("lh-2 not found in host list")
	}
	resp = apiCall(t, ts, "POST", "/api/v1/hosts/"+lh2ID+"/block", nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("block lh-2: HTTP %d: %s", resp.StatusCode, string(body))
	}
	resp.Body.Close()

	updates = pollAgent(t, ts, peerFP, peerSigning)
	if updates.ConfigYAML == nil {
		t.Fatal("peer poll after lighthouse block: ConfigYAML is nil")
	}
	if strings.Contains(*updates.ConfigYAML, "203.0.113.20:4242") {
		t.Errorf("peer config still references blocked lighthouse public addr:\n%s", *updates.ConfigYAML)
	}
	if !strings.Contains(*updates.ConfigYAML, "203.0.113.10:4242") {
		t.Errorf("peer config missing surviving lighthouse:\n%s", *updates.ConfigYAML)
	}
}
