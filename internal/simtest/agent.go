package simtest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"time"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"

	agentpop "github.com/forgekeep/nebula-mesh/internal/agent/pop"
	corepop "github.com/forgekeep/nebula-mesh/internal/pop"
)

// Agent is a virtual host: an enrolled identity that speaks the real ADR 0004
// poll protocol. It tracks only what an agent legitimately knows — its
// fingerprint and signing key — never server-side state.
type Agent struct {
	HostID      string
	Name        string
	Fingerprint string

	signingPriv ed25519.PrivateKey
}

// PollResponse is the subset of the agent-updates response the simulation
// asserts against.
type PollResponse struct {
	Status         int
	Reason         string   `json:"reason"` // set on 403/410 revocation bodies
	HasUpdates     bool     `json:"has_updates"`
	ConfigYAML     *string  `json:"config_yaml"`
	CertificatePEM *string  `json:"certificate_pem"`
	RekeyRequired  bool     `json:"rekey_required"`
	Blocklist      []string `json:"blocklist"`
}

// CreateHost creates a host row and returns its ID and single-use enrollment
// token. role may be "" (regular host), "lighthouse", or "relay".
func (h *Harness) CreateHost(networkID, name, role, nebulaIP string) (hostID, token string) {
	h.tb.Helper()
	req := map[string]any{
		"network_id": networkID,
		"name":       name,
		"nebula_ips": []string{nebulaIP},
	}
	if role != "" {
		req["role"] = role
		req["public_ip"] = "203.0.113.10"
		req["listen_port"] = 4242
	}
	var out struct {
		Host            struct{ ID string } `json:"host"`
		EnrollmentToken string              `json:"enrollment_token"`
	}
	if code := h.API(http.MethodPost, "/api/v1/hosts", req, &out); code != http.StatusCreated {
		h.tb.Fatalf("create host %q: HTTP %d", name, code)
	}
	return out.Host.ID, out.EnrollmentToken
}

// Enroll creates and enrolls a regular host, returning a ready-to-poll Agent.
func (h *Harness) Enroll(networkID, name, nebulaIP string) *Agent {
	h.tb.Helper()
	hostID, token := h.CreateHost(networkID, name, "", nebulaIP)

	// X25519 keypair for the Nebula cert; Ed25519 keypair for PoP signing.
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		h.tb.Fatalf("rand: %v", err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		h.tb.Fatalf("x25519: %v", err)
	}
	pubPEM := cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, pub)

	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		h.tb.Fatalf("ed25519: %v", err)
	}
	signPubPEM := pem.EncodeToMemory(&pem.Block{Type: "NEBULA ED25519 PUBLIC KEY", Bytes: signPub})

	var enrollOut struct {
		CertificatePEM string `json:"certificate_pem"`
	}
	if code := h.API(http.MethodPost, "/api/v1/enroll", map[string]string{
		"token":                  token,
		"public_key_pem":         string(pubPEM),
		"signing_public_key_pem": string(signPubPEM),
	}, &enrollOut); code != http.StatusOK {
		h.tb.Fatalf("enroll %q: HTTP %d", name, code)
	}

	hostCert, _, err := cert.UnmarshalCertificateFromPEM([]byte(enrollOut.CertificatePEM))
	if err != nil {
		h.tb.Fatalf("parse enrolled cert for %q: %v", name, err)
	}
	fp, err := hostCert.Fingerprint()
	if err != nil {
		h.tb.Fatalf("fingerprint for %q: %v", name, err)
	}

	h.Journal.Add(Event{Actor: name, Action: "enroll", Target: hostID})
	return &Agent{HostID: hostID, Name: name, Fingerprint: fp, signingPriv: signPriv}
}

// Poll performs one signed GET /api/v1/agent/updates, the real ADR 0004 poll.
func (a *Agent) Poll(h *Harness) PollResponse {
	h.tb.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, h.Server.URL+"/api/v1/agent/updates", http.NoBody)
	if err != nil {
		h.tb.Fatalf("new poll request for %q: %v", a.Name, err)
	}
	ts := h.now().UTC().Format(time.RFC3339)
	nb := make([]byte, 16)
	if _, err := rand.Read(nb); err != nil {
		h.tb.Fatalf("nonce: %v", err)
	}
	nonce := base64.StdEncoding.EncodeToString(nb)
	canonical := corepop.CanonicalString(req.Method, req.URL.Path, req.URL.Host, ts, nonce)
	sig, err := agentpop.Sign(a.signingPriv, canonical)
	if err != nil {
		h.tb.Fatalf("sign poll for %q: %v", a.Name, err)
	}
	req.Header.Set(corepop.HeaderFingerprint, a.Fingerprint)
	req.Header.Set(corepop.HeaderTimestamp, ts)
	req.Header.Set(corepop.HeaderNonce, nonce)
	req.Header.Set(corepop.HeaderSignature, agentpop.EncodeSignature(sig))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.tb.Fatalf("do poll for %q: %v", a.Name, err)
	}
	defer resp.Body.Close()

	out := PollResponse{Status: resp.StatusCode}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	h.Journal.Add(Event{
		Actor:  a.Name,
		Action: "poll",
		Target: a.HostID,
		Status: resp.StatusCode,
		Note:   pollNote(out),
	})
	return out
}

// DrainToConverged polls until the server stops shipping config (steady
// state), returning the number of polls. It fails the test if convergence is
// not reached within maxPolls — a stuck host is itself a convergence failure.
func (a *Agent) DrainToConverged(h *Harness, maxPolls int) int {
	h.tb.Helper()
	for i := 1; i <= maxPolls; i++ {
		if r := a.Poll(h); r.ConfigYAML == nil {
			return i
		}
	}
	h.tb.Fatalf("%q did not converge within %d polls\n%s", a.Name, maxPolls, h.Journal.Report(a.HostID))
	return maxPolls
}

func pollNote(r PollResponse) string {
	switch {
	case r.ConfigYAML != nil:
		return "config shipped"
	case r.CertificatePEM != nil:
		return "cert renewed"
	case r.RekeyRequired:
		return "rekey required"
	default:
		return "no config"
	}
}
