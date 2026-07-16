package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/pb33f/libopenapi"
	validator "github.com/pb33f/libopenapi-validator"
	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

const specPath = "../../api/openapi.yaml"

// loadContract parses the OpenAPI 3.1 document and returns a validator. It also
// asserts the document is itself valid — a failure here means the hand-written
// spec is broken, not a handler.
func loadContract(t *testing.T) validator.Validator {
	t.Helper()
	specBytes, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	doc, err := libopenapi.NewDocument(specBytes)
	if err != nil {
		t.Fatalf("parse spec: %v", err)
	}
	v, errs := validator.NewValidator(doc)
	if len(errs) > 0 {
		t.Fatalf("build validator: %v", errs)
	}
	if ok, verrs := v.ValidateDocument(); !ok {
		for _, e := range verrs {
			t.Errorf("spec is not a valid OpenAPI document: %s — %s", e.Message, e.Reason)
		}
		t.FailNow()
	}
	return v
}

// assertContract validates one recorded response against the spec. It fails
// when the path/method/status is undefined or the body does not match the
// response schema — i.e. when a handler has drifted from the contract.
func assertContract(t *testing.T, v validator.Validator, req *http.Request, rec *httptest.ResponseRecorder) {
	t.Helper()
	ok, verrs := v.ValidateHttpResponse(req, rec.Result())
	if !ok {
		for _, e := range verrs {
			t.Errorf("%s %s response violates the contract: %s — %s (fix: %s)",
				req.Method, req.URL.Path, e.Message, e.Reason, e.HowToFix)
		}
	}
}

// serve runs a request through the server and returns the recorder.
func serve(srv *Server, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

// TestContract_SpecIsValid is the cheapest guard: the spec parses and validates.
func TestContract_SpecIsValid(t *testing.T) {
	loadContract(t)
}

// TestContract_AdminEndpoints validates real admin responses against the spec.
func TestContract_AdminEndpoints(t *testing.T) {
	v := loadContract(t)
	srv, _ := newTestServer(t)

	// Create network.
	netBody, _ := json.Marshal(createNetworkRequest{Name: "contract-net", CIDRs: []string{"192.168.50.0/24"}})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/networks", bytes.NewReader(netBody))
	authRequest(req)
	rec := serve(srv, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create network: %d / %s", rec.Code, rec.Body.String())
	}
	assertContract(t, v, req, rec)
	var net struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &net)

	// List networks.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/networks", nil)
	authRequest(req)
	assertContract(t, v, req, serve(srv, req))

	// Get network by id.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/networks/"+net.ID, nil)
	authRequest(req)
	assertContract(t, v, req, serve(srv, req))

	// Create host.
	hostBody, _ := json.Marshal(createHostRequest{NetworkID: net.ID, Name: "contract-host", NebulaIPs: []string{"192.168.50.10"}})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/hosts", bytes.NewReader(hostBody))
	authRequest(req)
	rec = serve(srv, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create host: %d / %s", rec.Code, rec.Body.String())
	}
	assertContract(t, v, req, rec)
	var ch createHostResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &ch)

	// Get host, list hosts, blocklist, audit-log.
	for _, path := range []string{
		"/api/v1/hosts/" + ch.Host.ID,
		"/api/v1/hosts",
		"/api/v1/blocklist",
		"/api/v1/audit-log",
	} {
		req = httptest.NewRequest(http.MethodGet, path, nil)
		authRequest(req)
		rec = serve(srv, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: %d / %s", path, rec.Code, rec.Body.String())
		}
		assertContract(t, v, req, rec)
	}
}

func TestContract_CAImport(t *testing.T) {
	v := loadContract(t)
	srv, apiKey := newServerWithMaster(t)
	body, contentType := testCAImportMultipart(t, "contract-import")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cas/import", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", contentType)
	req.TLS = &tls.ConnectionState{}
	rec := serve(srv, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("import CA: %d / %s", rec.Code, rec.Body.String())
	}
	assertContract(t, v, req, rec)
}

func TestContract_MeshImports(t *testing.T) {
	v := loadContract(t)
	srv, st := newTestServer(t)
	network, ca := seedAPIMeshImportScope(t, st, "contract")

	body, _ := json.Marshal(createMeshImportRequest{NetworkID: network.ID, CAID: ca.ID, ExpectedHosts: intPointer(2)})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mesh-imports", bytes.NewReader(body))
	authRequest(req)
	rec := serve(srv, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create mesh import: %d / %s", rec.Code, rec.Body.String())
	}
	assertContract(t, v, req, rec)
	var created meshImportTokenResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"/api/v1/mesh-imports", "/api/v1/mesh-imports/" + created.MeshImport.ID} {
		req = httptest.NewRequest(http.MethodGet, path, nil)
		authRequest(req)
		rec = serve(srv, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: %d / %s", path, rec.Code, rec.Body.String())
		}
		assertContract(t, v, req, rec)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/mesh-imports/"+created.MeshImport.ID+"/rotate-token", nil)
	authRequest(req)
	rec = serve(srv, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("rotate mesh import token: %d / %s", rec.Code, rec.Body.String())
	}
	assertContract(t, v, req, rec)

	req = httptest.NewRequest(http.MethodPost, "/api/v1/mesh-imports/"+created.MeshImport.ID+"/cancel", nil)
	authRequest(req)
	rec = serve(srv, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("cancel mesh import: %d / %s", rec.Code, rec.Body.String())
	}
	assertContract(t, v, req, rec)
}

func TestContract_AgentImport(t *testing.T) {
	v := loadContract(t)
	fixture := newAgentImportFixture(t)
	payload := map[string]any{
		"token": fixture.token, "ca_certificate_pem": fixture.caPEM,
		"agent_signing_public_key_pem": fixture.signingPEM,
		"payload_hash":                 fixture.payloadHash, "snapshot": fixture.snapshot,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/agent/import/challenge", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := serve(fixture.server, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("challenge: %d / %s", response.Code, response.Body.String())
	}
	assertContract(t, v, request, response)
	var challenge testAgentImportChallengeResponse
	if err := json.Unmarshal(response.Body.Bytes(), &challenge); err != nil {
		t.Fatal(err)
	}
	for attempt, wantStatus := range []int{http.StatusCreated, http.StatusTooManyRequests} {
		quotaRequest := httptest.NewRequest(http.MethodPost, "/api/v1/agent/import/challenge", bytes.NewReader(body))
		quotaRequest.Header.Set("Content-Type", "application/json")
		quotaResponse := serve(fixture.server, quotaRequest)
		if quotaResponse.Code != wantStatus {
			t.Fatalf("quota challenge attempt %d: %d / %s", attempt+2, quotaResponse.Code, quotaResponse.Body.String())
		}
		assertContract(t, v, quotaRequest, quotaResponse)
	}
	proof := computeAgentImportProof(t, fixture, challenge)
	payload["challenge_id"] = challenge.ChallengeID
	payload["proof"] = base64.RawURLEncoding.EncodeToString(proof)
	body, err = json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodPost, "/api/v1/agent/import", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response = serve(fixture.server, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("register: %d / %s", response.Code, response.Body.String())
	}
	assertContract(t, v, request, response)
}

// TestContract_AgentEndpoints validates the enroll + signed-poll responses the
// fleet depends on — the endpoints where silent drift hurts most.
func TestContract_AgentEndpoints(t *testing.T) {
	v := loadContract(t)
	srv, _ := newTestServer(t)

	netID := createNetwork(t, srv)
	hostBody, _ := json.Marshal(createHostRequest{NetworkID: netID, Name: "agent-host", NebulaIPs: []string{"192.168.100.40"}})
	hreq := httptest.NewRequest(http.MethodPost, "/api/v1/hosts", bytes.NewReader(hostBody))
	authRequest(hreq)
	hrec := serve(srv, hreq)
	if hrec.Code != http.StatusCreated {
		t.Fatalf("create host: %d / %s", hrec.Code, hrec.Body.String())
	}
	var created createHostResponse
	_ = json.Unmarshal(hrec.Body.Bytes(), &created)

	// X25519 for the cert, Ed25519 for poll signatures.
	x25519Priv := make([]byte, 32)
	if _, err := rand.Read(x25519Priv); err != nil {
		t.Fatal(err)
	}
	x25519Pub, err := curve25519.X25519(x25519Priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	pubKeyPEM := cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, x25519Pub)
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingPubPEM := pem.EncodeToMemory(&pem.Block{Type: SigningPublicKeyPEMType, Bytes: edPub})

	// Enroll.
	profile := models.DefaultAgentProfile()
	profile.ConfigAckV1 = true
	enrollBody, _ := json.Marshal(enrollRequest{
		Token:         created.EnrollmentToken,
		PublicKeyPEM:  string(pubKeyPEM),
		SigningPubPEM: string(signingPubPEM),
		Profile:       profile,
	})
	ereq := httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewReader(enrollBody))
	erec := serve(srv, ereq)
	if erec.Code != http.StatusOK {
		t.Fatalf("enroll: %d / %s", erec.Code, erec.Body.String())
	}
	assertContract(t, v, ereq, erec)

	var enrolled struct {
		CertificatePEM string `json:"certificate_pem"`
	}
	_ = json.Unmarshal(erec.Body.Bytes(), &enrolled)
	hostCert, _, err := cert.UnmarshalCertificateFromPEM([]byte(enrolled.CertificatePEM))
	if err != nil {
		t.Fatal(err)
	}
	fp, err := hostCert.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}

	// Signed poll.
	preq := httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil)
	signPoll(t, preq, enrolledAgent{hostID: created.Host.ID, fingerprint: fp, signingPub: edPub, signingPriv: edPriv})
	prec := serve(srv, preq)
	if prec.Code != http.StatusOK {
		t.Fatalf("agent updates: %d / %s", prec.Code, prec.Body.String())
	}
	assertContract(t, v, preq, prec)
	var updates agentUpdatesResponse
	_ = json.Unmarshal(prec.Body.Bytes(), &updates)
	if updates.ConfigVersion <= 0 {
		t.Fatalf("agent updates omitted pending config version: %s", prec.Body.String())
	}
	ackPath := fmt.Sprintf("/api/v1/agent/config-ack/%d", updates.ConfigVersion)
	ackRequest := httptest.NewRequest(http.MethodPost, ackPath, nil)
	signPoll(t, ackRequest, enrolledAgent{hostID: created.Host.ID, fingerprint: fp, signingPub: edPub, signingPriv: edPriv})
	ackResponse := serve(srv, ackRequest)
	if ackResponse.Code != http.StatusOK {
		t.Fatalf("config ack: %d / %s", ackResponse.Code, ackResponse.Body.String())
	}
	assertContract(t, v, ackRequest, ackResponse)
}
