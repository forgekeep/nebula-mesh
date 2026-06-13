package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"
)

const specPath = "../../api/openapi.yaml"

// loadContract loads the OpenAPI document and a router for matching requests to
// operations. A failure here means the hand-written spec is itself invalid.
func loadContract(t *testing.T) routers.Router {
	t.Helper()
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile(specPath)
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatalf("spec is not a valid OpenAPI document: %v", err)
	}
	router, err := gorillamux.NewRouter(doc)
	if err != nil {
		t.Fatalf("build router from spec: %v", err)
	}
	return router
}

// assertContract validates one recorded response against the spec. It fails
// when the path/method is undefined, the status code is not documented, or the
// body does not match the response schema — i.e. when a handler has drifted.
func assertContract(t *testing.T, router routers.Router, req *http.Request, rec *httptest.ResponseRecorder) {
	t.Helper()
	route, pathParams, err := router.FindRoute(req)
	if err != nil {
		t.Fatalf("%s %s: not defined in the spec: %v", req.Method, req.URL.Path, err)
	}
	body := rec.Body.Bytes()
	err = openapi3filter.ValidateResponse(context.Background(), &openapi3filter.ResponseValidationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{
			Request:    req,
			PathParams: pathParams,
			Route:      route,
		},
		Status:  rec.Code,
		Header:  rec.Result().Header,
		Body:    io.NopCloser(bytes.NewReader(body)),
		Options: &openapi3filter.Options{IncludeResponseStatus: true},
	})
	if err != nil {
		t.Errorf("%s %s response violates the contract: %v\nbody: %s", req.Method, req.URL.Path, err, body)
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
	router := loadContract(t)
	srv, _ := newTestServer(t)

	// Create network.
	netBody, _ := json.Marshal(createNetworkRequest{Name: "contract-net", CIDRs: []string{"192.168.50.0/24"}})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/networks", bytes.NewReader(netBody))
	authRequest(req)
	rec := serve(srv, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create network: %d / %s", rec.Code, rec.Body.String())
	}
	assertContract(t, router, req, rec)
	var net struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &net)

	// List networks.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/networks", nil)
	authRequest(req)
	assertContract(t, router, req, serve(srv, req))

	// Get network by id.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/networks/"+net.ID, nil)
	authRequest(req)
	assertContract(t, router, req, serve(srv, req))

	// Create host.
	hostBody, _ := json.Marshal(createHostRequest{NetworkID: net.ID, Name: "contract-host", NebulaIPs: []string{"192.168.50.10"}})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/hosts", bytes.NewReader(hostBody))
	authRequest(req)
	rec = serve(srv, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create host: %d / %s", rec.Code, rec.Body.String())
	}
	assertContract(t, router, req, rec)
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
		assertContract(t, router, req, rec)
	}
}

// TestContract_AgentEndpoints validates the enroll + signed-poll responses the
// fleet depends on — the endpoints where silent drift hurts most.
func TestContract_AgentEndpoints(t *testing.T) {
	router := loadContract(t)
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
	enrollBody, _ := json.Marshal(enrollRequest{
		Token:         created.EnrollmentToken,
		PublicKeyPEM:  string(pubKeyPEM),
		SigningPubPEM: string(signingPubPEM),
	})
	ereq := httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewReader(enrollBody))
	erec := serve(srv, ereq)
	if erec.Code != http.StatusOK {
		t.Fatalf("enroll: %d / %s", erec.Code, erec.Body.String())
	}
	assertContract(t, router, ereq, erec)

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
	assertContract(t, router, preq, prec)
}
