package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"
)

// enrollAndParseCert runs a full create-host + enroll cycle and returns the
// certificate the server issued, so a test can assert on what was actually
// signed rather than on what the host row says.
func enrollAndParseCert(t *testing.T, srv *Server, req createHostRequest) cert.Certificate {
	t.Helper()

	body, _ := json.Marshal(req)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/hosts", bytes.NewReader(body))
	authRequest(request)
	recorder := httptest.NewRecorder()
	srv.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("create host: %d %s", recorder.Code, recorder.Body.String())
	}
	var created createHostResponse
	if err := json.NewDecoder(recorder.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}

	privateKey := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(privateKey); err != nil {
		t.Fatal(err)
	}
	defer clear(privateKey)
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	signingPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingPEM := pem.EncodeToMemory(&pem.Block{Type: SigningPublicKeyPEMType, Bytes: signingPublic})

	enrollBody, _ := json.Marshal(enrollRequest{
		Token:         created.EnrollmentToken,
		PublicKeyPEM:  string(cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, publicKey)),
		SigningPubPEM: string(signingPEM),
	})
	recorder = httptest.NewRecorder()
	srv.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewReader(enrollBody)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("enroll: %d %s", recorder.Code, recorder.Body.String())
	}

	var response enrollResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	hostCert, _, err := cert.UnmarshalCertificateFromPEM([]byte(response.CertificatePEM))
	if err != nil {
		t.Fatalf("parse issued cert: %v", err)
	}
	return hostCert
}

// The end-to-end guarantee: a host created with unsafe_networks must enroll
// with those prefixes inside its certificate. Nebula authorizes routing on the
// certificate, so anything less leaves the gateway silently refusing to route.
func TestEnroll_IssuesCertWithUnsafeNetworks(t *testing.T) {
	srv, _ := newTestServer(t)
	networkID := createNetwork(t, srv)

	hostCert := enrollAndParseCert(t, srv, createHostRequest{
		NetworkID:      networkID,
		Name:           "gateway",
		NebulaIPs:      []string{"192.168.100.50"},
		UnsafeNetworks: []string{"192.168.1.0/24"},
	})

	got := hostCert.UnsafeNetworks()
	want := netip.MustParsePrefix("192.168.1.0/24")
	if len(got) != 1 || got[0] != want {
		t.Fatalf("issued cert unsafe networks = %v, want [%v]", got, want)
	}
}

func TestEnroll_OrdinaryHostGetsNoUnsafeNetworks(t *testing.T) {
	srv, _ := newTestServer(t)
	networkID := createNetwork(t, srv)

	hostCert := enrollAndParseCert(t, srv, createHostRequest{
		NetworkID: networkID,
		Name:      "plain",
		NebulaIPs: []string{"192.168.100.51"},
	})

	if got := hostCert.UnsafeNetworks(); len(got) != 0 {
		t.Errorf("issued cert unsafe networks = %v, want none", got)
	}
}

// The per-shape rejection rules are covered in models; what this proves is
// that handleCreateHost calls the validator at all and maps its error to 400.
// The overlay case is kept separate because it exercises different plumbing —
// the handler passing network.CIDRs through.
func TestCreateHost_RejectsInvalidUnsafeNetworks(t *testing.T) {
	srv, _ := newTestServer(t)
	networkID := createNetwork(t, srv)

	cases := []struct {
		name     string
		networks []string
	}{
		{"malformed prefix", []string{"192.168.1.1/24"}},
		{"overlaps the overlay", []string{"192.168.100.0/24"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(createHostRequest{
				NetworkID:      networkID,
				Name:           "gw-" + tc.name,
				NebulaIPs:      []string{"192.168.100.60"},
				UnsafeNetworks: tc.networks,
			})
			request := httptest.NewRequest(http.MethodPost, "/api/v1/hosts", bytes.NewReader(body))
			authRequest(request)
			recorder := httptest.NewRecorder()
			srv.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusBadRequest {
				t.Errorf("got %d, want 400; body: %s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

// Editing unsafe_networks on an enrolled host must both persist and schedule a
// re-issuance: the prefix only takes effect once it is inside a signed cert,
// so a saved-but-not-rekeyed edit would look applied while still dropping
// every packet.
func TestUpdateHost_UnsafeNetworksSchedulesRekey(t *testing.T) {
	srv, sqliteStore := newTestServer(t)
	networkID := createNetwork(t, srv)

	body, _ := json.Marshal(createHostRequest{
		NetworkID: networkID, Name: "gw-edit", NebulaIPs: []string{"192.168.100.70"},
	})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/hosts", bytes.NewReader(body))
	authRequest(request)
	recorder := httptest.NewRecorder()
	srv.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("create host: %d %s", recorder.Code, recorder.Body.String())
	}
	var created createHostResponse
	if err := json.NewDecoder(recorder.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}

	patch, _ := json.Marshal(map[string]any{"unsafe_networks": []string{"192.168.1.0/24"}})
	request = httptest.NewRequest(http.MethodPatch, "/api/v1/hosts/"+created.Host.ID, bytes.NewReader(patch))
	authRequest(request)
	recorder = httptest.NewRecorder()
	srv.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("patch host: %d %s", recorder.Code, recorder.Body.String())
	}

	stored, err := sqliteStore.GetHost(t.Context(), created.Host.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.UnsafeNetworks) != 1 || stored.UnsafeNetworks[0] != "192.168.1.0/24" {
		t.Fatalf("unsafe networks = %v, want [192.168.1.0/24]", stored.UnsafeNetworks)
	}
	if !stored.PendingRekey {
		t.Error("editing unsafe_networks must schedule a certificate re-issuance")
	}
}

func TestUpdateHost_RejectsInvalidUnsafeNetworks(t *testing.T) {
	srv, _ := newTestServer(t)
	networkID := createNetwork(t, srv)

	body, _ := json.Marshal(createHostRequest{
		NetworkID: networkID, Name: "gw-bad-edit", NebulaIPs: []string{"192.168.100.71"},
	})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/hosts", bytes.NewReader(body))
	authRequest(request)
	recorder := httptest.NewRecorder()
	srv.ServeHTTP(recorder, request)
	var created createHostResponse
	if err := json.NewDecoder(recorder.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}

	patch, _ := json.Marshal(map[string]any{"unsafe_networks": []string{"192.168.1.1/24"}})
	request = httptest.NewRequest(http.MethodPatch, "/api/v1/hosts/"+created.Host.ID, bytes.NewReader(patch))
	authRequest(request)
	recorder = httptest.NewRecorder()
	srv.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400; body: %s", recorder.Code, recorder.Body.String())
	}
}
