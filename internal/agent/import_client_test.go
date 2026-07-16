package agent

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"

	"github.com/forgekeep/nebula-mesh/internal/importproof"
)

func TestImportExistingCompletesChallengeAndReusesSigningKey(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	fixture.writeDefaultConfig(t)
	server := newAgentImportMock(t)
	signingPath := filepath.Join(t.TempDir(), "host.signing.key")

	firstDiscovery, err := DiscoverExisting(fixture.configPath)
	if err != nil {
		t.Fatal(err)
	}
	result, err := ImportExisting(t.Context(), server.URL, "nmi_test-token", signingPath, firstDiscovery)
	if err != nil {
		t.Fatal(err)
	}
	if result.HostID != "imported-host" || result.SessionID != "session-1" || result.Status != "importing" {
		t.Fatalf("result = %#v", result)
	}
	if len(firstDiscovery.HostPrivateKey) != 0 {
		t.Fatal("host private key was not wiped after import proof")
	}
	firstSigningPEM, err := os.ReadFile(signingPath)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(signingPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("signing key mode = %v, err = %v", info.Mode().Perm(), err)
	}

	secondDiscovery, err := DiscoverExisting(fixture.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ImportExisting(t.Context(), server.URL, "nmi_test-token", signingPath, secondDiscovery); err != nil {
		t.Fatal(err)
	}
	secondSigningPEM, err := os.ReadFile(signingPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstSigningPEM) != string(secondSigningPEM) {
		t.Fatal("retry replaced the persisted signing key")
	}
	if server.signingPEMs[0] != server.signingPEMs[1] {
		t.Fatal("retry did not bind the same signing public key")
	}
	if server.proofFailures != 0 {
		t.Fatalf("proof failures = %d", server.proofFailures)
	}
}

func TestImportExistingRecoversCommittedRegistrationAfterLostResponse(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	fixture.writeDefaultConfig(t)
	server := newAgentImportMock(t)
	server.loseFirstFinal = true
	server.commitLostFinal = true
	discovery, err := DiscoverExisting(fixture.configPath)
	if err != nil {
		t.Fatal(err)
	}
	result, err := ImportExisting(t.Context(), server.URL, "nmi_test-token", filepath.Join(t.TempDir(), "host.signing.key"), discovery)
	if err != nil {
		t.Fatal(err)
	}
	if result.Created || result.Status != "importing" || result.Fingerprint == "" || server.finalCalls != 2 || server.pollCalls != 1 {
		t.Fatalf("recovered result=%#v final_calls=%d poll_calls=%d", result, server.finalCalls, server.pollCalls)
	}
}

func TestImportExistingRetriesExactFinalOnlyAfterUnauthorizedPoll(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	fixture.writeDefaultConfig(t)
	server := newAgentImportMock(t)
	server.loseFirstFinal = true
	discovery, err := DiscoverExisting(fixture.configPath)
	if err != nil {
		t.Fatal(err)
	}
	result, err := ImportExisting(t.Context(), server.URL, "nmi_test-token", filepath.Join(t.TempDir(), "host.signing.key"), discovery)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Created || server.finalCalls != 2 || server.pollCalls != 0 {
		t.Fatalf("result=%#v final_calls=%d poll_calls=%d", result, server.finalCalls, server.pollCalls)
	}
	if len(server.finalBodies) != 2 || server.finalBodies[0] != server.finalBodies[1] {
		t.Fatal("retry did not reuse the exact challenge proof payload")
	}
}

func TestImportExistingDoesNotConfirmExplicitConflict(t *testing.T) {
	for _, conflict := range []string{"agent_import_conflict", "import_challenge_used"} {
		t.Run(conflict, func(t *testing.T) {
			fixture := newDiscoveryFixture(t)
			fixture.writeDefaultConfig(t)
			server := newAgentImportMock(t)
			server.registrationLive = true
			server.finalConflict = conflict
			discovery, err := DiscoverExisting(fixture.configPath)
			if err != nil {
				t.Fatal(err)
			}
			_, err = ImportExisting(t.Context(), server.URL, "nmi_test-token", filepath.Join(t.TempDir(), "host.signing.key"), discovery)
			if err == nil {
				t.Fatal("ImportExisting succeeded for explicit conflict")
			}
			if server.finalCalls != 1 || server.pollCalls != 0 {
				t.Fatalf("final_calls=%d poll_calls=%d, want 1/0", server.finalCalls, server.pollCalls)
			}
		})
	}
}

type agentImportMock struct {
	*httptest.Server
	expectedProofHash string
	signingPEMs       []string
	proofFailures     int
	payloadHash       string
	fingerprint       string
	loseFirstFinal    bool
	commitLostFinal   bool
	registrationLive  bool
	finalConflict     string
	finalCalls        int
	finalBodies       []string
	pollCalls         int
}

func newAgentImportMock(t *testing.T) *agentImportMock {
	t.Helper()
	mock := &agentImportMock{}
	mock.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		var body struct {
			Token                    string `json:"token"`
			AgentSigningPublicKeyPEM string `json:"agent_signing_public_key_pem"`
			PayloadHash              string `json:"payload_hash"`
			Snapshot                 struct {
				CertificatePEM string `json:"certificate_pem"`
			} `json:"snapshot"`
			Proof string `json:"proof"`
		}
		switch request.URL.Path {
		case "/api/v1/agent/import/challenge":
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode import challenge: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			hostCertificate, _, err := cert.UnmarshalCertificateFromPEM([]byte(body.Snapshot.CertificatePEM))
			if err != nil {
				t.Errorf("parse host cert: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			fingerprint, err := hostCertificate.Fingerprint()
			if err != nil {
				t.Error(err)
				return
			}
			challenge, proofHash, err := importproof.Generate(nilReader{}, hostCertificate.PublicKey(), importproof.Binding{
				SessionID: "session-1", CertificateFingerprint: fingerprint,
				AgentSigningPublicKeyPEM: body.AgentSigningPublicKeyPEM, PayloadHash: body.PayloadHash,
			})
			if err != nil {
				t.Errorf("generate challenge: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			mock.expectedProofHash = proofHash
			mock.payloadHash = body.PayloadHash
			mock.fingerprint = fingerprint
			mock.signingPEMs = append(mock.signingPEMs, body.AgentSigningPublicKeyPEM)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"challenge_id": "challenge-1", "session_id": "session-1",
				"server_public_key": base64.RawURLEncoding.EncodeToString(challenge.ServerPublicKey),
				"server_nonce":      base64.RawURLEncoding.EncodeToString(challenge.Nonce),
				"expires_at":        time.Now().Add(time.Minute),
			})
		case "/api/v1/agent/import":
			mock.finalCalls++
			rawBody, err := io.ReadAll(request.Body)
			if err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			mock.finalBodies = append(mock.finalBodies, string(rawBody))
			if err := json.Unmarshal(rawBody, &body); err != nil {
				t.Errorf("decode import request: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			proof, err := base64.RawURLEncoding.DecodeString(body.Proof)
			if err != nil || len(proof) != sha256.Size || !importproof.VerifyHash(mock.expectedProofHash, proof) || body.PayloadHash != mock.payloadHash {
				mock.proofFailures++
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if mock.loseFirstFinal && mock.finalCalls == 1 {
				mock.registrationLive = mock.commitLostFinal
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"host_id":`))
				return
			}
			if mock.commitLostFinal && mock.registrationLive {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":"import_challenge_used"}`))
				return
			}
			if mock.finalConflict != "" {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":"` + mock.finalConflict + `"}`))
				return
			}
			mock.registrationLive = true
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"host_id": "imported-host", "certificate_fingerprint": mock.fingerprint,
				"status": "importing", "created": true,
			})
		case "/api/v1/agent/updates":
			mock.pollCalls++
			if !mock.registrationLive {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"unknown_agent"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"has_updates": false, "import_pending": true})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(mock.Close)
	return mock
}

// nilReader supplies deterministic non-secret bytes to keep the test focused
// on client/server proof agreement. Production always uses crypto/rand.
type nilReader struct{}

func (nilReader) Read(buffer []byte) (int, error) {
	for index := range buffer {
		buffer[index] = byte(index + 1)
	}
	return len(buffer), nil
}
