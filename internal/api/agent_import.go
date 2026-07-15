package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/slackhq/nebula/cert"

	"github.com/forgekeep/nebula-mesh/internal/bootstraptoken"
	"github.com/forgekeep/nebula-mesh/internal/importproof"
	"github.com/forgekeep/nebula-mesh/internal/meshimport"
	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

const agentImportChallengeTTL = 2 * time.Minute

type agentImportPayload struct {
	Token                    string              `json:"token"`
	CACertificatePEM         string              `json:"ca_certificate_pem"`
	AgentSigningPublicKeyPEM string              `json:"agent_signing_public_key_pem"`
	PayloadHash              string              `json:"payload_hash"`
	Snapshot                 meshimport.Snapshot `json:"snapshot"`
}

type agentImportRequest struct {
	Token                    string              `json:"token"`
	CACertificatePEM         string              `json:"ca_certificate_pem"`
	AgentSigningPublicKeyPEM string              `json:"agent_signing_public_key_pem"`
	PayloadHash              string              `json:"payload_hash"`
	Snapshot                 meshimport.Snapshot `json:"snapshot"`
	ChallengeID              string              `json:"challenge_id"`
	Proof                    string              `json:"proof"`
}

func (r agentImportRequest) payload() agentImportPayload {
	return agentImportPayload{
		Token: r.Token, CACertificatePEM: r.CACertificatePEM,
		AgentSigningPublicKeyPEM: r.AgentSigningPublicKeyPEM,
		PayloadHash:              r.PayloadHash, Snapshot: r.Snapshot,
	}
}

type agentImportChallengeResponse struct {
	ChallengeID     string    `json:"challenge_id"`
	SessionID       string    `json:"session_id"`
	ServerPublicKey string    `json:"server_public_key"`
	ServerNonce     string    `json:"server_nonce"`
	ExpiresAt       time.Time `json:"expires_at"`
}

type agentImportResponse struct {
	HostID                 string            `json:"host_id"`
	CertificateFingerprint string            `json:"certificate_fingerprint"`
	Status                 models.HostStatus `json:"status"`
	Created                bool              `json:"created"`
}

type verifiedAgentImport struct {
	session         *models.MeshImport
	ca              *models.CA
	network         *models.Network
	hostCertificate cert.Certificate
	fingerprint     string
	payloadHash     string
	snapshot        meshimport.Snapshot
	signingPEM      string
}

func (s *Server) handleAgentImportChallenge(w http.ResponseWriter, r *http.Request) {
	var request agentImportPayload
	if err := decodeJSONStrict(r, &request); err != nil {
		writeAgentImportDecodeError(w, err)
		return
	}
	verified, ok := s.verifyAgentImportPayload(w, r, request)
	if !ok {
		return
	}
	binding := verified.proofBinding()
	challengeMaterial, expectedProofHash, err := importproof.Generate(rand.Reader, verified.hostCertificate.PublicKey(), binding)
	if err != nil {
		s.logger.Error("generate agent import proof", "error", err)
		writeError(w, http.StatusInternalServerError, "agent_import_failed")
		return
	}
	now := s.now()
	expiresAt := now.Add(agentImportChallengeTTL)
	challenge := &models.MeshImportChallenge{
		ID: uuid.NewString(), MeshImportID: verified.session.ID,
		CertificateFingerprint: verified.fingerprint, AgentSigningPubPEM: verified.signingPEM,
		PayloadHash: verified.payloadHash, ServerNonce: expectedProofHash,
		ExpiresAt: expiresAt, CreatedAt: now,
	}
	if err := s.store.CreateMeshImportChallenge(r.Context(), challenge, now); err != nil {
		s.writeAgentImportStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, agentImportChallengeResponse{
		ChallengeID: challenge.ID, SessionID: verified.session.ID,
		ServerPublicKey: base64.RawURLEncoding.EncodeToString(challengeMaterial.ServerPublicKey),
		ServerNonce:     base64.RawURLEncoding.EncodeToString(challengeMaterial.Nonce), ExpiresAt: expiresAt,
	})
}

func (s *Server) handleAgentImport(w http.ResponseWriter, r *http.Request) {
	var request agentImportRequest
	if err := decodeJSONStrict(r, &request); err != nil {
		writeAgentImportDecodeError(w, err)
		return
	}
	if request.ChallengeID == "" || request.Proof == "" {
		writeError(w, http.StatusBadRequest, "challenge_id_and_proof_required")
		return
	}
	verified, ok := s.verifyAgentImportPayload(w, r, request.payload())
	if !ok {
		return
	}
	challenge, err := s.store.GetMeshImportChallenge(r.Context(), request.ChallengeID)
	if err != nil {
		s.writeAgentImportStoreError(w, err)
		return
	}
	if challenge.MeshImportID != verified.session.ID || challenge.CertificateFingerprint != verified.fingerprint ||
		challenge.AgentSigningPubPEM != verified.signingPEM || challenge.PayloadHash != verified.payloadHash {
		writeError(w, http.StatusUnauthorized, "invalid_import_proof")
		return
	}
	if !s.now().Before(challenge.ExpiresAt) {
		writeError(w, http.StatusGone, "import_challenge_expired")
		return
	}
	proof, err := base64.RawURLEncoding.DecodeString(request.Proof)
	if err != nil || len(proof) != sha256.Size || !importproof.VerifyHash(challenge.ServerNonce, proof) {
		writeError(w, http.StatusUnauthorized, "invalid_import_proof")
		return
	}
	defer clear(proof)

	hostID := uuid.NewString()
	snapshotID := uuid.NewString()
	verified.snapshot.ID = snapshotID
	verified.snapshot.HostID = hostID
	report := meshimport.Reconcile(meshimport.ReconcileInput{
		NetworkID: verified.network.ID, CAID: verified.ca.ID, NetworkCIDRs: verified.network.CIDRs,
		CACertificatePEM: verified.ca.CertPEM, CAFingerprint: verified.ca.Fingerprint,
		Snapshots: []meshimport.Snapshot{verified.snapshot}, Now: s.now(),
	})
	if len(report.Proposal.Hosts) != 1 {
		writeError(w, http.StatusBadRequest, "invalid_import_snapshot")
		return
	}
	host := report.Proposal.Hosts[0].Host
	host.SigningPubPEM = verified.signingPEM
	host.Status = models.HostStatusImporting
	host.CreatedAt = s.now()
	host.UpdatedAt = host.CreatedAt
	snapshotJSON, err := json.Marshal(verified.snapshot)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_import_snapshot")
		return
	}
	registration := &models.MeshImportRegistration{
		ChallengeID: request.ChallengeID, CertificateNotBefore: verified.hostCertificate.NotBefore(),
		CertificateNotAfter: verified.hostCertificate.NotAfter(), Host: &host,
		Snapshot: &models.MeshImportSnapshot{
			ID: snapshotID, MeshImportID: verified.session.ID, HostID: hostID,
			CertificateFingerprint: verified.fingerprint, CertificatePEM: verified.snapshot.CertificatePEM,
			AgentSigningPubPEM: verified.signingPEM, PayloadHash: verified.payloadHash,
			SnapshotJSON: string(snapshotJSON), CreatedAt: s.now(), UpdatedAt: s.now(),
		},
		Profile: &models.HostAgentProfile{
			HostID: hostID, MeshImportID: verified.session.ID,
			NebulaConfigPath: verified.snapshot.Profile.NebulaConfigPath,
			NebulaCAPath:     verified.snapshot.Profile.NebulaCAPath,
			NebulaCertPath:   verified.snapshot.Profile.NebulaCertPath,
			NebulaKeyPath:    verified.snapshot.Profile.NebulaKeyPath,
			ConfigAckV1:      verified.snapshot.Profile.ConfigAckV1,
			CreatedAt:        s.now(), UpdatedAt: s.now(),
		},
	}
	result, err := s.store.RegisterImportedHost(r.Context(), registration, s.now())
	if err != nil {
		s.writeAgentImportStoreError(w, err)
		return
	}
	s.recordAuditAction(r.Context(), auditMeshImportHostRegistered, result.Host.ID,
		fmt.Sprintf("session=%s fingerprint=%s payload_hash=%s", verified.session.ID, verified.fingerprint, verified.payloadHash))
	status := http.StatusOK
	if result.Created {
		status = http.StatusCreated
	}
	writeJSON(w, status, agentImportResponse{
		HostID: result.Host.ID, CertificateFingerprint: verified.fingerprint,
		Status: result.Host.Status, Created: result.Created,
	})
}

func writeAgentImportDecodeError(w http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, "import_snapshot_too_large")
		return
	}
	writeError(w, http.StatusBadRequest, "invalid_import_request")
}

func (s *Server) verifyAgentImportPayload(w http.ResponseWriter, r *http.Request, request agentImportPayload) (*verifiedAgentImport, bool) {
	if err := bootstraptoken.ValidatePurpose(request.Token, bootstraptoken.PurposeMeshImport, false); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_import_token")
		return nil, false
	}
	session, err := s.store.GetMeshImportByTokenHash(r.Context(), bootstraptoken.Hash(request.Token), s.now())
	if err != nil {
		s.writeAgentImportStoreError(w, err)
		return nil, false
	}
	ca, err := s.store.GetCA(r.Context(), session.CAID)
	if err != nil {
		s.writeAgentImportStoreError(w, err)
		return nil, false
	}
	network, err := s.store.GetNetwork(r.Context(), session.NetworkID)
	if err != nil {
		s.writeAgentImportStoreError(w, err)
		return nil, false
	}
	configuredCA, remainder, err := cert.UnmarshalCertificateFromPEM([]byte(request.CACertificatePEM))
	if err != nil || strings.TrimSpace(string(remainder)) != "" || !configuredCA.IsCA() {
		writeError(w, http.StatusBadRequest, "invalid_ca_bundle")
		return nil, false
	}
	configuredFingerprint, err := configuredCA.Fingerprint()
	if err != nil || !strings.EqualFold(configuredFingerprint, session.CAFingerprint) {
		writeError(w, http.StatusBadRequest, "invalid_ca_bundle")
		return nil, false
	}
	storedCA, remainder, err := cert.UnmarshalCertificateFromPEM([]byte(ca.CertPEM))
	if err != nil || strings.TrimSpace(string(remainder)) != "" || !storedCA.IsCA() {
		s.logger.Error("stored import CA is invalid", "ca_id", ca.ID)
		writeError(w, http.StatusInternalServerError, "agent_import_failed")
		return nil, false
	}
	hostCertificate, remainder, err := cert.UnmarshalCertificateFromPEM([]byte(request.Snapshot.CertificatePEM))
	if err != nil || strings.TrimSpace(string(remainder)) != "" || hostCertificate.IsCA() || hostCertificate.Curve() != cert.Curve_CURVE25519 {
		writeError(w, http.StatusBadRequest, "invalid_host_certificate")
		return nil, false
	}
	fingerprint, err := hostCertificate.Fingerprint()
	if err != nil || hostCertificate.Expired(s.now()) {
		writeError(w, http.StatusBadRequest, "invalid_host_certificate")
		return nil, false
	}
	pool := cert.NewCAPool()
	if err := pool.AddCA(storedCA); err != nil {
		s.logger.Error("build import CA pool", "ca_id", ca.ID, "error", err)
		writeError(w, http.StatusInternalServerError, "agent_import_failed")
		return nil, false
	}
	if _, err := pool.VerifyCertificate(s.now(), hostCertificate); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_host_certificate")
		return nil, false
	}
	if _, err := strictSigningPublicKeyPEM(request.AgentSigningPublicKeyPEM); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_signing_public_key")
		return nil, false
	}
	if err := meshimport.ValidateSnapshot(request.Snapshot, meshimport.Limits{}); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_import_snapshot")
		return nil, false
	}
	if len(request.Snapshot.Config.CARootFingerprints) != 1 ||
		!strings.EqualFold(request.Snapshot.Config.CARootFingerprints[0], session.CAFingerprint) {
		writeError(w, http.StatusBadRequest, "invalid_ca_bundle")
		return nil, false
	}
	payloadJSON, err := json.Marshal(request.Snapshot)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_import_snapshot")
		return nil, false
	}
	payloadSum := sha256.Sum256(payloadJSON)
	payloadHash := hex.EncodeToString(payloadSum[:])
	if !strings.EqualFold(payloadHash, strings.TrimSpace(request.PayloadHash)) {
		writeError(w, http.StatusBadRequest, "payload_hash_mismatch")
		return nil, false
	}
	return &verifiedAgentImport{
		session: session, ca: ca, network: network, hostCertificate: hostCertificate,
		fingerprint: fingerprint, payloadHash: payloadHash, snapshot: request.Snapshot,
		signingPEM: request.AgentSigningPublicKeyPEM,
	}, true
}

func strictSigningPublicKeyPEM(value string) ([]byte, error) {
	block, remainder := pem.Decode([]byte(value))
	if block == nil || block.Type != SigningPublicKeyPEMType || len(block.Bytes) != ed25519.PublicKeySize || strings.TrimSpace(string(remainder)) != "" {
		return nil, ErrBadSigningPEM
	}
	return block.Bytes, nil
}

func (verified *verifiedAgentImport) proofBinding() importproof.Binding {
	return importproof.Binding{
		SessionID: verified.session.ID, CertificateFingerprint: verified.fingerprint,
		AgentSigningPublicKeyPEM: verified.signingPEM, PayloadHash: verified.payloadHash,
	}
}

func (s *Server) writeAgentImportStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrMeshImportTokenExpired):
		writeError(w, http.StatusGone, "import_token_expired")
	case errors.Is(err, store.ErrMeshImportNotCollecting):
		writeError(w, http.StatusGone, "import_not_collecting")
	case errors.Is(err, store.ErrMeshImportChallengeExpired):
		writeError(w, http.StatusGone, "import_challenge_expired")
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusUnauthorized, "invalid_import_token_or_challenge")
	case errors.Is(err, store.ErrMeshImportChallengeUsed),
		errors.Is(err, store.ErrMeshImportChallengeMismatch),
		errors.Is(err, store.ErrMeshImportSigningKeyConflict),
		errors.Is(err, store.ErrMeshImportPayloadConflict),
		errors.Is(err, store.ErrMeshImportExpectedHostsReached),
		errors.Is(err, store.ErrDuplicateEntry), errors.Is(err, store.ErrIPTaken):
		writeError(w, http.StatusConflict, "agent_import_conflict")
	default:
		s.logger.Error("agent import store operation", "error", err)
		writeError(w, http.StatusInternalServerError, "agent_import_failed")
	}
}
