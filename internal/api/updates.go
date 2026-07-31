package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/slackhq/nebula/cert"

	apipop "github.com/forgekeep/nebula-mesh/internal/api/pop"
	"github.com/forgekeep/nebula-mesh/internal/bootstraptoken"
	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/pki"
	corepop "github.com/forgekeep/nebula-mesh/internal/pop"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

type agentUpdatesResponse struct {
	HasUpdates      bool     `json:"has_updates"`
	CertificatePEM  *string  `json:"certificate_pem,omitempty"`
	CACertPEM       *string  `json:"ca_certificate_pem,omitempty"`
	ConfigYAML      *string  `json:"config_yaml,omitempty"`
	ConfigVersion   int      `json:"config_version,omitempty"`
	Blocklist       []string `json:"blocklist"`
	ImportPending   bool     `json:"import_pending,omitempty"`
	RekeyRequired   bool     `json:"rekey_required,omitempty"`
	EnrollmentToken string   `json:"enrollment_token,omitempty"`
}

// pollClockSkew is the symmetric tolerance applied to X-Nebula-Timestamp
// (ADR 0004 §7.1).
const pollClockSkew = 5 * time.Minute

// overlapWindow returns how long the previous cert fingerprint is accepted
// after auto-renew lands. ADR 0004 §7.1 specifies "2 × poll_interval"; the
// server does not see the agent's poll cadence directly, so we pick a
// conservative two minutes — that covers the 30s default plus retries.
func overlapWindow() time.Duration { return 2 * time.Minute }

func (s *Server) handleAgentUpdates(w http.ResponseWriter, r *http.Request) {
	headers, ok := readAgentAuthHeaders(w, r)
	if !ok {
		return
	}
	fingerprint := headers.fingerprint

	host, err := s.store.GetHostByFingerprint(r.Context(), fingerprint)
	if errors.Is(err, store.ErrNotFound) {
		if tombstone, tombstoneErr := s.store.GetMeshImportTombstone(r.Context(), fingerprint); tombstoneErr == nil {
			if !s.authenticateMeshImportTombstonePoll(w, r, tombstone, headers.timestamp, headers.nonce, headers.signature) {
				return
			}
			s.recordAuditAction(r.Context(), auditHostAuthFailed, tombstone.FormerHostID, "import_canceled")
			writeRevocation(w, http.StatusGone, revocationGoneResponse{
				Reason:  "import_canceled",
				Message: tombstone.TerminalReason,
				At:      s.now().UTC(),
			})
			return
		} else if !errors.Is(tombstoneErr, store.ErrNotFound) {
			s.logger.Error("get mesh import tombstone", "error", tombstoneErr)
			writeError(w, http.StatusInternalServerError, "failed to authenticate host")
			return
		}
		// The fingerprint is not bound to any live host row. If it shows
		// up in the blocklist the row was deleted after enrollment — in
		// that case the agent gets a structured 410 gone so it stops the
		// poll loop instead of retrying forever.
		if s.fingerprintInBlocklist(r.Context(), fingerprint) {
			s.recordAuditAction(r.Context(), auditHostAuthFailed, "", authReasonGone)
			writeRevocation(w, http.StatusGone, revocationGoneResponse{
				Reason:  "gone",
				Message: "host row no longer exists; agent should stop and re-enroll if a fresh --token is provisioned",
				At:      time.Now().UTC(),
			})
			return
		}
		s.recordAuditAction(r.Context(), auditHostAuthFailed, "", authReasonUnknownFingerprint)
		writeError(w, http.StatusUnauthorized, "unknown_fingerprint")
		return
	}
	if err != nil {
		s.logger.Error("get host by fingerprint", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get host")
		return
	}

	if !s.authenticateKnownAgentRequest(w, r, host, headers) {
		return
	}
	now := s.now()

	// Revocation signal. Blocked hosts get a structured 403 with a
	// machine-readable body so the agent can log loudly and exit (ADR 0004
	// §7.1). The poll loop must not silently drain configuration to a host
	// we have already revoked.
	if host.Status == models.HostStatusBlocked {
		s.recordAuditAction(r.Context(), auditHostAuthFailed, host.ID, authReasonRevoked)
		writeRevocation(w, http.StatusForbidden, revocationRevokedResponse{
			Reason:    "revoked",
			Message:   "host is blocked; agent should stop the poll loop and exit 0",
			BlockedAt: time.Now().UTC(),
		})
		return
	}
	if host.Status == models.HostStatusImporting {
		writeJSON(w, http.StatusOK, struct {
			HasUpdates    bool `json:"has_updates"`
			ImportPending bool `json:"import_pending"`
		}{ImportPending: true})
		return
	}
	profile, profileErr := s.store.GetHostAgentProfile(r.Context(), host.ID)
	if profileErr != nil && !errors.Is(profileErr, store.ErrNotFound) {
		s.logger.Error("get host agent profile", "host", host.ID, "error", profileErr)
		writeError(w, http.StatusInternalServerError, "failed to get agent profile")
		return
	}
	configAckV1 := profileErr == nil && profile.ConfigAckV1
	pollingPrevious := host.PrevCertFingerprint != "" && fingerprint == host.PrevCertFingerprint

	// Cert-rotation overlap window (ADR 0004 §7.1).
	//
	// If the agent polled with the *current* cert fingerprint and the row
	// still has a parked previous fingerprint, clear it — the rotation
	// completed successfully and we no longer need the dual-accept window.
	// If the agent polled with the previous fingerprint and the wall-clock
	// window has expired (2 × poll interval, lower-bounded at one minute),
	// clear it too so a forever-stale agent does not keep the slot.
	if host.PrevCertFingerprint != "" {
		if fingerprint == host.CertFingerprint {
			if err := s.store.ClearPrevFingerprint(r.Context(), host.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
				s.logger.Error("clear prev fingerprint", "error", err)
			}
		} else if !configAckV1 && host.CertRotatedAt != nil && now.Sub(*host.CertRotatedAt) > overlapWindow() {
			if err := s.store.ClearPrevFingerprint(r.Context(), host.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
				s.logger.Error("clear prev fingerprint (timeout)", "error", err)
			}
			// Window expired: this old fingerprint should no longer be
			// accepted. Treat as unknown so the agent re-enrolls.
			s.recordAuditAction(r.Context(), auditHostAuthFailed, host.ID, authReasonUnknownFingerprint)
			writeError(w, http.StatusUnauthorized, "unknown_fingerprint")
			return
		}
	}

	// non-critical: log and continue — last_seen is informational
	if err := s.store.UpdateHostLastSeen(r.Context(), host.ID, now); err != nil {
		s.logger.Error("update last seen", "error", err)
	} else if s.hostSeen != nil {
		s.hostSeen(host.ID, now, host.NetworkID)
	}

	// Get the blocklist scoped to this host's CA — an agent only needs to reject
	// peers under its own CA, and shipping the global list leaks other tenants'
	// revoked fingerprints across the boundary (#203).
	blocklist, err := s.store.GetBlocklistForCA(r.Context(), host.CAID)
	if err != nil {
		s.logger.Error("get blocklist", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get blocklist")
		return
	}

	resp := agentUpdatesResponse{
		Blocklist: blocklist,
	}
	needsCABundle := false
	if pollingPrevious && configAckV1 {
		currentCertificate, currentErr := s.store.GetCurrentCertificate(r.Context(), host.ID)
		if currentErr != nil {
			s.logger.Error("load current certificate for reliable redelivery", "host", host.ID, "error", currentErr)
			writeError(w, http.StatusInternalServerError, "failed to load current certificate")
			return
		}
		certificate := string(currentCertificate)
		resp.CertificatePEM = &certificate
		needsCABundle = true
	}

	// Check if certificate needs renewal
	certInfo, err := s.store.GetCertificateInfo(r.Context(), host.ID)
	if !pollingPrevious && err == nil && pki.ShouldRenewAt(certInfo.NotBefore, certInfo.NotAfter, now) {
		signed, renewErr := s.signHostCert(r.Context(), host, certInfo, now)

		if renewErr != nil {
			s.metrics.recordRenewal(resultError)
			s.logger.Error("auto-renew cert", "host", host.Name, "error", renewErr)
		} else {
			s.metrics.recordSignature(host.CAID)
			// Save outside CA lock — DB I/O does not need CA access
			if saveErr := s.store.SaveCertificateAndUpdateHostCert(r.Context(), host.ID, signed.certPEM, signed.fp, signed.notBefore, signed.notAfter); saveErr != nil {
				s.metrics.recordRenewal(resultError)
				s.logger.Error("save renewed cert", "host", host.Name, "error", saveErr)
				writeError(w, http.StatusInternalServerError, "failed to save renewed certificate")
				return
			}
			s.metrics.recordRenewal(resultOK)
			certStr := string(signed.certPEM)
			resp.CertificatePEM = &certStr
			needsCABundle = true
			s.logger.Info("certificate renewed", "host", host.Name)
		}
	}

	// A successor-only rotation is itself an update. Renewal and reliable
	// old-fingerprint redelivery use the same lossless current+successor bundle.
	if host.CAID != "" {
		if successor, successorErr := s.store.FindCAByPredecessor(r.Context(), host.CAID); successorErr == nil && successor != nil {
			needsCABundle = true
		} else if successorErr != nil && !errors.Is(successorErr, store.ErrNotFound) {
			s.logger.Error("find CA successor", "host", host.ID, "error", successorErr)
		}
	}
	if needsCABundle {
		bundle, bundleErr := s.renderAgentCABundle(r.Context(), host.CAID)
		if bundleErr != nil {
			s.logger.Error("render agent CA bundle", "host", host.ID, "error", bundleErr)
			writeError(w, http.StatusInternalServerError, "failed to render CA bundle")
			return
		}
		resp.CACertPEM = &bundle
	}

	// Check if the network config version moved since this host's last poll.
	// If it did, re-render the Nebula config with the current lighthouse list
	// (and any other network-level config) and ship it to the agent.
	netVersion, verErr := s.store.GetNetworkConfigVersion(r.Context(), host.NetworkID)
	if verErr != nil {
		s.logger.Error("get network config version", "error", verErr)
	} else {
		hostVersion, hvErr := s.store.GetHostConfigVersion(r.Context(), host.ID)
		if hvErr != nil {
			s.logger.Error("get host config version", "error", hvErr)
		} else if hostVersion != netVersion || (configAckV1 && profile.PendingConfigVersion != 0) {
			configYAML, cfgErr := s.renderHostConfig(r.Context(), host)
			if cfgErr != nil {
				s.logger.Error("render host config", "host", host.Name, "error", cfgErr)
			} else {
				if configAckV1 {
					if pendingErr := s.store.SetPendingHostConfigVersion(r.Context(), host.ID, netVersion); pendingErr != nil {
						s.logger.Error("set pending host config version", "host", host.Name, "error", pendingErr)
					} else {
						cfgStr := string(configYAML)
						resp.ConfigYAML = &cfgStr
						resp.ConfigVersion = netVersion
						s.logger.Info("config delivery pending ack", "host", host.Name, "from_version", hostVersion, "to_version", netVersion)
					}
				} else if uvErr := s.store.UpdateHostConfigVersion(r.Context(), host.ID, netVersion); uvErr != nil {
					s.logger.Error("update host config version", "host", host.Name, "error", uvErr)
				} else {
					cfgStr := string(configYAML)
					resp.ConfigYAML = &cfgStr
					s.logger.Info("config rolled out", "host", host.Name, "from_version", hostVersion, "to_version", netVersion)
				}
			}
		}
	}

	// Rekey signal: pending_rekey on the host row (force-rotate?new_key=true,
	// or an edit to a certificate-bound field) makes the next poll under the
	// existing fingerprint carry a single-use enrollment token so the agent
	// can re-enroll a fresh keypair.
	//
	// The flag stays set until the agent actually completes the enrollment,
	// which clears it inside that transaction. A rekey the agent cannot
	// finish — an unwritable directory, a crash, a host that never comes
	// back — is therefore re-offered on the following poll instead of being
	// silently lost, which used to strand the host on its old certificate
	// with the server reporting nothing pending.
	//
	// Re-offering means minting a fresh token each poll while the rekey is
	// outstanding; only the token hash is stored, so the previous one cannot
	// be re-sent. CreateTokenForHost deletes the host's other unused tokens,
	// so at most one is ever live. The agent stops polling while it
	// re-enrolls, so it cannot invalidate the token it is currently using.
	if host.PendingRekey {
		tokenStr, tokenErr := bootstraptoken.Generate(bootstraptoken.PurposeEnrollment)
		if tokenErr != nil {
			s.logger.Error("generate rekey token", "host", host.ID, "error", tokenErr)
		} else {
			expiresAt := now.Add(s.tokenTTLFor(r.Context(), host.NetworkID))
			if err := s.store.CreateTokenForHost(r.Context(), host.ID, tokenStr, expiresAt); err != nil {
				s.logger.Error("mint rekey token", "host", host.ID, "error", err)
			} else {
				resp.RekeyRequired = true
				resp.EnrollmentToken = tokenStr
			}
		}
	}

	resp.HasUpdates = len(blocklist) > 0 || resp.CertificatePEM != nil || resp.CACertPEM != nil || resp.ConfigYAML != nil || resp.RekeyRequired
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) renderAgentCABundle(ctx context.Context, caID string) (string, error) {
	current, err := s.store.GetCA(ctx, caID)
	if err != nil {
		return "", err
	}
	bundle := current.CertPEM
	successor, err := s.store.FindCAByPredecessor(ctx, caID)
	if err == nil && successor != nil {
		bundle += "\n" + successor.CertPEM
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return "", err
	}
	return bundle, nil
}

func (s *Server) authenticateMeshImportTombstonePoll(
	w http.ResponseWriter,
	r *http.Request,
	tombstone *models.MeshImportTombstone,
	timestamp, nonce, signatureB64 string,
) bool {
	signingPub, err := decodeSigningPublicKeyPEM(tombstone.AgentSigningPubPEM)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "bad_signature")
		return false
	}
	signature, err := decodeSigBase64(signatureB64)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "bad_signature")
		return false
	}
	canonical := corepop.CanonicalString(r.Method, r.URL.Path, r.Host, timestamp, nonce)
	if err := apipop.Verify(signingPub, canonical, signature); err != nil {
		writeError(w, http.StatusUnauthorized, "bad_signature")
		return false
	}
	ts, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "timestamp_skew")
		return false
	}
	if diff := s.now().Sub(ts); diff > pollClockSkew || diff < -pollClockSkew {
		writeError(w, http.StatusUnauthorized, "timestamp_skew")
		return false
	}
	if err := s.store.AddPopNonce(r.Context(), tombstone.FormerHostID, nonce, ts.Add(pollClockSkew)); err != nil {
		if errors.Is(err, store.ErrReplayedNonce) {
			writeError(w, http.StatusUnauthorized, "replayed_nonce")
			return false
		}
		s.logger.Error("record canceled import poll nonce", "host", tombstone.FormerHostID, "error", err)
		writeError(w, http.StatusInternalServerError, "failed to check replay")
		return false
	}
	return true
}

// signResult holds the output of signing a host certificate.
type signResult struct {
	certPEM   []byte
	fp        string
	notBefore time.Time
	notAfter  time.Time
}

// signHostCert re-signs the host certificate with the same public key and fresh expiry.
// CA key material is held only during the signing operation.
func (s *Server) signHostCert(ctx context.Context, host *models.Host, certInfo *models.CertificateInfo, now time.Time) (*signResult, error) {
	// Durable revocation (GHSA-339v-266x-79xr): do not renew/re-sign for a
	// blocked host or a disabled operator's host. Auto-renewal callers treat a
	// returned error as "skip renewal", so the host keeps its current cert and
	// drops off the mesh at expiry instead of renewing indefinitely.
	if err := s.checkIssuanceAllowed(ctx, host); err != nil {
		return nil, fmt.Errorf("issuance not allowed: %w", err)
	}

	// Prep work — no CA lock needed
	currentCert, _, err := cert.UnmarshalCertificateFromPEM([]byte(certInfo.PEM))
	if err != nil {
		return nil, fmt.Errorf("parse current cert: %w", err)
	}
	if len(currentCert.PublicKey()) == 0 {
		return nil, fmt.Errorf("current certificate has empty public key")
	}

	network, err := s.store.GetNetwork(ctx, host.NetworkID)
	if err != nil {
		return nil, fmt.Errorf("get network: %w", err)
	}

	prefixes, err := buildHostPrefixes(network, host.NebulaIPs)
	if err != nil {
		return nil, err
	}

	unsafeNetworks, err := models.ParseUnsafeNetworks(host.UnsafeNetworks)
	if err != nil {
		return nil, err
	}

	caMgr, err := s.caForHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve host CA: %w", err)
	}
	defer caMgr.Wipe() // GHSA-8h84-fhqq-q58v: zeroise plaintext CA key on return.
	newCert, err := caMgr.Sign(pki.SignRequest{
		Name:           host.Name,
		PublicKey:      currentCert.PublicKey(),
		Networks:       prefixes,
		UnsafeNetworks: unsafeNetworks,
		Groups:         host.Groups,
		Duration:       pki.DefaultAgentCertDuration,
		Now:            now,
	})
	if err != nil {
		return nil, fmt.Errorf("sign renewed cert: %w", err)
	}

	// Post-sign work — no CA lock needed
	certPEM, err := newCert.MarshalPEM()
	if err != nil {
		return nil, fmt.Errorf("marshal cert: %w", err)
	}

	fp, err := newCert.Fingerprint()
	if err != nil {
		return nil, fmt.Errorf("fingerprint: %w", err)
	}

	return &signResult{
		certPEM:   certPEM,
		fp:        fp,
		notBefore: newCert.NotBefore(),
		notAfter:  newCert.NotAfter(),
	}, nil
}
