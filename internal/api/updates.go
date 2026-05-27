package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/slackhq/nebula/cert"

	apipop "github.com/forgekeep/nebula-mesh/internal/api/pop"
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
	Blocklist       []string `json:"blocklist"`
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
	fingerprint := r.Header.Get(corepop.HeaderFingerprint)
	timestamp := r.Header.Get(corepop.HeaderTimestamp)
	nonce := r.Header.Get(corepop.HeaderNonce)
	signatureB64 := r.Header.Get(corepop.HeaderSignature)
	if fingerprint == "" || timestamp == "" || nonce == "" || signatureB64 == "" {
		s.recordAuditAction(r.Context(), auditHostAuthFailed, "", authReasonBadSignature)
		writeError(w, http.StatusBadRequest, "missing_signature")
		return
	}

	host, err := s.store.GetHostByFingerprint(r.Context(), fingerprint)
	if errors.Is(err, store.ErrNotFound) {
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

	// Verify the proof-of-possession signature against the stored Ed25519
	// signing public key. host.SigningPubPEM is empty for legacy host rows
	// that pre-date the ADR 0004 enrollment, in which case verification is
	// impossible — answer 401 with reason=bad_signature so the operator can
	// re-enroll the host via POST /hosts/{id}/reenroll.
	signingPub, err := decodeSigningPublicKeyPEM(host.SigningPubPEM)
	if err != nil {
		s.recordAuditAction(r.Context(), auditHostAuthFailed, host.ID, authReasonBadSignature)
		writeError(w, http.StatusUnauthorized, "bad_signature")
		return
	}
	sigBytes, err := decodeSigBase64(signatureB64)
	if err != nil {
		s.recordAuditAction(r.Context(), auditHostAuthFailed, host.ID, authReasonBadSignature)
		writeError(w, http.StatusUnauthorized, "bad_signature")
		return
	}
	canonical := corepop.CanonicalString(r.Method, r.URL.Path, r.Host, timestamp, nonce)
	if err := apipop.Verify(signingPub, canonical, sigBytes); err != nil {
		s.recordAuditAction(r.Context(), auditHostAuthFailed, host.ID, authReasonBadSignature)
		writeError(w, http.StatusUnauthorized, "bad_signature")
		return
	}

	// Timestamp window.
	ts, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		s.recordAuditAction(r.Context(), auditHostAuthFailed, host.ID, authReasonTimestampSkew)
		writeError(w, http.StatusUnauthorized, "timestamp_skew")
		return
	}
	now := s.now()
	if diff := now.Sub(ts); diff > pollClockSkew || diff < -pollClockSkew {
		s.recordAuditAction(r.Context(), auditHostAuthFailed, host.ID, authReasonTimestampSkew)
		writeError(w, http.StatusUnauthorized, "timestamp_skew")
		return
	}

	// Replay protection — persist (host, nonce) for the skew window so a
	// replay survives restart and can't be evicted by a noisy neighbor.
	// GHSA-v2jf-442r-6mjh. Fail closed on store error.
	if err := s.store.AddPopNonce(r.Context(), host.ID, nonce, ts.Add(pollClockSkew)); err != nil {
		if errors.Is(err, store.ErrReplayedNonce) {
			s.recordAuditAction(r.Context(), auditHostAuthFailed, host.ID, authReasonReplayedNonce)
			writeError(w, http.StatusUnauthorized, "replayed_nonce")
			return
		}
		s.logger.Error("record poll nonce", "host", host.ID, "error", err)
		writeError(w, http.StatusInternalServerError, "failed to check replay")
		return
	}

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
		} else if host.CertRotatedAt != nil && now.Sub(*host.CertRotatedAt) > overlapWindow() {
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

	// Get blocklist
	blocklist, err := s.store.GetBlocklist(r.Context())
	if err != nil {
		s.logger.Error("get blocklist", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get blocklist")
		return
	}

	resp := agentUpdatesResponse{
		Blocklist: blocklist,
	}

	// Check if certificate needs renewal
	certInfo, err := s.store.GetCertificateInfo(r.Context(), host.ID)
	if err == nil && pki.ShouldRenewAt(certInfo.NotBefore, certInfo.NotAfter, now) {
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
			caStr := string(signed.caCertPEM)
			resp.CACertPEM = &caStr
			s.logger.Info("certificate renewed", "host", host.Name)
		}
	}

	// If host's CA has a successor, include trust bundle in response.
	// Trust bundle allows agents to accept both old and new CA certs during rotation.
	if host.CAID != "" && resp.CACertPEM == nil {
		successor, ferr := s.store.FindCAByPredecessor(r.Context(), host.CAID)
		if ferr == nil && successor != nil {
			oldCA, oerr := s.store.GetCA(r.Context(), host.CAID)
			if oerr == nil && oldCA != nil {
				bundle := oldCA.CertPEM + "\n" + successor.CertPEM
				resp.CACertPEM = &bundle
				s.logger.Info("returning trust bundle", "host_id", host.ID, "old_ca", host.CAID, "successor_ca", successor.ID)
			}
		}
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
		} else if hostVersion != netVersion {
			configYAML, cfgErr := s.renderHostConfig(r.Context(), host)
			if cfgErr != nil {
				s.logger.Error("render host config", "host", host.Name, "error", cfgErr)
			} else {
				if uvErr := s.store.UpdateHostConfigVersion(r.Context(), host.ID, netVersion); uvErr != nil {
					s.logger.Error("update host config version", "host", host.Name, "error", uvErr)
				} else {
					cfgStr := string(configYAML)
					resp.ConfigYAML = &cfgStr
					s.logger.Info("config rolled out", "host", host.Name, "from_version", hostVersion, "to_version", netVersion)
				}
			}
		}
	}

	// Rekey signal: force-rotate?new_key=true sets pending_rekey on the
	// host row; the very next poll under the existing fingerprint carries
	// a single-use enrollment token so the agent can re-enroll a fresh
	// keypair. The pending_rekey flag is cleared once the token is minted
	// so a follow-up poll doesn't re-issue another token.
	if host.PendingRekey {
		tokenStr := uuid.New().String()
		expiresAt := now.Add(s.tokenTTLFor(r.Context(), host.NetworkID))
		if err := s.store.CreateTokenForHost(r.Context(), host.ID, tokenStr, expiresAt); err != nil {
			s.logger.Error("mint rekey token", "host", host.ID, "error", err)
		} else if err := s.store.ClearPendingRekey(r.Context(), host.ID); err != nil {
			s.logger.Error("clear pending_rekey", "host", host.ID, "error", err)
		} else {
			resp.RekeyRequired = true
			resp.EnrollmentToken = tokenStr
		}
	}

	resp.HasUpdates = len(blocklist) > 0 || resp.CertificatePEM != nil || resp.ConfigYAML != nil || resp.RekeyRequired
	writeJSON(w, http.StatusOK, resp)
}

// signResult holds the output of signing a host certificate.
type signResult struct {
	certPEM   []byte
	fp        string
	notBefore time.Time
	notAfter  time.Time
	caCertPEM []byte
}

// signHostCert re-signs the host certificate with the same public key and fresh expiry.
// CA lock is held only during crypto operations (Sign + CACertPEM).
func (s *Server) signHostCert(ctx context.Context, host *models.Host, certInfo *models.CertificateInfo, now time.Time) (*signResult, error) {
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

	caMgr, err := s.caForHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve host CA: %w", err)
	}
	defer caMgr.Wipe() // GHSA-8h84-fhqq-q58v: zeroise plaintext CA key on return.
	// CA operations — sign and retrieve CA certificate
	newCert, caCertPEM, caErr := func() (cert.Certificate, []byte, error) {
		c, signErr := caMgr.Sign(pki.SignRequest{
			Name:      host.Name,
			PublicKey: currentCert.PublicKey(),
			Networks:  prefixes,
			Groups:    host.Groups,
			Duration:  pki.DefaultAgentCertDuration,
			Now:       now,
		})
		if signErr != nil {
			return nil, nil, fmt.Errorf("sign renewed cert: %w", signErr)
		}
		ca, err := caMgr.CACertPEM()
		if err != nil {
			return nil, nil, fmt.Errorf("get CA cert PEM: %w", err)
		}
		return c, ca, nil
	}()
	if caErr != nil {
		return nil, caErr
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
		caCertPEM: caCertPEM,
	}, nil
}
