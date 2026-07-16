package api

import (
	"errors"
	"net/http"
	"time"

	apipop "github.com/forgekeep/nebula-mesh/internal/api/pop"
	"github.com/forgekeep/nebula-mesh/internal/models"
	corepop "github.com/forgekeep/nebula-mesh/internal/pop"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

type agentAuthHeaders struct {
	fingerprint string
	timestamp   string
	nonce       string
	signature   string
}

func readAgentAuthHeaders(w http.ResponseWriter, r *http.Request) (agentAuthHeaders, bool) {
	headers := agentAuthHeaders{
		fingerprint: r.Header.Get(corepop.HeaderFingerprint),
		timestamp:   r.Header.Get(corepop.HeaderTimestamp),
		nonce:       r.Header.Get(corepop.HeaderNonce),
		signature:   r.Header.Get(corepop.HeaderSignature),
	}
	if headers.fingerprint == "" || headers.timestamp == "" || headers.nonce == "" || headers.signature == "" {
		writeError(w, http.StatusBadRequest, "missing_signature")
		return agentAuthHeaders{}, false
	}
	return headers, true
}

func (s *Server) authenticateKnownAgentRequest(
	w http.ResponseWriter, r *http.Request, host *models.Host, headers agentAuthHeaders,
) bool {
	signingPublic, err := decodeSigningPublicKeyPEM(host.SigningPubPEM)
	if err != nil {
		s.recordAuditAction(r.Context(), auditHostAuthFailed, host.ID, authReasonBadSignature)
		writeError(w, http.StatusUnauthorized, "bad_signature")
		return false
	}
	signature, err := decodeSigBase64(headers.signature)
	if err != nil || apipop.Verify(signingPublic,
		corepop.CanonicalString(r.Method, r.URL.Path, r.Host, headers.timestamp, headers.nonce), signature) != nil {
		s.recordAuditAction(r.Context(), auditHostAuthFailed, host.ID, authReasonBadSignature)
		writeError(w, http.StatusUnauthorized, "bad_signature")
		return false
	}
	requestTime, err := time.Parse(time.RFC3339, headers.timestamp)
	if err != nil {
		s.recordAuditAction(r.Context(), auditHostAuthFailed, host.ID, authReasonTimestampSkew)
		writeError(w, http.StatusUnauthorized, "timestamp_skew")
		return false
	}
	if diff := s.now().Sub(requestTime); diff > pollClockSkew || diff < -pollClockSkew {
		s.recordAuditAction(r.Context(), auditHostAuthFailed, host.ID, authReasonTimestampSkew)
		writeError(w, http.StatusUnauthorized, "timestamp_skew")
		return false
	}
	if err := s.store.AddPopNonce(r.Context(), host.ID, headers.nonce, requestTime.Add(pollClockSkew)); err != nil {
		if errors.Is(err, store.ErrReplayedNonce) {
			s.recordAuditAction(r.Context(), auditHostAuthFailed, host.ID, authReasonReplayedNonce)
			writeError(w, http.StatusUnauthorized, "replayed_nonce")
			return false
		}
		s.logger.Error("record agent request nonce", "host", host.ID, "error", err)
		writeError(w, http.StatusInternalServerError, "failed to check replay")
		return false
	}
	return true
}
