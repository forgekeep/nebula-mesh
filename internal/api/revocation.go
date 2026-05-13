package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// revocationRevokedResponse is the JSON body returned for blocked hosts on a
// signed poll (ADR 0004 §7.1 — structured revocation).
type revocationRevokedResponse struct {
	Reason    string    `json:"reason"`
	Message   string    `json:"message"`
	BlockedAt time.Time `json:"blocked_at"`
}

// revocationGoneResponse is the JSON body returned when the host row has
// been deleted but its fingerprint still lives on the blocklist.
type revocationGoneResponse struct {
	Reason  string    `json:"reason"`
	Message string    `json:"message"`
	At      time.Time `json:"deleted_at"`
}

func writeRevocation(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// fingerprintInBlocklist returns true when the fingerprint is recorded in
// the blocklist table. Errors during the lookup are logged and treated as
// "not in the list" — better to fall through to 401 unknown_fingerprint
// than to wrongly stop a working agent.
func (s *Server) fingerprintInBlocklist(ctx context.Context, fingerprint string) bool {
	list, err := s.store.GetBlocklist(ctx)
	if err != nil {
		s.logger.Error("blocklist lookup for revocation check", "error", err)
		return false
	}
	for _, fp := range list {
		if fp == fingerprint {
			return true
		}
	}
	return false
}
