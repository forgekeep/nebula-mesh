// Package credentialhash creates keyed, domain-separated credential digests.
package credentialhash

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
)

const rootInfo = "nebula-mesh/credential-hash/root/v1"

var (
	errEmptyMaster    = errors.New("credential hash master key is empty")
	errEmptyRaw       = errors.New("credential hash input is empty")
	errInvalidPurpose = errors.New("credential hash purpose is invalid")
	errDestroyed      = errors.New("credential hasher is destroyed")
)

// Purpose identifies the credential type to hash.
type Purpose string

const (
	PurposeOperatorAPIKey   Purpose = "operator-api-key"
	PurposeOperatorSession  Purpose = "operator-session"
	PurposeEnrollmentToken  Purpose = "enrollment-token"
	PurposeMeshImportToken  Purpose = "mesh-import-token" // #nosec G101 -- public domain label, not credential material
	PurposeTOTPRecoveryCode Purpose = "totp-recovery-code"
)

// Hasher holds the derived root key used to produce credential digests.
type Hasher struct {
	mu        sync.RWMutex
	rootKey   []byte
	destroyed bool
}

// New derives a credential-digest root key from master.
func New(master []byte) (*Hasher, error) {
	if len(master) == 0 {
		return nil, errEmptyMaster
	}

	rootKey, err := hkdf.Key(sha256.New, master, nil, rootInfo, sha256.Size)
	if err != nil {
		return nil, err
	}
	return &Hasher{rootKey: rootKey}, nil
}

// Digest returns a versioned HMAC-SHA256 digest for raw in the given domain.
func (h *Hasher) Digest(purpose Purpose, raw []byte) (string, error) {
	if !purpose.valid() {
		return "", errInvalidPurpose
	}
	if len(raw) == 0 {
		return "", errEmptyRaw
	}

	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.destroyed {
		return "", errDestroyed
	}

	mac := hmac.New(sha256.New, h.rootKey)
	_, _ = mac.Write([]byte(purpose))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(raw)
	return "hmac-sha256-v1:" + hex.EncodeToString(mac.Sum(nil)), nil
}

// Destroy zeroizes the derived root key and disables future digests.
func (h *Hasher) Destroy() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.destroyed {
		return
	}
	clear(h.rootKey)
	h.rootKey = nil
	h.destroyed = true
}

func (p Purpose) valid() bool {
	switch p {
	case PurposeOperatorAPIKey, PurposeOperatorSession, PurposeEnrollmentToken, PurposeMeshImportToken, PurposeTOTPRecoveryCode:
		return true
	default:
		return false
	}
}
