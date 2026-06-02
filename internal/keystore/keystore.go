// Package keystore implements envelope encryption for CA private key
// material persisted in SQLite. Each CA gets a fresh data-encryption key
// (DEK) wrapped under a process-wide master key (KEK) supplied through
// NEBULA_MGMT_MASTER_KEY. AES-256-GCM is used for both wraps.
//
// See docs/adr/0002-per-operator-cas.md §4.1 for the design rationale.
package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

const (
	// MasterKeySize is the expected size of the unwrapped master key, in bytes.
	MasterKeySize = 32
	// DEKSize is the size of a per-CA data-encryption key.
	DEKSize = 32
	// NonceSize is the GCM nonce length used everywhere in this package.
	NonceSize = 12
)

// ErrInvalidMasterKey is returned when the configured master key has the
// wrong length or fails to base64-decode.
var ErrInvalidMasterKey = errors.New("master key must be 32 random bytes, base64-encoded")

// Master wraps the process-wide AEAD instance for the KEK.
type Master struct {
	aead cipher.AEAD
}

// NewMasterFromBase64 builds a Master from a base64-encoded 32-byte key.
// The decoded bytes are copied into the AEAD key schedule by NewMaster, so the
// transient plaintext copy is zeroized before returning rather than left on the
// heap for the GC to reclaim (and possibly reuse).
func NewMasterFromBase64(b64 string) (*Master, error) {
	if b64 == "" {
		return nil, ErrInvalidMasterKey
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidMasterKey, err)
	}
	defer Zeroize(raw)
	return NewMaster(raw)
}

// NewMaster builds a Master from raw 32-byte material.
func NewMaster(raw []byte) (*Master, error) {
	if len(raw) != MasterKeySize {
		return nil, ErrInvalidMasterKey
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	return &Master{aead: aead}, nil
}

// WrappedKey holds a DEK encrypted under the master key.
type WrappedKey struct {
	Ciphertext []byte
	Nonce      []byte
}

// WrappedBlob holds an arbitrary payload encrypted under a per-CA DEK.
type WrappedBlob struct {
	Ciphertext []byte
	Nonce      []byte
}

// GenerateDEK returns a fresh DEK plus its master-key-wrapped form.
// Callers MUST zeroise the returned plaintext DEK as soon as it is no
// longer needed.
func (m *Master) GenerateDEK() (plaintext []byte, wrapped WrappedKey, err error) {
	dek := make([]byte, DEKSize)
	if _, err := rand.Read(dek); err != nil {
		return nil, WrappedKey{}, fmt.Errorf("rand dek: %w", err)
	}
	wrapped, err = m.WrapDEK(dek)
	if err != nil {
		return nil, WrappedKey{}, err
	}
	return dek, wrapped, nil
}

// WrapDEK encrypts a DEK under the master key.
func (m *Master) WrapDEK(dek []byte) (WrappedKey, error) {
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return WrappedKey{}, fmt.Errorf("rand nonce: %w", err)
	}
	ct := m.aead.Seal(nil, nonce, dek, nil)
	return WrappedKey{Ciphertext: ct, Nonce: nonce}, nil
}

// UnwrapDEK decrypts a DEK previously wrapped with WrapDEK. The returned
// plaintext lives only until the caller zeroises it.
func (m *Master) UnwrapDEK(w WrappedKey) ([]byte, error) {
	if len(w.Nonce) != NonceSize {
		return nil, fmt.Errorf("wrapped dek nonce: %d bytes, want %d", len(w.Nonce), NonceSize)
	}
	pt, err := m.aead.Open(nil, w.Nonce, w.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("unwrap dek: %w", err)
	}
	return pt, nil
}

// SealWithDEK encrypts a payload under the given DEK using AES-256-GCM.
func SealWithDEK(dek, plaintext []byte) (WrappedBlob, error) {
	if len(dek) != DEKSize {
		return WrappedBlob{}, fmt.Errorf("dek length: %d, want %d", len(dek), DEKSize)
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return WrappedBlob{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return WrappedBlob{}, err
	}
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return WrappedBlob{}, err
	}
	ct := aead.Seal(nil, nonce, plaintext, nil)
	return WrappedBlob{Ciphertext: ct, Nonce: nonce}, nil
}

// OpenWithDEK decrypts a WrappedBlob using the given DEK.
func OpenWithDEK(dek []byte, w WrappedBlob) ([]byte, error) {
	if len(dek) != DEKSize {
		return nil, fmt.Errorf("dek length: %d, want %d", len(dek), DEKSize)
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(w.Nonce) != NonceSize {
		return nil, fmt.Errorf("wrapped blob nonce: %d bytes, want %d", len(w.Nonce), NonceSize)
	}
	pt, err := aead.Open(nil, w.Nonce, w.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("open with dek: %w", err)
	}
	return pt, nil
}

// Zeroize overwrites b with zeros. Use immediately after the plaintext
// material is no longer required.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
