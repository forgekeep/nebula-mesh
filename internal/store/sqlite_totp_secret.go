package store

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/forgekeep/nebula-mesh/internal/keystore"
)

const totpSecretPrefix = "totp-aes256gcm-v1:" // #nosec G101 -- public ciphertext format marker, not a credential

var ErrTOTPSecretMasterUnavailable = errors.New("TOTP secret master key unavailable")

type totpSecretCipher interface {
	Seal(plaintext, aad []byte) (keystore.WrappedBlob, error)
	Open(blob keystore.WrappedBlob, aad []byte) ([]byte, error)
}

func totpSecretAAD(operatorID string) []byte {
	return []byte("nebula-mesh:operator-totp-secret:v1:" + operatorID)
}

func (s *SQLiteStore) sealTOTPSecret(operatorID, secret string) (string, error) {
	if secret == "" {
		return "", nil
	}
	plaintext := []byte(secret)
	defer keystore.Zeroize(plaintext)
	return s.sealTOTPSecretBytes(operatorID, plaintext)
}

func (s *SQLiteStore) sealTOTPSecretBytes(operatorID string, plaintext []byte) (string, error) {
	if len(plaintext) == 0 {
		return "", nil
	}
	if s.totpCipher == nil {
		return "", ErrTOTPSecretMasterUnavailable
	}
	blob, err := s.totpCipher.Seal(plaintext, totpSecretAAD(operatorID))
	if err != nil {
		return "", fmt.Errorf("encrypt TOTP secret: %w", err)
	}
	packed := make([]byte, 0, len(blob.Nonce)+len(blob.Ciphertext))
	packed = append(packed, blob.Nonce...)
	packed = append(packed, blob.Ciphertext...)
	return totpSecretPrefix + base64.RawStdEncoding.EncodeToString(packed), nil
}

func (s *SQLiteStore) openTOTPSecret(operatorID, sealed string) (string, error) {
	if sealed == "" {
		return "", nil
	}
	if s.totpCipher == nil {
		return "", ErrTOTPSecretMasterUnavailable
	}
	if !strings.HasPrefix(sealed, totpSecretPrefix) {
		return "", errors.New("TOTP secret has unsupported storage format")
	}
	packed, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(sealed, totpSecretPrefix))
	if err != nil || len(packed) < keystore.NonceSize+16 {
		return "", errors.New("TOTP secret ciphertext is malformed")
	}
	plaintext, err := s.totpCipher.Open(keystore.WrappedBlob{
		Nonce: packed[:keystore.NonceSize], Ciphertext: packed[keystore.NonceSize:],
	}, totpSecretAAD(operatorID))
	if err != nil {
		return "", fmt.Errorf("decrypt TOTP secret: %w", err)
	}
	defer keystore.Zeroize(plaintext)
	return string(plaintext), nil
}
