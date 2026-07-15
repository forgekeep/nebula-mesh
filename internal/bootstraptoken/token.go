package bootstraptoken

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

type Purpose string

const (
	PurposeEnrollment Purpose = "enrollment"
	PurposeMeshImport Purpose = "mesh_import"

	enrollmentPrefix = "nme_"
	meshImportPrefix = "nmi_"
	tokenBytes       = 32
)

var (
	ErrUnknownPurpose = errors.New("bootstrap token purpose is unknown")
	ErrWrongPurpose   = errors.New("bootstrap token has the wrong purpose")
)

func Generate(purpose Purpose) (string, error) {
	prefix, err := prefixFor(purpose)
	if err != nil {
		return "", err
	}
	entropy := make([]byte, tokenBytes)
	if _, err := rand.Read(entropy); err != nil {
		return "", fmt.Errorf("generate bootstrap token: %w", err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(entropy), nil
}

func ValidatePurpose(token string, expected Purpose, allowLegacyEnrollment bool) error {
	actual, known := parsePurpose(token)
	if known {
		if actual != expected {
			return ErrWrongPurpose
		}
		return nil
	}
	if allowLegacyEnrollment && expected == PurposeEnrollment && token != "" && !strings.HasPrefix(token, "nm") {
		return nil
	}
	return ErrUnknownPurpose
}

func Hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// PurposeOf returns the purpose encoded in a prefixed bootstrap token. Legacy
// unprefixed enrollment tokens intentionally return known=false; callers may
// accept them only in the explicit backward-compatible enrollment path.
func PurposeOf(token string) (Purpose, bool) {
	return parsePurpose(token)
}

func parsePurpose(token string) (Purpose, bool) {
	switch {
	case strings.HasPrefix(token, enrollmentPrefix) && len(token) > len(enrollmentPrefix):
		return PurposeEnrollment, true
	case strings.HasPrefix(token, meshImportPrefix) && len(token) > len(meshImportPrefix):
		return PurposeMeshImport, true
	default:
		return "", false
	}
}

func prefixFor(purpose Purpose) (string, error) {
	switch purpose {
	case PurposeEnrollment:
		return enrollmentPrefix, nil
	case PurposeMeshImport:
		return meshImportPrefix, nil
	default:
		return "", fmt.Errorf("%w: %q", ErrUnknownPurpose, purpose)
	}
}
