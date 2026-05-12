package web

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	totpIssuer            = "Nebula Mesh"
	totpRecoveryCodeCount = 10
)

// generateTOTPSecret creates a new TOTP secret keyed for the operator's
// username. It returns the otpauth:// URL (for QR rendering) and the raw
// base32-encoded secret to persist.
func generateTOTPSecret(username string) (string, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: username,
	})
	if err != nil {
		return "", "", fmt.Errorf("generate totp: %w", err)
	}
	return key.URL(), key.Secret(), nil
}

// verifyTOTP validates a 6-digit code against the operator's secret.
func verifyTOTP(secret, code string) bool {
	code = strings.TrimSpace(code)
	if secret == "" || code == "" {
		return false
	}
	ok, err := totp.ValidateCustom(code, secret, timeNow(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return false
	}
	return ok
}

// generateRecoveryCodes returns N random 10-character codes (uppercase
// alphanumeric) and their SHA-256 hex hashes for storage.
func generateRecoveryCodes(n int) (codes []string, hashes []string, err error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // base32-ish, no 0/O/I/1
	for i := 0; i < n; i++ {
		buf := make([]byte, 10)
		if _, err := rand.Read(buf); err != nil {
			return nil, nil, fmt.Errorf("rand: %w", err)
		}
		var sb strings.Builder
		for _, b := range buf {
			sb.WriteByte(alphabet[int(b)%len(alphabet)])
		}
		code := sb.String()
		codes = append(codes, code)
		hashes = append(hashes, hashRecoveryCode(code))
	}
	return codes, hashes, nil
}

// hashRecoveryCode normalizes a code (uppercase, strip spaces/dashes) and
// returns its SHA-256 hex digest so plain codes can be matched.
func hashRecoveryCode(code string) string {
	norm := strings.ToUpper(strings.NewReplacer(" ", "", "-", "").Replace(strings.TrimSpace(code)))
	sum := sha256.Sum256([]byte(norm))
	return hex.EncodeToString(sum[:])
}

// encodeSecretForDisplay formats the base32 secret into groups of 4 for
// manual entry into an authenticator app.
func encodeSecretForDisplay(secret string) string {
	// Strip any padding so display is uniform.
	clean := strings.TrimRight(secret, "=")
	var sb strings.Builder
	for i, c := range clean {
		if i > 0 && i%4 == 0 {
			sb.WriteByte(' ')
		}
		sb.WriteRune(c)
	}
	return sb.String()
}

// dummy import guard so test builds don't fail when base32 is only used via totp.
var _ = base32.StdEncoding
