package web

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"fmt"
	"strings"
	"time"

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
func generateTOTPSecret(username string) (otpauthURL, secret string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: username,
	})
	if err != nil {
		return "", "", fmt.Errorf("generate totp: %w", err)
	}
	return key.URL(), key.Secret(), nil
}

// totpPeriod is the TOTP timestep length. The acceptance window is
// ±totpSkew timesteps around now.
const (
	totpPeriod = 30
	totpSkew   = 1
)

// verifyTOTPWithTimestep validates a 6-digit code and, on success, returns
// the timestep (Unix time / period) the code matched. Callers that gate
// authentication must persist the timestep via ConsumeOperatorTOTPTimestep
// so the same code cannot be replayed within its ±skew acceptance window.
// totp.ValidateCustom does not expose which step matched, so each candidate
// step in the window is checked individually with the same parameters.
func verifyTOTPWithTimestep(secret, code string) (int64, bool) {
	code = strings.TrimSpace(code)
	if secret == "" || code == "" {
		return 0, false
	}
	now := timeNow()
	step := now.Unix() / totpPeriod
	for delta := int64(-totpSkew); delta <= totpSkew; delta++ {
		candidate := step + delta
		want, err := totp.GenerateCodeCustom(secret, time.Unix(candidate*totpPeriod, 0), totp.ValidateOpts{
			Period:    totpPeriod,
			Skew:      0,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return candidate, true
		}
	}
	return 0, false
}

// generateRecoveryCodes returns N random 10-character uppercase codes.
// The Store derives their keyed at-rest verifiers.
func generateRecoveryCodes(n int) ([]string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // base32-ish, no 0/O/I/1
	codes := make([]string, 0, n)
	for i := 0; i < n; i++ {
		buf := make([]byte, 10)
		if _, err := rand.Read(buf); err != nil {
			return nil, fmt.Errorf("rand: %w", err)
		}
		var sb strings.Builder
		for _, b := range buf {
			sb.WriteByte(alphabet[int(b)%len(alphabet)])
		}
		code := sb.String()
		codes = append(codes, code)
	}
	return codes, nil
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
