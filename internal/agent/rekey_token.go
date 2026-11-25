package agent

import (
	"errors"
	"fmt"
	"strings"

	"github.com/slackhq/nebula/cert"

	"github.com/forgekeep/nebula-mesh/internal/rekeytoken"
)

func decryptRekeyToken(path, sealed string) (string, error) {
	keyPEM, err := readDiscoveryFile(path)
	if err != nil {
		return "", fmt.Errorf("read Nebula host key: %w", err)
	}
	defer clear(keyPEM)
	privateKey, remainder, curve, err := cert.UnmarshalPrivateKeyFromPEM(keyPEM)
	if err != nil || curve != cert.Curve_CURVE25519 || strings.TrimSpace(string(remainder)) != "" {
		return "", errors.New("nebula host key is not one file-backed X25519 private key")
	}
	defer clear(privateKey)
	return rekeytoken.Open(privateKey, sealed)
}
