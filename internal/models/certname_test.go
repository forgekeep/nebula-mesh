package models

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/slackhq/nebula/cert"
)

func TestMaxCertNameLen_MatchesNebula(t *testing.T) {
	if MaxCertNameLen != cert.MaxNameLength {
		t.Fatalf("MaxCertNameLen = %d, nebula cert.MaxNameLength = %d", MaxCertNameLen, cert.MaxNameLength)
	}
}

// Nebula signs a v2 certificate with a name at the bound and refuses one past
// it, so every name accepted by ValidateCertName yields a usable certificate.
func TestMaxCertNameLen_BoundsSignableName(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(name string) error {
		now := time.Now()
		tbs := &cert.TBSCertificate{
			Version:   cert.Version2,
			Name:      name,
			IsCA:      true,
			NotBefore: now,
			NotAfter:  now.Add(time.Hour),
			PublicKey: pub,
			Curve:     cert.Curve_CURVE25519,
		}
		_, err := tbs.Sign(nil, cert.Curve_CURVE25519, priv)
		return err
	}
	if err := sign(strings.Repeat("a", MaxCertNameLen)); err != nil {
		t.Errorf("sign name at limit: %v", err)
	}
	if err := sign(strings.Repeat("a", MaxCertNameLen+1)); err == nil {
		t.Error("sign name over limit succeeded, want error")
	}
}

func TestValidateCertName(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr string
	}{
		{"short", "web-1", ""},
		{"at limit", strings.Repeat("a", MaxCertNameLen), ""},
		{"empty", "", "name must not be empty"},
		{"over limit", strings.Repeat("a", MaxCertNameLen+1), "name must be at most 253 bytes"},
		{"multibyte over limit in bytes", strings.Repeat("я", 127), "name must be at most 253 bytes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCertName("name", tt.value)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateCertName = %v, want nil", err)
				}
				return
			}
			if err == nil || err.Error() != tt.wantErr {
				t.Fatalf("ValidateCertName = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestCertNameWithSuffix(t *testing.T) {
	tests := []struct {
		name string
		base string
		want string
	}{
		{"short base kept", "alice", "alice-default"},
		{"long base trimmed", strings.Repeat("a", MaxCertNameLen), strings.Repeat("a", MaxCertNameLen-len("-default")) + "-default"},
		// 2-byte runes: the byte budget for the base is odd, so the cut must
		// step back to a rune boundary instead of splitting a rune.
		{"rune boundary", strings.Repeat("я", 127), strings.Repeat("я", 122) + "-default"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CertNameWithSuffix(tt.base, "-default")
			if got != tt.want {
				t.Fatalf("CertNameWithSuffix = %q, want %q", got, tt.want)
			}
			if !utf8.ValidString(got) {
				t.Errorf("result is not valid UTF-8: %q", got)
			}
			if err := ValidateCertName("name", got); err != nil {
				t.Errorf("result fails ValidateCertName: %v", err)
			}
		})
	}
}

func TestValidateHostAdvanced_MTUBounds(t *testing.T) {
	if err := ValidateHostAdvanced(&HostAdvanced{MTU: MaxMTU}); err != nil {
		t.Errorf("MTU at limit: %v", err)
	}
	err := ValidateHostAdvanced(&HostAdvanced{MTU: MaxMTU + 1})
	if err == nil || err.Error() != "advanced.mtu must be between 576 and 8937" {
		t.Errorf("MTU over limit: err = %v", err)
	}
}
