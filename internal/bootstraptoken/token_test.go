package bootstraptoken

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestGenerateUsesPurposePrefixAnd256Bits(t *testing.T) {
	tests := []struct {
		purpose Purpose
		prefix  string
	}{
		{PurposeEnrollment, "nme_"},
		{PurposeMeshImport, "nmi_"},
	}
	for _, test := range tests {
		t.Run(string(test.purpose), func(t *testing.T) {
			first, err := Generate(test.purpose)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			second, err := Generate(test.purpose)
			if err != nil {
				t.Fatalf("Generate second: %v", err)
			}
			if first == second {
				t.Fatal("two generated tokens are equal")
			}
			if !strings.HasPrefix(first, test.prefix) {
				t.Fatalf("token = %q, want prefix %q", first, test.prefix)
			}
			raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(first, test.prefix))
			if err != nil {
				t.Fatalf("decode token entropy: %v", err)
			}
			if len(raw) != 32 {
				t.Fatalf("entropy = %d bytes, want 32", len(raw))
			}
		})
	}
}

func TestValidatePurpose(t *testing.T) {
	tests := []struct {
		name        string
		token       string
		purpose     Purpose
		allowLegacy bool
		wantErr     error
	}{
		{"enrollment", "nme_value", PurposeEnrollment, false, nil},
		{"import", "nmi_value", PurposeMeshImport, false, nil},
		{"import rejected by enrollment", "nmi_value", PurposeEnrollment, true, ErrWrongPurpose},
		{"enrollment rejected by import", "nme_value", PurposeMeshImport, false, ErrWrongPurpose},
		{"legacy enrollment accepted", "legacy-uuid", PurposeEnrollment, true, nil},
		{"legacy enrollment disabled", "legacy-uuid", PurposeEnrollment, false, ErrUnknownPurpose},
		{"legacy import rejected", "legacy-uuid", PurposeMeshImport, true, ErrUnknownPurpose},
		{"unknown prefix", "nmz_value", PurposeEnrollment, true, ErrUnknownPurpose},
		{"empty", "", PurposeEnrollment, true, ErrUnknownPurpose},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidatePurpose(test.token, test.purpose, test.allowLegacy)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("ValidatePurpose error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestPurposeOf(t *testing.T) {
	if purpose, ok := PurposeOf("nmi_value"); !ok || purpose != PurposeMeshImport {
		t.Fatalf("PurposeOf import = %q, %t", purpose, ok)
	}
	if purpose, ok := PurposeOf("legacy-token"); ok || purpose != "" {
		t.Fatalf("PurposeOf legacy = %q, %t", purpose, ok)
	}
}
