package config

import (
	"strings"
	"testing"
)

func TestOIDCConfig_Validate(t *testing.T) {
	tests := []struct {
		name      string
		cfg       *OIDCConfig
		wantError string // empty → expect nil; otherwise substring match on err.Error()
	}{
		{
			name: "nil OIDC accepted",
			cfg:  nil,
		},
		{
			name: "disabled OIDC accepted regardless of fields",
			cfg:  &OIDCConfig{Enabled: false},
		},
		{
			name:      "enabled + unset default_role + no allowlists rejected",
			cfg:       &OIDCConfig{Enabled: true},
			wantError: "default_role",
		},
		{
			name:      "enabled + admin default_role + no allowlists rejected",
			cfg:       &OIDCConfig{Enabled: true, DefaultRole: "admin"},
			wantError: "default_role",
		},
		{
			name: "enabled + user default_role + no allowlists accepted",
			cfg:  &OIDCConfig{Enabled: true, DefaultRole: "user"},
		},
		{
			name: "enabled + admin default_role + allowed_emails set accepted (explicit two-field opt-in)",
			cfg:  &OIDCConfig{Enabled: true, DefaultRole: "admin", AllowedEmails: []string{"alice@example.com"}},
		},
		{
			name: "enabled + admin default_role + allowed_groups set accepted",
			cfg:  &OIDCConfig{Enabled: true, DefaultRole: "admin", AllowedGroups: []string{"nebula-admins"}},
		},
		{
			name: "enabled + unset default_role + allowed_emails set accepted (allowlist gates access; runtime defaults to user)",
			cfg:  &OIDCConfig{Enabled: true, AllowedEmails: []string{"alice@example.com"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantError == "" {
				if err != nil {
					t.Errorf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want error containing %q", tc.wantError)
			}
			if !strings.Contains(err.Error(), tc.wantError) {
				t.Errorf("Validate() = %v, want error containing %q", err, tc.wantError)
			}
		})
	}
}

// TestOIDCConfig_Validate_ErrorMessageNamesFields confirms the error message
// names both fields the operator can edit to fix the configuration, so a
// reader sees the resolution path without grepping the source.
func TestOIDCConfig_Validate_ErrorMessageNamesFields(t *testing.T) {
	cfg := &OIDCConfig{Enabled: true, DefaultRole: "admin"}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	for _, want := range []string{"default_role", "allowed_groups", "allowed_emails"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message %q missing %q", msg, want)
		}
	}
}
