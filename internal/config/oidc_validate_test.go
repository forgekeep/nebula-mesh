package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
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
				return
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
		return
	}
	msg := err.Error()
	for _, want := range []string{"default_role", "allowed_groups", "allowed_emails"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message %q missing %q", msg, want)
		}
	}
}

// TestOIDCConfig_RequireEmailVerified_YAMLRoundTrip pins yaml.v3's
// decoding of the `require_email_verified` knob. The field is a
// *bool so the unset case is distinguishable from explicit `false`
// — EmailVerifiedRequired() must default to `true` when the field
// is nil, and only return `false` for an explicit `false` value.
//
// The quoted-bool case (`"false"`) is the interesting one: yaml.v3
// is strict about !!str → !!bool coercion and rejects it with a
// type-error rather than silently treating it as false. Pinning the
// behavior here means a future YAML-library swap (or yaml.v3 major
// version bump) that started accepting quoted bools as truthy would
// be caught by CI instead of silently downgrading the gate.
func TestOIDCConfig_RequireEmailVerified_YAMLRoundTrip(t *testing.T) {
	cases := []struct {
		name              string
		yamlSnippet       string
		wantParseError    bool
		wantPointerNil    bool
		wantRequired      bool // value of EmailVerifiedRequired() after parse (only checked if no parse error)
	}{
		{
			name:              "unset_defaults_to_required",
			yamlSnippet:       `enabled: true`,
			wantPointerNil:    true,
			wantRequired:      true,
		},
		{
			name:              "bare_true_keeps_required",
			yamlSnippet:       "enabled: true\nrequire_email_verified: true\n",
			wantPointerNil:    false,
			wantRequired:      true,
		},
		{
			name:              "bare_false_opts_out",
			yamlSnippet:       "enabled: true\nrequire_email_verified: false\n",
			wantPointerNil:    false,
			wantRequired:      false,
		},
		{
			// yaml.v3 default mode: !!str cannot unmarshal into
			// a *bool, so the quoted form errors out. The error
			// surfaces to the operator at LoadServerConfig time
			// — louder failure than silently treating the
			// quoted form as a bool of either polarity.
			name:           "quoted_false_errors",
			yamlSnippet:    "enabled: true\nrequire_email_verified: \"false\"\n",
			wantParseError: true,
		},
		{
			// Same posture for quoted "true": yaml.v3 errors
			// rather than silently accepting it as truthy.
			name:           "quoted_true_errors",
			yamlSnippet:    "enabled: true\nrequire_email_verified: \"true\"\n",
			wantParseError: true,
		},
		{
			// yaml.v3 still accepts YAML 1.1 truthy strings
			// (yes/no/on/off/y/n) as bools when the target is
			// *bool. Operators who write `require_email_verified:
			// no` thinking it's a quoted string will silently
			// land in bypass mode. Pinning so the surprising
			// behavior is at least visible in tests — a future
			// yaml-lib swap that rejected these would actually
			// be safer, not a regression.
			name:           "yaml_1_1_no_accepted_as_bypass",
			yamlSnippet:    "enabled: true\nrequire_email_verified: no\n",
			wantPointerNil: false,
			wantRequired:   false,
		},
		{
			name:           "yaml_1_1_yes_accepted_as_required",
			yamlSnippet:    "enabled: true\nrequire_email_verified: yes\n",
			wantPointerNil: false,
			wantRequired:   true,
		},
		{
			name:           "yaml_1_1_off_accepted_as_bypass",
			yamlSnippet:    "enabled: true\nrequire_email_verified: off\n",
			wantPointerNil: false,
			wantRequired:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var cfg OIDCConfig
			err := yaml.Unmarshal([]byte(tc.yamlSnippet), &cfg)
			if tc.wantParseError {
				if err == nil {
					t.Fatalf("expected parse error, got nil; cfg.RequireEmailVerified=%v EmailVerifiedRequired=%v", cfg.RequireEmailVerified, cfg.EmailVerifiedRequired())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected parse error: %v", err)
			}
			if (cfg.RequireEmailVerified == nil) != tc.wantPointerNil {
				t.Errorf("RequireEmailVerified pointer nil=%v, want nil=%v", cfg.RequireEmailVerified == nil, tc.wantPointerNil)
			}
			if got := cfg.EmailVerifiedRequired(); got != tc.wantRequired {
				t.Errorf("EmailVerifiedRequired() = %v, want %v", got, tc.wantRequired)
			}
		})
	}
}

// TestOIDCConfig_EmailVerifiedRequired_DefaultsToTrue pins the
// accessor's behavior on nil receiver and nil field, so a future
// refactor that changes the default cannot do so silently.
func TestOIDCConfig_EmailVerifiedRequired_DefaultsToTrue(t *testing.T) {
	cases := []struct {
		name string
		cfg  *OIDCConfig
		want bool
	}{
		{"nil_receiver", nil, true},
		{"empty_config", &OIDCConfig{}, true},
		{"explicit_true", &OIDCConfig{RequireEmailVerified: ptrBool(true)}, true},
		{"explicit_false", &OIDCConfig{RequireEmailVerified: ptrBool(false)}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.EmailVerifiedRequired(); got != tc.want {
				t.Errorf("EmailVerifiedRequired() = %v, want %v", got, tc.want)
			}
		})
	}
}

func ptrBool(b bool) *bool { return &b }
