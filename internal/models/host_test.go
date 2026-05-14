package models

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidRole(t *testing.T) {
	tests := []struct {
		role HostRole
		want bool
	}{
		{HostRoleHost, true},
		{HostRoleLighthouse, true},
		{HostRoleRelay, true},
		{"", true},       // empty = use default in handler
		{"invalid", false},
		{"admin", false},
		{"HOST", false}, // case-sensitive
	}

	for _, tt := range tests {
		t.Run(string(tt.role), func(t *testing.T) {
			if got := ValidRole(tt.role); got != tt.want {
				t.Errorf("ValidRole(%q) = %v, want %v", tt.role, got, tt.want)
			}
		})
	}
}

func TestValidateRoleReachability(t *testing.T) {
	tests := []struct {
		name       string
		role       HostRole
		publicIP   string
		listenPort int
		wantErr    error
	}{
		{"host: no constraints", HostRoleHost, "", 0, nil},
		{"host: empty alias", "", "", 0, nil},
		{"lighthouse: both set", HostRoleLighthouse, "203.0.113.1", 4242, nil},
		{"relay: both set", HostRoleRelay, "203.0.113.2", 4242, nil},

		{"lighthouse: missing public_ip", HostRoleLighthouse, "", 4242, ErrRoleRequiresPublicIP},
		{"lighthouse: whitespace public_ip", HostRoleLighthouse, "   ", 4242, ErrRoleRequiresPublicIP},
		{"lighthouse: missing listen_port", HostRoleLighthouse, "203.0.113.1", 0, ErrRoleRequiresListenPort},
		{"lighthouse: both missing → public_ip wins", HostRoleLighthouse, "", 0, ErrRoleRequiresPublicIP},

		{"relay: missing public_ip", HostRoleRelay, "", 4242, ErrRoleRequiresPublicIP},
		{"relay: missing listen_port", HostRoleRelay, "203.0.113.1", 0, ErrRoleRequiresListenPort},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateRoleReachability(tt.role, tt.publicIP, tt.listenPort)
			if tt.wantErr == nil {
				if got != nil {
					t.Errorf("got error %v, want nil", got)
				}
				return
			}
			if !errors.Is(got, tt.wantErr) {
				t.Errorf("got error %v, want %v", got, tt.wantErr)
			}
		})
	}
}

func TestValidKind(t *testing.T) {
	tests := []struct {
		name     string
		kind     HostKind
		expected bool
	}{
		{name: "agent", kind: HostKindAgent, expected: true},
		{name: "mobile", kind: HostKindMobile, expected: true},
		{name: "empty string", kind: "", expected: false},
		{name: "unknown", kind: "unknown", expected: false},
		{name: "lighthouse", kind: "lighthouse", expected: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, ValidKind(tt.kind))
		})
	}
}

func TestValidVariant(t *testing.T) {
	tests := []struct {
		name    string
		variant HostVariant
		expected bool
	}{
		{name: "none (empty)", variant: HostVariantNone, expected: true},
		{name: "ios", variant: HostVariantIOS, expected: true},
		{name: "android", variant: HostVariantAndroid, expected: true},
		{name: "windows", variant: "windows", expected: false},
		{name: "macos", variant: "macos", expected: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, ValidVariant(tt.variant))
		})
	}
}

func TestValidateMobileConstraints(t *testing.T) {
	tests := []struct {
		name    string
		kind    HostKind
		variant HostVariant
		role    HostRole
		wantErr bool
		errIs   error
	}{
		{
			name:    "mobile with lighthouse role",
			kind:    HostKindMobile,
			variant: HostVariantIOS,
			role:    HostRoleLighthouse,
			wantErr: true,
			errIs:   ErrMobileRoleRestricted,
		},
		{
			name:    "mobile with relay role",
			kind:    HostKindMobile,
			variant: HostVariantAndroid,
			role:    HostRoleRelay,
			wantErr: true,
			errIs:   ErrMobileRoleRestricted,
		},
		{
			name:    "mobile with variant empty and role host",
			kind:    HostKindMobile,
			variant: HostVariantNone,
			role:    HostRoleHost,
			wantErr: true,
			errIs:   ErrMobileVariantRequired,
		},
		{
			name:    "mobile ios with host role",
			kind:    HostKindMobile,
			variant: HostVariantIOS,
			role:    HostRoleHost,
			wantErr: false,
		},
		{
			name:    "mobile android with host role",
			kind:    HostKindMobile,
			variant: HostVariantAndroid,
			role:    HostRoleHost,
			wantErr: false,
		},
		{
			name:    "agent with any role and any variant",
			kind:    HostKindAgent,
			variant: HostVariantIOS,
			role:    HostRoleLighthouse,
			wantErr: false,
		},
		{
			name:    "agent kind ignores mobile constraints",
			kind:    HostKindAgent,
			variant: HostVariantNone,
			role:    HostRoleRelay,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMobileConstraints(tt.kind, tt.variant, tt.role)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errIs != nil {
					assert.ErrorIs(t, err, tt.errIs)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
