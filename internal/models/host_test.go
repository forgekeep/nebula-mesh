package models

import (
	"errors"
	"testing"
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
