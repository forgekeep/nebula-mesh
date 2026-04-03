package models

import "testing"

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
