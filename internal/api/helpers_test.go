package api

import (
	"net/netip"
	"testing"
)

func TestBuildHostPrefix(t *testing.T) {
	tests := []struct {
		name    string
		hostIP  string
		cidr    string
		want    netip.Prefix
		wantErr bool
	}{
		{
			name:   "v4 match",
			hostIP: "192.168.100.10",
			cidr:   "192.168.100.0/24",
			want:   netip.MustParsePrefix("192.168.100.10/24"),
		},
		{
			name:    "v4 host vs v6 network",
			hostIP:  "192.168.100.10",
			cidr:    "fd00::/64",
			wantErr: true,
		},
		{
			name:    "invalid host IP",
			hostIP:  "not-an-ip",
			cidr:    "192.168.100.0/24",
			wantErr: true,
		},
		{
			name:    "invalid CIDR",
			hostIP:  "192.168.100.10",
			cidr:    "bad-cidr",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildHostPrefix(tt.hostIP, tt.cidr)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
