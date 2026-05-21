package api

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/juev/nebula-mesh/internal/models"
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

func TestBuildHostPrefixes_SingleFamily(t *testing.T) {
	network := &models.Network{
		ID:    "net1",
		Name:  "test",
		CIDRs: []string{"192.168.100.0/24"},
	}

	prefixes, err := buildHostPrefixes(network, []string{"192.168.100.10"})
	require.NoError(t, err)
	require.Len(t, prefixes, 1)
	assert.Equal(t, netip.MustParsePrefix("192.168.100.10/24"), prefixes[0])
}

func TestBuildHostPrefixes_DualFamily(t *testing.T) {
	network := &models.Network{
		ID:    "net1",
		Name:  "test",
		CIDRs: []string{"10.0.0.0/8", "fd00::/64"},
	}

	prefixes, err := buildHostPrefixes(network, []string{"fd00::5", "10.0.0.5"})
	require.NoError(t, err)
	require.Len(t, prefixes, 2)
	assert.Equal(t, netip.MustParsePrefix("fd00::5/64"), prefixes[0])
	assert.Equal(t, netip.MustParsePrefix("10.0.0.5/8"), prefixes[1])
}

func TestBuildHostPrefixes_ChoosesCorrectParent(t *testing.T) {
	network := &models.Network{
		ID:    "net1",
		Name:  "test",
		CIDRs: []string{"10.0.0.0/8", "192.168.0.0/16"},
	}

	prefixes, err := buildHostPrefixes(network, []string{"192.168.1.5"})
	require.NoError(t, err)
	require.Len(t, prefixes, 1)
	assert.Equal(t, netip.MustParsePrefix("192.168.1.5/16"), prefixes[0])
}

func TestBuildHostPrefixes_NoMatchingParent(t *testing.T) {
	network := &models.Network{
		ID:    "net1",
		Name:  "test",
		CIDRs: []string{"192.168.0.0/16"},
	}

	_, err := buildHostPrefixes(network, []string{"10.0.0.5"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not within any network CIDR")
}

func TestBuildHostPrefixes_OrderPreserved(t *testing.T) {
	network := &models.Network{
		ID:    "net1",
		Name:  "test",
		CIDRs: []string{"10.0.0.0/8", "fd00::/64"},
	}

	prefixes, err := buildHostPrefixes(network, []string{"fd00::5", "10.0.0.5"})
	require.NoError(t, err)
	require.Len(t, prefixes, 2)
	assert.Equal(t, netip.MustParsePrefix("fd00::5/64"), prefixes[0])
	assert.Equal(t, netip.MustParsePrefix("10.0.0.5/8"), prefixes[1])
}
