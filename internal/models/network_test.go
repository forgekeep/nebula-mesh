package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetwork_CIDRs_Valid(t *testing.T) {
	tests := []struct {
		name string
		cidr []string
	}{
		{
			name: "single ipv4",
			cidr: []string{"10.42.0.0/24"},
		},
		{
			name: "single ipv6",
			cidr: []string{"fd00:42::/64"},
		},
		{
			name: "mixed ipv4 and ipv6",
			cidr: []string{"10.42.0.0/24", "fd00:42::/64"},
		},
		{
			name: "multiple ipv4",
			cidr: []string{"10.42.0.0/24", "192.168.0.0/16", "172.16.0.0/12"},
		},
		{
			name: "multiple ipv6",
			cidr: []string{"fd00::/64", "fd01::/64", "fd02::/64"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateNetworkCIDRs(tt.cidr)
			assert.NoError(t, err)
		})
	}
}

func TestNetwork_CIDRs_Empty(t *testing.T) {
	err := ValidateNetworkCIDRs([]string{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one CIDR required")
}

func TestNetwork_CIDRs_Duplicate(t *testing.T) {
	cidrs := []string{"10.42.0.0/24", "10.42.0.0/24"}
	err := ValidateNetworkCIDRs(cidrs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate")
}

func TestNetwork_CIDRs_Overlap(t *testing.T) {
	cidrs := []string{"10.0.0.0/8", "10.42.0.0/16"}
	err := ValidateNetworkCIDRs(cidrs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "overlap")
}

func TestNetwork_CIDRs_Invalid(t *testing.T) {
	tests := []struct {
		name string
		cidr []string
	}{
		{
			name: "invalid ipv4 prefix length",
			cidr: []string{"10.0.0.0/33"},
		},
		{
			name: "not a cidr",
			cidr: []string{"not-a-cidr"},
		},
		{
			name: "invalid in second element",
			cidr: []string{"10.42.0.0/24", "invalid"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateNetworkCIDRs(tt.cidr)
			require.Error(t, err)
		})
	}
}
