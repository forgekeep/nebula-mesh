package pki

import (
	"testing"
	"time"
)

func TestShouldRenew(t *testing.T) {
	tests := []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
		want      bool
	}{
		{
			name:      "90% TTL remaining — no renewal",
			notBefore: time.Now().Add(-1 * 24 * time.Hour),
			notAfter:  time.Now().Add(9 * 24 * time.Hour),
			want:      false,
		},
		{
			name:      "50% TTL remaining — no renewal",
			notBefore: time.Now().Add(-5 * 24 * time.Hour),
			notAfter:  time.Now().Add(5 * 24 * time.Hour),
			want:      false,
		},
		{
			name:      "15% TTL remaining — needs renewal",
			notBefore: time.Now().Add(-17 * 24 * time.Hour),
			notAfter:  time.Now().Add(3 * 24 * time.Hour),
			want:      true,
		},
		{
			name:      "expired — needs renewal",
			notBefore: time.Now().Add(-10 * 24 * time.Hour),
			notAfter:  time.Now().Add(-1 * time.Hour),
			want:      true,
		},
		{
			name:      "exactly 20% — needs renewal",
			notBefore: time.Now().Add(-80 * time.Hour),
			notAfter:  time.Now().Add(20 * time.Hour),
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShouldRenew(tt.notBefore, tt.notAfter)
			if got != tt.want {
				total := tt.notAfter.Sub(tt.notBefore)
				remaining := time.Until(tt.notAfter)
				pct := float64(remaining) / float64(total) * 100
				t.Errorf("ShouldRenew() = %v, want %v (remaining: %.1f%%)", got, tt.want, pct)
			}
		})
	}
}

func TestFindHostsForRenewal(t *testing.T) {
	now := time.Now()

	hosts := []HostCertInfo{
		{HostID: "h1", NotBefore: now.Add(-17 * 24 * time.Hour), NotAfter: now.Add(3 * 24 * time.Hour)},  // 15% — renew
		{HostID: "h2", NotBefore: now.Add(-5 * 24 * time.Hour), NotAfter: now.Add(5 * 24 * time.Hour)},    // 50% — skip
		{HostID: "h3", NotBefore: now.Add(-19 * 24 * time.Hour), NotAfter: now.Add(1 * 24 * time.Hour)},   // 5% — renew
	}

	needRenewal := FindHostsForRenewal(hosts)
	if len(needRenewal) != 2 {
		t.Fatalf("expected 2 hosts for renewal, got %d", len(needRenewal))
	}
	if needRenewal[0].HostID != "h1" || needRenewal[1].HostID != "h3" {
		t.Errorf("wrong hosts: %v", needRenewal)
	}
}
