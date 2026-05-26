package pki

import (
	"testing"
	"time"
)

func TestShouldRenewAt(t *testing.T) {
	// Fixed reference instant — no wall clock, so the table is deterministic
	// (the old time.Now()-relative table could straddle a boundary).
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
		want      bool
	}{
		{"90% TTL remaining — no renewal", now.Add(-1 * 24 * time.Hour), now.Add(9 * 24 * time.Hour), false},
		{"50% TTL remaining — no renewal", now.Add(-5 * 24 * time.Hour), now.Add(5 * 24 * time.Hour), false},
		{"15% TTL remaining — needs renewal", now.Add(-17 * 24 * time.Hour), now.Add(3 * 24 * time.Hour), true},
		{"expired — needs renewal", now.Add(-10 * 24 * time.Hour), now.Add(-1 * time.Hour), true},
		{"exactly 20% — needs renewal", now.Add(-80 * time.Hour), now.Add(20 * time.Hour), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShouldRenewAt(tt.notBefore, tt.notAfter, now)
			if got != tt.want {
				total := tt.notAfter.Sub(tt.notBefore)
				remaining := tt.notAfter.Sub(now)
				pct := float64(remaining) / float64(total) * 100
				t.Errorf("ShouldRenewAt() = %v, want %v (remaining: %.1f%%)", got, tt.want, pct)
			}
		})
	}
}

// TestShouldRenew_DelegatesToWallClock spot-checks the wall-clock wrapper.
func TestShouldRenew_DelegatesToWallClock(t *testing.T) {
	if !ShouldRenew(time.Now().Add(-10*24*time.Hour), time.Now().Add(-time.Hour)) {
		t.Error("expired cert should need renewal via ShouldRenew")
	}
	if ShouldRenew(time.Now().Add(-time.Hour), time.Now().Add(9*24*time.Hour)) {
		t.Error("fresh cert should not need renewal via ShouldRenew")
	}
}

func TestFindHostsForRenewal(t *testing.T) {
	now := time.Now()

	hosts := []HostCertInfo{
		{HostID: "h1", NotBefore: now.Add(-17 * 24 * time.Hour), NotAfter: now.Add(3 * 24 * time.Hour)}, // 15% — renew
		{HostID: "h2", NotBefore: now.Add(-5 * 24 * time.Hour), NotAfter: now.Add(5 * 24 * time.Hour)},  // 50% — skip
		{HostID: "h3", NotBefore: now.Add(-19 * 24 * time.Hour), NotAfter: now.Add(1 * 24 * time.Hour)}, // 5% — renew
	}

	needRenewal := FindHostsForRenewal(hosts)
	if len(needRenewal) != 2 {
		t.Fatalf("expected 2 hosts for renewal, got %d", len(needRenewal))
	}
	if needRenewal[0].HostID != "h1" || needRenewal[1].HostID != "h3" {
		t.Errorf("wrong hosts: %v", needRenewal)
	}
}
