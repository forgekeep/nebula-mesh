package pki

import "time"

const renewalThreshold = 0.20 // renew when less than 20% TTL remains

// HostCertInfo holds certificate timing for renewal checks.
type HostCertInfo struct {
	HostID    string
	NotBefore time.Time
	NotAfter  time.Time
}

// ShouldRenew returns true if the certificate should be renewed as of now.
// Renewal is needed when remaining TTL is less than 20% of total duration.
func ShouldRenew(notBefore, notAfter time.Time) bool {
	return ShouldRenewAt(notBefore, notAfter, time.Now())
}

// ShouldRenewAt is ShouldRenew evaluated at an explicit instant, so callers
// holding an injectable clock (and tests advancing simulated time) get a
// deterministic decision instead of an implicit time.Now().
func ShouldRenewAt(notBefore, notAfter, now time.Time) bool {
	total := notAfter.Sub(notBefore)
	remaining := notAfter.Sub(now)

	if remaining <= 0 {
		return true
	}

	return float64(remaining)/float64(total) <= renewalThreshold
}

// FindHostsForRenewal filters hosts that need certificate renewal.
func FindHostsForRenewal(hosts []HostCertInfo) []HostCertInfo {
	var result []HostCertInfo
	for _, h := range hosts {
		if ShouldRenew(h.NotBefore, h.NotAfter) {
			result = append(result, h)
		}
	}
	return result
}
