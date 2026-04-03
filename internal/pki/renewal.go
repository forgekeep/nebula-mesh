package pki

import "time"

const renewalThreshold = 0.20 // renew when less than 20% TTL remains

// HostCertInfo holds certificate timing for renewal checks.
type HostCertInfo struct {
	HostID    string
	NotBefore time.Time
	NotAfter  time.Time
}

// ShouldRenew returns true if the certificate should be renewed.
// Renewal is needed when remaining TTL is less than 20% of total duration.
func ShouldRenew(notBefore, notAfter time.Time) bool {
	total := notAfter.Sub(notBefore)
	remaining := time.Until(notAfter)

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
