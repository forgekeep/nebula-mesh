package models

import (
	"fmt"
	"unicode/utf8"
)

// MaxCertNameLen bounds a name embedded in a Nebula v2 certificate, host or CA,
// in bytes. It mirrors cert.MaxNameLength: Nebula refuses to load a v2
// certificate whose name is empty or longer, and since v1.12 refuses to sign
// one, so a longer name would yield a CA or host that can never work.
const MaxCertNameLen = 253

// MaxMTU is the largest tun MTU Nebula can carry. Its underlay buffer is 9001
// bytes and a relayed packet adds 64 bytes of overhead, so larger values never
// fit; Nebula v1.12 caps them to this value with a warning.
const MaxMTU = 8937

// ValidateCertName rejects a name Nebula cannot carry in a v2 certificate.
func ValidateCertName(field, name string) error {
	if name == "" {
		return fmt.Errorf("%s must not be empty", field)
	}
	if len(name) > MaxCertNameLen {
		return fmt.Errorf("%s must be at most %d bytes", field, MaxCertNameLen)
	}
	return nil
}

// CertNameWithSuffix appends suffix to base, trimming base at a rune boundary
// so the result fits MaxCertNameLen. Derived names such as "<user>-default" or
// "<ca>-rotated" must stay signable even when base is already at the limit.
func CertNameWithSuffix(base, suffix string) string {
	limit := MaxCertNameLen - len(suffix)
	if len(base) > limit {
		for limit > 0 && !utf8.RuneStart(base[limit]) {
			limit--
		}
		base = base[:limit]
	}
	return base + suffix
}
