package agent

import (
	"errors"
	"fmt"

	"github.com/forgekeep/nebula-mesh/internal/bootstraptoken"
)

type BootstrapAction string

const (
	BootstrapEnroll BootstrapAction = "enroll"
	BootstrapImport BootstrapAction = "import"
)

// DecideBootstrap is the shared local state/token-purpose gate used by both
// command entrypoints. It performs no network or filesystem writes.
func DecideBootstrap(state DiscoveryState, token string, force bool) (BootstrapAction, error) {
	purpose, known := bootstraptoken.PurposeOf(token)
	legacyEnrollment := !known && bootstraptoken.ValidatePurpose(token, bootstraptoken.PurposeEnrollment, true) == nil
	if !known && !legacyEnrollment {
		return "", fmt.Errorf("unknown bootstrap token purpose")
	}
	if state == DiscoveryUnsafe {
		if force && (purpose == bootstraptoken.PurposeEnrollment || legacyEnrollment) {
			return BootstrapEnroll, nil
		}
		return "", errors.New("existing Nebula installation is partial or unsafe")
	}
	switch state {
	case DiscoveryNone:
		if purpose == bootstraptoken.PurposeMeshImport {
			return "", errors.New("import token requires an existing complete Nebula installation")
		}
		return BootstrapEnroll, nil
	case DiscoveryComplete:
		if purpose == bootstraptoken.PurposeMeshImport {
			return BootstrapImport, nil
		}
		if force && (purpose == bootstraptoken.PurposeEnrollment || legacyEnrollment) {
			return BootstrapEnroll, nil
		}
		return "", errors.New("existing Nebula installation requires an import token; use --force only for destructive fresh enrollment")
	default:
		return "", fmt.Errorf("unknown discovery state %q", state)
	}
}
