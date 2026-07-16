package meshimport

import (
	"encoding/json"
	"errors"
	"fmt"
)

const (
	defaultMaxSnapshotBytes = 2 << 20
	defaultMaxPathBytes     = 4096
)

var (
	ErrSnapshotTooLarge = errors.New("mesh import snapshot is too large")
	ErrInvalidAgentPath = errors.New("invalid Nebula agent path")
)

type Limits struct {
	MaxSnapshotBytes int
	MaxPathBytes     int
}

func ValidateSnapshot(snapshot Snapshot, limits Limits) error {
	limits = normalizedLimits(limits)
	if snapshot.ID == "" || snapshot.HostID == "" || snapshot.CertificatePEM == "" {
		return errors.New("snapshot id, host id and certificate are required")
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return fmt.Errorf("measure snapshot: %w", err)
	}
	if len(encoded) > limits.MaxSnapshotBytes {
		return fmt.Errorf("%w: %d bytes exceeds %d", ErrSnapshotTooLarge, len(encoded), limits.MaxSnapshotBytes)
	}
	if err := snapshot.Profile.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidAgentPath, err)
	}
	for _, path := range []string{snapshot.Profile.NebulaConfigPath, snapshot.Profile.NebulaCAPath, snapshot.Profile.NebulaCertPath, snapshot.Profile.NebulaKeyPath} {
		if len(path) > limits.MaxPathBytes {
			return fmt.Errorf("%w: path exceeds %d bytes", ErrInvalidAgentPath, limits.MaxPathBytes)
		}
	}
	return nil
}

func normalizedLimits(limits Limits) Limits {
	if limits.MaxSnapshotBytes <= 0 {
		limits.MaxSnapshotBytes = defaultMaxSnapshotBytes
	}
	if limits.MaxPathBytes <= 0 {
		limits.MaxPathBytes = defaultMaxPathBytes
	}
	return limits
}
