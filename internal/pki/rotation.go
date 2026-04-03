package pki

import (
	"fmt"
	"time"
)

// Rotation manages a CA rotation: old CA + new CA in parallel.
type Rotation struct {
	oldCA *CAManager
	newCA *CAManager
}

// NewRotation creates a new CA and sets up a rotation from the old CA.
func NewRotation(oldCA *CAManager, newName string, duration time.Duration) (*Rotation, error) {
	newCA, _, err := NewCA(newName, duration)
	if err != nil {
		return nil, fmt.Errorf("create new CA: %w", err)
	}

	return &Rotation{oldCA: oldCA, newCA: newCA}, nil
}

// OldCA returns the old CA.
func (r *Rotation) OldCA() *CAManager {
	return r.oldCA
}

// NewCA returns the new CA.
func (r *Rotation) NewCA() *CAManager {
	return r.newCA
}

// TrustBundle returns PEM bytes containing both CA certificates.
// Agents should trust both during the transition period.
func (r *Rotation) TrustBundle() ([]byte, error) {
	oldPEM, err := r.oldCA.CACertPEM()
	if err != nil {
		return nil, fmt.Errorf("marshal old CA: %w", err)
	}

	newPEM, err := r.newCA.CACertPEM()
	if err != nil {
		return nil, fmt.Errorf("marshal new CA: %w", err)
	}

	bundle := make([]byte, 0, len(oldPEM)+len(newPEM))
	bundle = append(bundle, oldPEM...)
	bundle = append(bundle, newPEM...)

	return bundle, nil
}
