// Package cawatch implements the CA auto-rotation scanner: a periodic watchdog
// that detects CAs approaching their expiry and automatically rotates them.
// This is an opt-in feature controlled by the ca_auto_rotate config section.
package cawatch

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/keystore"
	"github.com/forgekeep/nebula-mesh/internal/pki"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

// Scanner is a periodic CA auto-rotation watchdog. Wire one up at server start,
// call StartLoop with a cancellable context, and it ticks every Interval
// until the context is canceled.
type Scanner struct {
	Store     store.Store
	Master    *keystore.Master
	Logger    *slog.Logger
	Threshold float64       // 0.20 default; fraction of CA lifetime when rotation is triggered
	Interval  time.Duration // 6*time.Hour default; how often to scan
}

// Run performs a single sweep: find CAs approaching expiry and rotate them.
// Errors from individual CA rotations are logged but do not stop the loop;
// rotation is idempotent through pki.RotateAndStoreCA (returns existing successor if any).
func (s *Scanner) Run(ctx context.Context) error {
	// Apply defaults if not set
	threshold := s.Threshold
	if threshold <= 0 {
		threshold = 0.20
	}

	cas, err := s.Store.ListCAsApproachingExpiry(ctx, threshold)
	if err != nil {
		return fmt.Errorf("list approaching expiry: %w", err)
	}

	for _, ca := range cas {
		// Respect context cancellation
		if ctx.Err() != nil {
			return ctx.Err()
		}

		_, rerr := pki.RotateAndStoreCA(ctx, s.Store, s.Master, s.logger(), ca)
		if rerr != nil {
			s.logger().Error("auto-rotate ca", "id", ca.ID, "name", ca.Name, "error", rerr)
			// Continue loop — don't block on single failure
			continue
		}
		s.logger().Info("auto-rotated ca", "id", ca.ID, "name", ca.Name)
	}
	return nil
}

// StartLoop runs Run() immediately, then on every Interval tick until ctx is
// canceled. Returns once the loop exits.
func (s *Scanner) StartLoop(ctx context.Context) {
	interval := s.Interval
	if interval <= 0 {
		interval = 6 * time.Hour
	}

	// Initial run immediately
	if err := s.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		s.logger().Error("ca auto-rotate scanner initial run", "error", err)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				s.logger().Error("ca auto-rotate scanner tick", "error", err)
			}
		}
	}
}

func (s *Scanner) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}
