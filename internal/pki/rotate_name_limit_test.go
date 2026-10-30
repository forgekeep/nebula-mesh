package pki_test

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/pki"
)

// Appending "-rotated" to a CA name already at the certificate name limit
// used to produce a name Nebula cannot sign, so rotation failed for that CA.
func TestRotateAndStoreCA_NameAtCertLimit(t *testing.T) {
	s := newTestStore(t)
	master := newTestMaster(t)
	op := seedOperator(t, s, "op-alice", "alice")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	ca1, _, err := pki.MintAndStoreCA(context.Background(), s, master, logger, pki.MintRequest{
		Operator: op,
		Name:     strings.Repeat("a", models.MaxCertNameLen),
		Duration: 24 * time.Hour,
	})
	require.NoError(t, err)

	ca2, err := pki.RotateAndStoreCA(context.Background(), s, master, logger, ca1)
	require.NoError(t, err)
	assert.Len(t, ca2.Name, models.MaxCertNameLen)
	assert.True(t, strings.HasSuffix(ca2.Name, "-rotated"), "rotated name = %q", ca2.Name)
}
