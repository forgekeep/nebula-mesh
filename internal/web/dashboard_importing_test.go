package web

import (
	"testing"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

func TestComputeStatsCountsImportingHostsSeparately(t *testing.T) {
	stats := computeStats([]*models.Host{
		{Status: models.HostStatusImporting},
		{Status: models.HostStatusPending},
		{Status: models.HostStatusEnrolled},
	}, 1)
	if stats.TotalHosts != 3 || stats.ImportingHosts != 1 || stats.PendingHosts != 1 || stats.EnrolledHosts != 1 {
		t.Fatalf("stats = %#v", stats)
	}
}
