package meshimport

import (
	"encoding/json"
	"testing"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

func TestBuildPreviewUsesNormalizedSnapshotIdentity(t *testing.T) {
	fixture := newCertificateFixture(t)
	snapshot := fixture.snapshot(t, "payload-id", "node-a", "10.42.0.10/24", nil)
	snapshot.ID = "forged-snapshot"
	snapshot.HostID = "forged-host"
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	report := BuildPreview(PreviewInput{
		Session: &models.MeshImport{ID: "import-1", NetworkID: "network-1", CAID: "ca-1", CAFingerprint: fixture.caFingerprint},
		Network: &models.Network{ID: "network-1", CAID: "ca-1", CIDRs: []string{"10.42.0.0/16"}},
		CA:      &models.CA{ID: "ca-1", CertPEM: fixture.caPEM, Fingerprint: fixture.caFingerprint},
		Snapshots: []*models.MeshImportSnapshot{{
			ID: "stored-snapshot", MeshImportID: "import-1", HostID: "stored-host",
			CertificatePEM: snapshot.CertificatePEM, SnapshotJSON: string(encoded),
		}},
		Now: fixture.now,
	})
	if len(report.Blockers) != 0 || len(report.Proposal.Hosts) != 1 {
		t.Fatalf("preview = %#v", report)
	}
	got := report.Proposal.Hosts[0]
	if got.SnapshotID != "stored-snapshot" || got.Host.ID != "stored-host" {
		t.Fatalf("normalized identity = snapshot %q host %q", got.SnapshotID, got.Host.ID)
	}
}

func TestBuildPreviewRejectsMalformedOrOutOfScopeStoredSnapshot(t *testing.T) {
	fixture := newCertificateFixture(t)
	input := PreviewInput{
		Session: &models.MeshImport{ID: "import-1", NetworkID: "network-1", CAID: "ca-1", CAFingerprint: fixture.caFingerprint},
		Network: &models.Network{ID: "network-1", CAID: "ca-1", CIDRs: []string{"10.42.0.0/16"}},
		CA:      &models.CA{ID: "ca-1", CertPEM: fixture.caPEM, Fingerprint: fixture.caFingerprint},
		Snapshots: []*models.MeshImportSnapshot{{
			ID: "bad", MeshImportID: "another-import", HostID: "host-bad", SnapshotJSON: "not-json",
		}},
		Now: fixture.now,
	}
	report := BuildPreview(input)
	requireIssueCode(t, report.Blockers, IssueInvalidSnapshot)
	if len(report.Proposal.Hosts) != 0 {
		t.Fatalf("malformed snapshot produced proposal: %#v", report.Proposal.Hosts)
	}
}

func TestWarningAcknowledgementKeysAreStableAndDistinct(t *testing.T) {
	first := Issue{Code: IssueUnsupportedConfigKey, SnapshotID: "snapshot-a", Field: "config.unsupported_keys[0]", Message: "alpha"}
	second := Issue{Code: IssueUnsupportedConfigKey, SnapshotID: "snapshot-a", Field: "config.unsupported_keys[1]", Message: "beta"}
	stableCopy := first
	if WarningAcknowledgementKey(first) != WarningAcknowledgementKey(stableCopy) {
		t.Fatal("warning key is not stable")
	}
	if WarningAcknowledgementKey(first) == WarningAcknowledgementKey(second) {
		t.Fatal("distinct warnings share an acknowledgement key")
	}
}
