package meshimport

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

type PreviewInput struct {
	Session   *models.MeshImport
	Network   *models.Network
	CA        *models.CA
	Snapshots []*models.MeshImportSnapshot
	Now       time.Time
}

// BuildPreview decodes stored discovery payloads and reconciles them against
// the normalized session scope. Database columns remain authoritative for all
// identity fields; an agent-supplied JSON payload cannot choose its row ids.
func BuildPreview(input PreviewInput) Report {
	if input.Session == nil || input.Network == nil || input.CA == nil {
		return Report{Blockers: []Issue{{Code: IssueInvalidSnapshot, Field: "scope", Message: "mesh import scope is incomplete"}}}
	}
	snapshots := make([]Snapshot, 0, len(input.Snapshots))
	invalid := make([]Issue, 0)
	for _, stored := range input.Snapshots {
		if stored == nil || stored.ID == "" || stored.HostID == "" || stored.MeshImportID != input.Session.ID {
			invalid = append(invalid, Issue{Code: IssueInvalidSnapshot, Field: "snapshot", Message: "stored snapshot is outside the import session"})
			continue
		}
		var snapshot Snapshot
		if err := json.Unmarshal([]byte(stored.SnapshotJSON), &snapshot); err != nil {
			invalid = append(invalid, Issue{Code: IssueInvalidSnapshot, SnapshotID: stored.ID, Field: "snapshot", Message: fmt.Sprintf("decode stored snapshot: %v", err)})
			continue
		}
		snapshot.ID = stored.ID
		snapshot.HostID = stored.HostID
		snapshot.CertificatePEM = stored.CertificatePEM
		snapshots = append(snapshots, snapshot)
	}
	report := Reconcile(ReconcileInput{
		NetworkID: input.Network.ID, CAID: input.CA.ID, NetworkCIDRs: input.Network.CIDRs,
		CACertificatePEM: input.CA.CertPEM, CAFingerprint: input.Session.CAFingerprint,
		Snapshots: snapshots, Now: input.Now,
	})
	if len(invalid) != 0 {
		report.Blockers = append(report.Blockers, invalid...)
		sort.Slice(report.Blockers, func(i, j int) bool {
			left, right := report.Blockers[i], report.Blockers[j]
			if left.Code != right.Code {
				return left.Code < right.Code
			}
			if left.SnapshotID != right.SnapshotID {
				return left.SnapshotID < right.SnapshotID
			}
			return left.Field < right.Field
		})
	}
	return report
}

// WarningAcknowledgementKey is a stable opaque identifier for one exact
// warning. A changed preview therefore invalidates acknowledgements naturally.
func WarningAcknowledgementKey(issue Issue) string {
	encoded, _ := json.Marshal(issue)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
