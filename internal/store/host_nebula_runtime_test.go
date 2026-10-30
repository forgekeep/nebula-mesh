package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestReportHostNebulaRuntime_ChangeRedeliversConfig(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	h := createTestHost(t, s, createTestNetwork(t, s))
	if err := s.UpdateHostConfigVersion(ctx, h.ID, 5); err != nil {
		t.Fatal(err)
	}

	at := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	changed, err := s.ReportHostNebulaRuntime(ctx, h.ID, "1.12.0", "linux", at)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("first report: changed = false, want true")
	}
	got, err := s.GetHost(ctx, h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.NebulaVersion != "1.12.0" || got.NebulaOS != "linux" {
		t.Errorf("runtime = %q/%q, want 1.12.0/linux", got.NebulaVersion, got.NebulaOS)
	}
	if got.NebulaReportedAt == nil || !got.NebulaReportedAt.Equal(at) {
		t.Errorf("nebula_reported_at = %v, want %v", got.NebulaReportedAt, at)
	}
	if v, err := s.GetHostConfigVersion(ctx, h.ID); err != nil || v != 0 {
		t.Errorf("config_version = %d, %v; want 0 so the next poll redelivers", v, err)
	}
}

func TestReportHostNebulaRuntime_SameReportKeepsConfigVersion(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	h := createTestHost(t, s, createTestNetwork(t, s))
	if _, err := s.ReportHostNebulaRuntime(ctx, h.ID, "1.12.0", "linux", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateHostConfigVersion(ctx, h.ID, 7); err != nil {
		t.Fatal(err)
	}

	later := time.Date(2026, 10, 30, 13, 0, 0, 0, time.UTC)
	changed, err := s.ReportHostNebulaRuntime(ctx, h.ID, "1.12.0", "linux", later)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("repeated report: changed = true, want false")
	}
	if v, _ := s.GetHostConfigVersion(ctx, h.ID); v != 7 {
		t.Errorf("config_version = %d, want 7", v)
	}
	got, _ := s.GetHost(ctx, h.ID)
	if got.NebulaReportedAt == nil || !got.NebulaReportedAt.Equal(later) {
		t.Errorf("nebula_reported_at = %v, want %v", got.NebulaReportedAt, later)
	}
}

func TestReportHostNebulaRuntime_OSChangeAloneRedelivers(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	h := createTestHost(t, s, createTestNetwork(t, s))
	if _, err := s.ReportHostNebulaRuntime(ctx, h.ID, "1.12.0", "linux", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateHostConfigVersion(ctx, h.ID, 3); err != nil {
		t.Fatal(err)
	}
	changed, err := s.ReportHostNebulaRuntime(ctx, h.ID, "1.12.0", "windows", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("OS change: changed = false, want true")
	}
	if v, _ := s.GetHostConfigVersion(ctx, h.ID); v != 0 {
		t.Errorf("config_version = %d, want 0", v)
	}
}

func TestReportHostNebulaRuntime_NotFound(t *testing.T) {
	s := newTestStore(t)
	_, err := s.ReportHostNebulaRuntime(context.Background(), "nonexistent", "1.12.0", "linux", time.Now())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// An operator edit rewrites the host row from a copy read earlier; it must not
// put back the runtime values that copy held.
func TestUpdateHost_KeepsReportedNebulaRuntime(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	h := createTestHost(t, s, createTestNetwork(t, s))
	stale, err := s.GetHost(ctx, h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReportHostNebulaRuntime(ctx, h.ID, "1.12.0", "linux", time.Now()); err != nil {
		t.Fatal(err)
	}

	stale.Name = "renamed"
	if err := s.UpdateHost(ctx, stale); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetHost(ctx, h.ID)
	if got.NebulaVersion != "1.12.0" || got.NebulaOS != "linux" {
		t.Errorf("runtime after edit = %q/%q, want 1.12.0/linux", got.NebulaVersion, got.NebulaOS)
	}
}

func TestMigration030_ExistingHostsStartUnknown(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	h := createTestHost(t, s, createTestNetwork(t, s))
	got, err := s.GetHost(ctx, h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.NebulaVersion != "" || got.NebulaOS != "" || got.NebulaReportedAt != nil {
		t.Errorf("new host runtime = %q/%q/%v, want empty", got.NebulaVersion, got.NebulaOS, got.NebulaReportedAt)
	}
}
