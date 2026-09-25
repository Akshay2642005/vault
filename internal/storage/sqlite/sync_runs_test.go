package sqlite

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vault/internal/domain"
	"vault/internal/storage"
)

func TestSyncRunRoundTripAndOrdering(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	backend := newTestBackend(t, ctx)

	base := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)

	runs := []*domain.SyncRun{
		{
			ID:         domain.GenerateID(),
			StartedAt:  base,
			FinishedAt: base.Add(30 * time.Second),
			Direction:  "both",
			Strategy:   "prefer-latest",
			Scope:      "myapp/development",
			Status:     domain.SyncStatusInSync,
			DryRun:     false,
			Pushed:     3,
			Pulled:     1,
			Conflicts:  0,
		},
		{
			ID:         domain.GenerateID(),
			StartedAt:  base.Add(time.Hour),
			FinishedAt: base.Add(time.Hour + time.Minute),
			Direction:  "pull",
			Strategy:   "fail",
			Scope:      "myapp/development",
			Status:     domain.SyncStatusFailed,
			DryRun:     false,
			Pushed:     0,
			Pulled:     0,
			Conflicts:  2,
			Error:      "conflict on myapp/development/API_KEY",
		},
		{
			ID:         domain.GenerateID(),
			StartedAt:  base.Add(2 * time.Hour),
			FinishedAt: base.Add(2 * time.Hour),
			Direction:  "both",
			Strategy:   "fail",
			Status:     domain.SyncStatusDryRun,
			DryRun:     true,
			Pushed:     0,
			Pulled:     0,
			Conflicts:  0,
		},
	}

	for _, r := range runs {
		if err := backend.RecordSyncRun(ctx, r); err != nil {
			t.Fatalf("RecordSyncRun() error = %v", err)
		}
	}

	// Newest first, limit respected.
	got, err := backend.ListSyncRuns(ctx, 2)
	if err != nil {
		t.Fatalf("ListSyncRuns() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len(ListSyncRuns(2)) = %d, want 2", len(got))
	}

	first := got[0]
	if first.Status != domain.SyncStatusDryRun || !first.DryRun {
		t.Fatalf("newest run wrong: %+v", first)
	}
	second := got[1]
	if second.Status != domain.SyncStatusFailed || second.Conflicts != 2 || second.Error == "" {
		t.Fatalf("second run wrong: %+v", second)
	}
	if !strings.Contains(second.Error, "API_KEY") {
		t.Fatalf("second run error = %q, want conflict on API_KEY", second.Error)
	}
	if second.Direction != "pull" || second.Strategy != "fail" || second.Scope != "myapp/development" {
		t.Fatalf("second run metadata wrong: %+v", second)
	}

	// Full list round-trips all fields.
	all, err := backend.ListSyncRuns(ctx, 10)
	if err != nil {
		t.Fatalf("ListSyncRuns(10) error = %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("len(ListSyncRuns(10)) = %d, want 3", len(all))
	}
	oldest := all[2]
	if oldest.Status != domain.SyncStatusInSync || oldest.Pushed != 3 || oldest.Pulled != 1 {
		t.Fatalf("oldest run fields wrong: %+v", oldest)
	}
}

func TestSyncRunRendersWorksWithoutVaultUnlock(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	cfg := &storage.Config{
		Type: "sqlite",
		Path: filepath.Join(t.TempDir(), "vault.db"),
	}

	backend, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	if err := backend.Initialize(ctx, cfg); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	// NOTE: CreateVault but NOT UnlockVault — sync_runs is metadata-only and
	// must be queryable from an initialized-but-locked vault (sync status).
	if err := backend.CreateVault(ctx, "password123"); err != nil {
		t.Fatalf("CreateVault() error = %v", err)
	}

	if err := backend.RecordSyncRun(ctx, &domain.SyncRun{
		ID:         domain.GenerateID(),
		StartedAt:  time.Now(),
		FinishedAt: time.Now(),
		Direction:  "both",
		Strategy:   "fail",
		Status:     domain.SyncStatusInSync,
		Pushed:     1,
	}); err != nil {
		t.Fatalf("RecordSyncRun() on locked vault error = %v", err)
	}

	runs, err := backend.ListSyncRuns(ctx, 5)
	if err != nil {
		t.Fatalf("ListSyncRuns() on locked vault error = %v", err)
	}
	if len(runs) != 1 || runs[0].Pushed != 1 {
		t.Fatalf("ListSyncRuns() on locked vault = %+v, want 1 run pushed=1", runs)
	}
}
