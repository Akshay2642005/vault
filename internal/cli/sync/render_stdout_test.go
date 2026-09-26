package sync

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"vault/internal/domain"
	syncengine "vault/internal/sync/engine"
)

// captureStdout redirects os.Stdout for the duration of fn and returns what was
// printed. These tests are intentionally serial (no t.Parallel): swapping the
// package-global os.Stdout while parallel tests run would race under -race.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe() error = %v", err)
	}
	os.Stdout = w

	fn()

	_ = w.Close()
	os.Stdout = old

	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	_ = r.Close()
	return string(data)
}

func TestRenderPlanPrintsToStdout(t *testing.T) {
	plan := syncengine.Plan{
		Push: []syncengine.Operation{
			op(syncengine.OpUpsertRemote, "myapp", "development", "API_KEY"),
		},
	}

	out := captureStdout(t, func() { RenderPlan(plan) })
	mustContain(t, out,
		"Sync plan",
		"Push (local -> remote): 1",
		"    - upsert-remote API_KEY",
	)
}

func TestRenderResult(t *testing.T) {
	dry := captureStdout(t, func() {
		RenderResult(syncengine.Result{Plan: syncengine.Plan{}, Applied: false})
	})
	mustContain(t, dry, "(dry-run) Plan generated. No changes applied.")

	applied := captureStdout(t, func() {
		RenderResult(syncengine.Result{
			Plan:              syncengine.Plan{},
			Applied:           true,
			OperationsApplied: 3,
			ConflictsDetected: 1,
		})
	})
	mustContain(t, applied, "✓ Sync complete (applied 3 operations, detected 1 conflicts)")
}

func TestRenderSyncRunsEmpty(t *testing.T) {
	out := captureStdout(t, func() { RenderSyncRuns(nil) })
	mustContain(t, out, "No sync runs recorded yet.")
}

func TestRenderSyncRunsTable(t *testing.T) {
	started := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)

	runs := []*domain.SyncRun{
		{
			StartedAt: started,
			Direction: "both",
			Status:    domain.SyncStatusInSync,
			Pushed:    2,
			Pulled:    1,
			Conflicts: 0,
			Scope:     "myapp/development",
		},
		{
			StartedAt: started.Add(time.Hour),
			Direction: "push",
			Status:    domain.SyncStatusFailed,
			DryRun:    true,
			Error:     "connection refused",
		},
	}

	out := captureStdout(t, func() { RenderSyncRuns(runs) })
	mustContain(t, out,
		"Sync run history (newest first)",
		"STATUS",
		// Row 1: in-sync run with scope note.
		"synced",
		"2026-03-01 10:00:00",
		"both",
		"myapp/development",
		// Row 2: dry-run flag overrides status; error becomes the note.
		"dry-run",
		"push",
		"connection refused",
	)

	// Dry-run must win over the stored status value.
	if strings.Contains(out, "failed") {
		t.Fatalf("dry-run row must display 'dry-run', not its status:\n%s", out)
	}
}

func TestRenderSyncRunsErrorAppendedToScope(t *testing.T) {
	runs := []*domain.SyncRun{
		{
			StartedAt: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC),
			Direction: "pull",
			Status:    domain.SyncStatusFailed,
			Scope:     "myapp",
			Error:     "boom",
		},
	}

	out := captureStdout(t, func() { RenderSyncRuns(runs) })
	mustContain(t, out, "myapp: boom")
}
