package sync

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"vault/internal/storage"
	_ "vault/internal/storage/sqlite"
	syncengine "vault/internal/sync/engine"
)

const enableTestPassword = "password123"

// newTempBackend returns a fresh, initialized, unlocked sqlite backend that
// plays the role of a sync target in these tests.
func newTempBackend(t *testing.T) storage.Backend {
	t.Helper()

	cfg := &storage.Config{Type: "sqlite", Path: filepath.Join(t.TempDir(), "vault.db")}
	b, err := storage.NewBackend(cfg)
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func TestEnableSyncTargetInitializes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	remote := newTempBackend(t)
	initialized, err := remote.IsInitialized(ctx)
	if err != nil {
		t.Fatalf("IsInitialized() error = %v", err)
	}
	if initialized {
		t.Fatal("fresh backend already initialized")
	}

	if err := EnableSyncTarget(ctx, remote, enableTestPassword); err != nil {
		t.Fatalf("EnableSyncTarget() error = %v", err)
	}

	initialized, err = remote.IsInitialized(ctx)
	if err != nil {
		t.Fatalf("IsInitialized() error = %v", err)
	}
	if !initialized {
		t.Fatal("backend not initialized after EnableSyncTarget")
	}
	if _, err := remote.UnlockVault(ctx, enableTestPassword); err != nil {
		t.Fatalf("UnlockVault() after enable error = %v", err)
	}
}

func TestEnableSyncTargetIdempotentWhenInitialized(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	remote := newTempBackend(t)
	if err := EnableSyncTarget(ctx, remote, enableTestPassword); err != nil {
		t.Fatalf("EnableSyncTarget() error = %v", err)
	}

	// Second enable with the same password succeeds without re-creating.
	if err := EnableSyncTarget(ctx, remote, enableTestPassword); err != nil {
		t.Fatalf("EnableSyncTarget() second run error = %v", err)
	}
}

func TestEnableSyncTargetRejectsWrongPasswordWhenInitialized(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	remote := newTempBackend(t)
	if err := EnableSyncTarget(ctx, remote, enableTestPassword); err != nil {
		t.Fatalf("EnableSyncTarget() error = %v", err)
	}

	err := EnableSyncTarget(ctx, remote, "wrong-password")
	if err == nil {
		t.Fatal("EnableSyncTarget(wrong password) error = nil, want failure")
	}
	if !strings.Contains(err.Error(), "already initialized but failed to unlock") {
		t.Fatalf("error = %v, want already-initialized unlock failure", err)
	}
}

func TestEnsureSyncTargetEnabled(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	remote := newTempBackend(t)

	// Not initialized yet => helpful error naming the command to run.
	err := EnsureSyncTargetEnabled(ctx, remote, enableTestPassword)
	if err == nil || !strings.Contains(err.Error(), "vault sync enable") {
		t.Fatalf("EnsureSyncTargetEnabled(uninitialized) error = %v, want hint to run sync enable", err)
	}

	if err := EnableSyncTarget(ctx, remote, enableTestPassword); err != nil {
		t.Fatalf("EnableSyncTarget() error = %v", err)
	}

	// Initialized + correct password => nil.
	if err := EnsureSyncTargetEnabled(ctx, remote, enableTestPassword); err != nil {
		t.Fatalf("EnsureSyncTargetEnabled() error = %v, want nil", err)
	}

	// Initialized + wrong password => unlock failure surfaced.
	err = EnsureSyncTargetEnabled(ctx, remote, "wrong-password")
	if err == nil || !strings.Contains(err.Error(), "failed to unlock sync target vault") {
		t.Fatalf("EnsureSyncTargetEnabled(wrong password) error = %v, want unlock failure", err)
	}
}

func TestConfirmApplyPlanEmptyPlanNeedsNoPrompt(t *testing.T) {
	t.Parallel()

	// Only the empty-plan branch is safe to test non-interactively: any other
	// branch opens /dev/tty for a keypress, which would hang in CI.
	if err := ConfirmApplyPlan(syncengine.Plan{}); err != nil {
		t.Fatalf("ConfirmApplyPlan(empty) error = %v, want nil (no prompt)", err)
	}
}
