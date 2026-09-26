package postgres

// Stage B6: engine × Postgres end-to-end.
//
// The sync engine runs with a SQLite primary and the live Postgres sync
// target — the exact pairing `vault sync run` uses in production. The
// sqlite×sqlite matrix lives in internal/sync/engine/engine_test.go; this
// file covers what only appears across real backends: timestamp semantics
// between `timestamp without time zone` and SQLite's offset-preserving
// storage, BYTEA round trips, and tombstone propagation through both dialects.
//
// Tests share one database: never call t.Parallel.

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vault/internal/crypto"
	"vault/internal/domain"
	"vault/internal/storage"
	"vault/internal/storage/sqlite"
	"vault/internal/sync/engine"
)

// engineEnv is a fresh SQLite primary paired with a reset Postgres target.
type engineEnv struct {
	local  storage.Backend // primary (sqlite)
	remote *Backend        // sync target (postgres)
}

func newEngineEnv(t *testing.T) *engineEnv {
	t.Helper()
	ctx := context.Background()

	cfg := &storage.Config{Type: "sqlite", Path: filepath.Join(t.TempDir(), "vault.db")}
	l, err := sqlite.New(cfg)
	if err != nil {
		t.Skipf("sqlite unavailable (requires cgo): %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	if err := l.Initialize(ctx, cfg); err != nil {
		msg := err.Error()
		if strings.Contains(msg, "requires cgo") ||
			strings.Contains(msg, "fts5") ||
			strings.Contains(msg, "no such module") {
			t.Skipf("sqlite unavailable (run with -tags sqlite_fts5): %v", err)
		}
		t.Fatalf("sqlite Initialize() error = %v", err)
	}
	if err := l.CreateVault(ctx, testPassword); err != nil {
		t.Fatalf("sqlite CreateVault() error = %v", err)
	}
	if _, err := l.UnlockVault(ctx, testPassword); err != nil {
		t.Fatalf("sqlite UnlockVault() error = %v", err)
	}

	return &engineEnv{local: l, remote: newUnlockedBackend(t)}
}

// engineSeed creates project+secret on any backend with a pinned UpdatedAt.
func engineSeed(t *testing.T, b storage.Backend, project, env, key, value string, updatedAt time.Time) {
	t.Helper()

	proj, err := b.GetProjectByName(context.Background(), project)
	if err != nil {
		proj, err = domain.NewProject(project, "", "test")
		if err != nil {
			t.Fatalf("NewProject(%q) error = %v", project, err)
		}
		if err := b.CreateProject(context.Background(), proj); err != nil {
			t.Fatalf("CreateProject(%q) error = %v", project, err)
		}
		proj, err = b.GetProjectByName(context.Background(), project)
		if err != nil {
			t.Fatalf("GetProjectByName(%q) error = %v", project, err)
		}
	}

	secret, err := domain.NewSecret(proj.ID, env, key, value, domain.SecretTypeGeneric, "test")
	if err != nil {
		t.Fatalf("NewSecret(%s/%s/%s) error = %v", project, env, key, err)
	}
	secret.UpdatedBy = "test"
	secret.Checksum = crypto.Hash([]byte(value))
	secret.UpdatedAt = updatedAt

	if err := b.CreateSecret(context.Background(), secret); err != nil {
		t.Fatalf("CreateSecret(%s/%s/%s) error = %v", project, env, key, err)
	}
}

// engineEdit simulates a user edit on either side (new value, new UpdatedAt,
// recalculated checksum); UpdateSecret bumps the version.
func engineEdit(t *testing.T, b storage.Backend, project, env, key, value string, updatedAt time.Time) {
	t.Helper()
	ctx := context.Background()

	proj, err := b.GetProjectByName(ctx, project)
	if err != nil {
		t.Fatalf("GetProjectByName(%q) error = %v", project, err)
	}
	secret, err := b.GetSecret(ctx, proj.ID, env, key)
	if err != nil {
		t.Fatalf("GetSecret(%s/%s/%s) error = %v", project, env, key, err)
	}

	secret.Value = value
	secret.Checksum = crypto.Hash([]byte(value))
	secret.UpdatedAt = updatedAt
	secret.UpdatedBy = "test"

	if err := b.UpdateSecret(ctx, secret); err != nil {
		t.Fatalf("UpdateSecret(%s/%s/%s) error = %v", project, env, key, err)
	}
}

// engineGet reads a secret by identity from any backend; the test fails when
// it is absent.
func engineGet(t *testing.T, b storage.Backend, project, env, key string) *domain.Secret {
	t.Helper()
	ctx := context.Background()

	proj, err := b.GetProjectByName(ctx, project)
	if err != nil {
		t.Fatalf("GetProjectByName(%q) error = %v", project, err)
	}
	secret, err := b.GetSecret(ctx, proj.ID, env, key)
	if err != nil {
		t.Fatalf("GetSecret(%s/%s/%s) error = %v", project, env, key, err)
	}
	return secret
}

// engineGetErr is the non-fatal variant used to assert absence.
func engineGetErr(t *testing.T, b storage.Backend, project, env, key string) error {
	t.Helper()
	ctx := context.Background()

	proj, err := b.GetProjectByName(ctx, project)
	if err != nil {
		return err
	}
	_, err = b.GetSecret(ctx, proj.ID, env, key)
	return err
}

func mustSync(t *testing.T, e *engineEnv, opts engine.Options, dryRun bool) engine.Result {
	t.Helper()
	res, err := engine.New(e.local, e.remote, opts).Sync(context.Background(), dryRun)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	return res
}

func mustPlan(t *testing.T, e *engineEnv, opts engine.Options) engine.Plan {
	t.Helper()
	plan, err := engine.New(e.local, e.remote, opts).SyncPlan(context.Background())
	if err != nil {
		t.Fatalf("SyncPlan() error = %v", err)
	}
	return plan
}

func fixedClockAt(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

var (
	t1 = time.Date(2026, 3, 1, 1, 0, 0, 0, time.UTC)  // secret edit
	t2 = time.Date(2026, 3, 1, 3, 0, 0, 0, time.UTC)  // baseline sync
	t3 = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC) // later sync
)

func TestEnginePushRoundTripAndConvergence(t *testing.T) {
	e := newEngineEnv(t)
	opts := engine.Options{Direction: engine.DirectionPush, Clock: fixedClockAt(t2)}

	engineSeed(t, e.local, "myapp", "development", "API_KEY", "local-value", t1)

	res := mustSync(t, e, opts, false)
	if !res.Applied || res.OperationsApplied != 1 {
		t.Fatalf("first sync: applied=%v ops=%d, want true/1", res.Applied, res.OperationsApplied)
	}

	// Remote must hold the same plaintext through the BYTEA round trip.
	remote := engineGet(t, e.remote, "myapp", "development", "API_KEY")
	if remote.Value != "local-value" {
		t.Errorf("remote value = %q, want local-value", remote.Value)
	}
	if remote.SyncStatus != domain.SyncStatusInSync || remote.LastSyncedAt == nil ||
		!remote.LastSyncedAt.Equal(t2) {
		t.Errorf("remote sync bookkeeping = %v / %v, want in_sync @ %v",
			remote.SyncStatus, remote.LastSyncedAt, t2)
	}

	// Both sides must record the same sync instant so the next run sees no
	// changes — the convergence property that timestamp skew would break.
	local := engineGet(t, e.local, "myapp", "development", "API_KEY")
	if local.LastSyncedAt == nil || !local.LastSyncedAt.Equal(t2) {
		t.Errorf("local LastSyncedAt = %v, want %v", local.LastSyncedAt, t2)
	}

	plan := mustPlan(t, e, opts)
	if len(plan.Push) != 0 || len(plan.Pull) != 0 || len(plan.Conflicts) != 0 || plan.Detected != 0 {
		t.Errorf("second plan = push %d, pull %d, conflicts %d (detected %d), want all zero",
			len(plan.Push), len(plan.Pull), len(plan.Conflicts), plan.Detected)
	}
}

func TestEnginePullNewPropagatesToLocal(t *testing.T) {
	e := newEngineEnv(t)
	opts := engine.Options{Direction: engine.DirectionPull, Clock: fixedClockAt(t2)}

	engineSeed(t, e.remote, "webapp", "staging", "DATABASE_URL", "postgres://remote", t1)

	res := mustSync(t, e, opts, false)
	if res.OperationsApplied != 1 {
		t.Fatalf("pull ops = %d, want 1", res.OperationsApplied)
	}

	local := engineGet(t, e.local, "webapp", "staging", "DATABASE_URL")
	if local.Value != "postgres://remote" {
		t.Errorf("local value = %q, want postgres://remote", local.Value)
	}

	plan := mustPlan(t, e, opts)
	if len(plan.Push)+len(plan.Pull)+len(plan.Conflicts) != 0 {
		t.Errorf("second plan not empty: push %d pull %d conflicts %d",
			len(plan.Push), len(plan.Pull), len(plan.Conflicts))
	}
}

func TestEngineConflictFailThenPreferRemote(t *testing.T) {
	e := newEngineEnv(t)

	// Baseline: both sides hold API_KEY and were synced at t2.
	engineSeed(t, e.local, "myapp", "development", "API_KEY", "base", t1)
	mustSync(t, e, engine.Options{Direction: engine.DirectionPush, Clock: fixedClockAt(t2)}, false)

	// Divergent edits on both sides, both later than the sync point.
	engineEdit(t, e.local, "myapp", "development", "API_KEY", "local-edit", time.Date(2026, 3, 1, 4, 0, 0, 0, time.UTC))
	engineEdit(t, e.remote, "myapp", "development", "API_KEY", "remote-edit", time.Date(2026, 3, 1, 5, 0, 0, 0, time.UTC))

	// Default strategy must refuse to pick a winner.
	failOpts := engine.Options{Direction: engine.DirectionBoth, Strategy: engine.ConflictFail, Clock: fixedClockAt(t3)}
	if _, err := engine.New(e.local, e.remote, failOpts).Sync(context.Background(), false); err == nil {
		t.Fatal("Sync(fail) succeeded on a genuine conflict, want error")
	}
	// Nothing must have been applied by the failed run.
	if got := engineGet(t, e.local, "myapp", "development", "API_KEY"); got.Value != "local-edit" {
		t.Errorf("local value after failed sync = %q, want local-edit", got.Value)
	}

	// prefer-remote resolves the conflict in favour of the remote value.
	preferRemote := engine.Options{Direction: engine.DirectionBoth, Strategy: engine.ConflictPreferRemote, Clock: fixedClockAt(t3)}
	res := mustSync(t, e, preferRemote, false)
	if res.ConflictsDetected != 1 {
		t.Errorf("ConflictsDetected = %d, want 1", res.ConflictsDetected)
	}
	if got := engineGet(t, e.local, "myapp", "development", "API_KEY"); got.Value != "remote-edit" {
		t.Errorf("local value after prefer-remote = %q, want remote-edit", got.Value)
	}

	plan := mustPlan(t, e, preferRemote)
	if len(plan.Push)+len(plan.Pull)+len(plan.Conflicts) != 0 {
		t.Errorf("post-resolution plan not empty: push %d pull %d conflicts %d",
			len(plan.Push), len(plan.Pull), len(plan.Conflicts))
	}
}

func TestEngineLocalTombstoneNeverResurrectsAndDeleteRemotePropagates(t *testing.T) {
	e := newEngineEnv(t)

	engineSeed(t, e.local, "myapp", "development", "TEMP_KEY", "v", t1)
	mustSync(t, e, engine.Options{Direction: engine.DirectionPush, Clock: fixedClockAt(t2)}, false)

	// Delete on the primary; the storage layer records a tombstone.
	if err := e.local.DeleteSecret(context.Background(), secretID(t, e.local, "myapp", "development", "TEMP_KEY")); err != nil {
		t.Fatalf("DeleteSecret(local) error = %v", err)
	}

	// Pull must NOT resurrect the locally deleted secret (tombstone wins even
	// though the remote copy still exists).
	pullOpts := engine.Options{Direction: engine.DirectionPull, Clock: fixedClockAt(t3)}
	mustSync(t, e, pullOpts, false)
	if err := engineGetErr(t, e.local, "myapp", "development", "TEMP_KEY"); err == nil {
		t.Fatal("local secret resurrected by pull despite tombstone")
	}

	// Without the opt-in flag the surviving remote copy must not be removed.
	pushOpts := engine.Options{Direction: engine.DirectionPush, Clock: fixedClockAt(t3)}
	mustSync(t, e, pushOpts, false)
	if err := engineGetErr(t, e.remote, "myapp", "development", "TEMP_KEY"); err != nil {
		t.Errorf("remote copy removed without DeleteRemoteMissing: %v", err)
	}

	// With the flag the deletion propagates.
	flagged := engine.Options{Direction: engine.DirectionPush, DeleteRemoteMissing: true, Clock: fixedClockAt(t3)}
	res := mustSync(t, e, flagged, false)
	if res.OperationsApplied != 1 {
		t.Errorf("delete-remote ops = %d, want 1", res.OperationsApplied)
	}
	if err := engineGetErr(t, e.remote, "myapp", "development", "TEMP_KEY"); err == nil {
		t.Fatal("remote secret still present after DeleteRemoteMissing sync")
	}
}

func TestEngineRemoteTombstonePropagatesToLocalBehindFlag(t *testing.T) {
	e := newEngineEnv(t)

	engineSeed(t, e.local, "myapp", "development", "API_KEY", "v", t1)
	mustSync(t, e, engine.Options{Direction: engine.DirectionPush, Clock: fixedClockAt(t2)}, false)

	// Delete on the remote (records a Postgres tombstone).
	remoteID := secretID(t, e.remote, "myapp", "development", "API_KEY")
	if err := e.remote.DeleteSecret(context.Background(), remoteID); err != nil {
		t.Fatalf("DeleteSecret(remote) error = %v", err)
	}

	// Without the flag the local copy survives.
	pullOpts := engine.Options{Direction: engine.DirectionPull, Clock: fixedClockAt(t3)}
	mustSync(t, e, pullOpts, false)
	if err := engineGetErr(t, e.local, "myapp", "development", "API_KEY"); err != nil {
		t.Errorf("local copy removed without DeleteLocalMissing: %v", err)
	}

	// With the flag the deletion propagates locally.
	flagged := engine.Options{Direction: engine.DirectionPull, DeleteLocalMissing: true, Clock: fixedClockAt(t3)}
	res := mustSync(t, e, flagged, false)
	if res.OperationsApplied != 1 {
		t.Errorf("delete-local ops = %d, want 1", res.OperationsApplied)
	}
	if err := engineGetErr(t, e.local, "myapp", "development", "API_KEY"); err == nil {
		t.Fatal("local secret still present after DeleteLocalMissing sync")
	}

	// The remote must stay deleted: a push without flags must not resurrect it.
	mustSync(t, e, engine.Options{Direction: engine.DirectionPush, Clock: fixedClockAt(t3)}, false)
	if err := engineGetErr(t, e.remote, "myapp", "development", "API_KEY"); err == nil {
		t.Fatal("remote secret resurrected by push despite tombstone")
	}
}

// TestEnginePreferLatestAcrossNonUTCZones is the cross-backend timestamp
// regression: prefer-latest compares SQLite-side and Postgres-side UpdatedAt
// instants. Postgres columns drop the zone offset on write, so an edit made in
// a non-UTC zone (this machine runs IST) used to come back shifted by the
// writer's offset and win every recency comparison it should have lost.
func TestEnginePreferLatestAcrossNonUTCZones(t *testing.T) {
	e := newEngineEnv(t)
	ist := time.FixedZone("IST", 5*3600+1800)

	// Baseline at 03:00 UTC.
	engineSeed(t, e.local, "myapp", "development", "API_KEY", "base", t1)
	mustSync(t, e, engine.Options{Direction: engine.DirectionPush, Clock: fixedClockAt(t2)}, false)

	// Local edit: 08:00 UTC.
	localEdit := time.Date(2026, 3, 1, 8, 0, 0, 0, time.UTC)
	engineEdit(t, e.local, "myapp", "development", "API_KEY", "local-newer", localEdit)

	// Remote edit: 10:00 IST == 04:30 UTC — an hour EARLIER than the local
	// edit. Stored correctly it must lose; shifted by +05:30 it would read as
	// 10:00 UTC and wrongly win.
	remoteEdit := time.Date(2026, 3, 1, 10, 0, 0, 0, ist)
	engineEdit(t, e.remote, "myapp", "development", "API_KEY", "remote-older", remoteEdit)

	opts := engine.Options{Direction: engine.DirectionBoth, Strategy: engine.ConflictPreferLatest, Clock: fixedClockAt(t3)}
	res := mustSync(t, e, opts, false)
	if res.ConflictsDetected != 1 {
		t.Fatalf("ConflictsDetected = %d, want 1", res.ConflictsDetected)
	}

	if got := engineGet(t, e.remote, "myapp", "development", "API_KEY"); got.Value != "local-newer" {
		t.Errorf("prefer-latest picked the wrong side: remote value = %q, want local-newer "+
			"(08:00 UTC must beat 10:00 IST = 04:30 UTC)", got.Value)
	}
	if got := engineGet(t, e.local, "myapp", "development", "API_KEY"); got.Value != "local-newer" {
		t.Errorf("local value = %q, want local-newer", got.Value)
	}
}

// secretID resolves a secret's storage ID by identity; used for direct
// DeleteSecret calls that mirror a user-issued deletion.
func secretID(t *testing.T, b storage.Backend, project, env, key string) string {
	t.Helper()
	proj, err := b.GetProjectByName(context.Background(), project)
	if err != nil {
		t.Fatalf("GetProjectByName(%q) error = %v", project, err)
	}
	secret, err := b.GetSecret(context.Background(), proj.ID, env, key)
	if err != nil {
		t.Fatalf("GetSecret(%s/%s/%s) error = %v", project, env, key, err)
	}
	return secret.ID
}
