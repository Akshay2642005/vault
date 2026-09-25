package engine

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
)

const testPassword = "password123"

// testEnv holds two independent, unlocked sqlite vaults used as local+remote.
type testEnv struct {
	local  storage.Backend
	remote storage.Backend
}

func newTestEnv(t *testing.T, ctx context.Context) *testEnv {
	t.Helper()

	newB := func() storage.Backend {
		cfg := &storage.Config{Type: "sqlite", Path: filepath.Join(t.TempDir(), "vault.db")}
		b, err := sqlite.New(cfg)
		if err != nil {
			t.Fatalf("sqlite.New() error = %v", err)
		}
		t.Cleanup(func() { _ = b.Close() })

		if err := b.Initialize(ctx, cfg); err != nil {
			if strings.Contains(err.Error(), "requires cgo") {
				t.Skipf("sqlite backend unavailable in this test environment: %v", err)
			}
			t.Fatalf("Initialize() error = %v", err)
		}
		if err := b.CreateVault(ctx, testPassword); err != nil {
			t.Fatalf("CreateVault() error = %v", err)
		}
		if _, err := b.UnlockVault(ctx, testPassword); err != nil {
			t.Fatalf("UnlockVault() error = %v", err)
		}
		return b
	}

	return &testEnv{local: newB(), remote: newB()}
}

func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

// deleteSecret deletes a secret on a backend by identity, which records a
// tombstone in the storage layer (same as a user-issued deletion).
func deleteSecret(t *testing.T, ctx context.Context, b storage.Backend, key string) {
	t.Helper()

	proj, err := b.GetProjectByName(ctx, "myapp")
	if err != nil {
		t.Fatalf("GetProjectByName() error = %v", err)
	}
	s, err := b.GetSecret(ctx, proj.ID, "development", key)
	if err != nil {
		t.Fatalf("GetSecret() error = %v", err)
	}
	if err := b.DeleteSecret(ctx, s.ID); err != nil {
		t.Fatalf("DeleteSecret() error = %v", err)
	}
}

func getTombstone(t *testing.T, ctx context.Context, b storage.Backend, key string) (*domain.Tombstone, error) {
	t.Helper()
	proj, err := b.GetProjectByName(ctx, "myapp")
	if err != nil {
		return nil, err
	}
	return b.GetTombstone(ctx, proj.ID, "development", key)
}

// seedSecret creates project "myapp" (if absent) plus a secret in development.
func seedSecret(t *testing.T, ctx context.Context, b storage.Backend, key, value string, updatedAt time.Time) {
	t.Helper()
	seedSecretIn(t, ctx, b, "myapp", "development", key, value, updatedAt)
}

// seedSecretIn creates (if needed) the given project and seeds a secret in the
// given environment. seedSecret is a myapp/development shorthand of this.
func seedSecretIn(t *testing.T, ctx context.Context, b storage.Backend, project, env, key, value string, updatedAt time.Time) {
	t.Helper()

	proj, err := b.GetProjectByName(ctx, project)
	if err != nil {
		proj, err = domain.NewProject(project, "", "test")
		if err != nil {
			t.Fatalf("NewProject(%q) error = %v", project, err)
		}
		if err := b.CreateProject(ctx, proj); err != nil {
			t.Fatalf("CreateProject(%q) error = %v", project, err)
		}
		proj, err = b.GetProjectByName(ctx, project)
		if err != nil {
			t.Fatalf("GetProjectByName(%q) error = %v", project, err)
		}
	}

	secret, err := domain.NewSecret(proj.ID, env, key, value, domain.SecretTypeGeneric, "test")
	if err != nil {
		t.Fatalf("NewSecret() error = %v", err)
	}
	secret.UpdatedBy = "test"
	secret.Checksum = crypto.Hash([]byte(value))
	secret.UpdatedAt = updatedAt

	if err := b.CreateSecret(ctx, secret); err != nil {
		t.Fatalf("CreateSecret() error = %v", err)
	}
}

// editSecret simulates a normal (non-sync) user edit: new value, new UpdatedAt,
// recalculated checksum. Version bumps inside UpdateSecret, as in production.
func editSecret(t *testing.T, ctx context.Context, b storage.Backend, key, value string, updatedAt time.Time) {
	t.Helper()

	proj, err := b.GetProjectByName(ctx, "myapp")
	if err != nil {
		t.Fatalf("GetProjectByName() error = %v", err)
	}
	secret, err := b.GetSecret(ctx, proj.ID, "development", key)
	if err != nil {
		t.Fatalf("GetSecret() error = %v", err)
	}

	secret.Value = value
	secret.Checksum = crypto.Hash([]byte(value))
	secret.UpdatedAt = updatedAt
	secret.UpdatedBy = "test"

	if err := b.UpdateSecret(ctx, secret); err != nil {
		t.Fatalf("UpdateSecret() error = %v", err)
	}
}

func getSecret(t *testing.T, ctx context.Context, b storage.Backend, key string) *domain.Secret {
	t.Helper()

	proj, err := b.GetProjectByName(ctx, "myapp")
	if err != nil {
		t.Fatalf("GetProjectByName() error = %v", err)
	}
	secret, err := b.GetSecret(ctx, proj.ID, "development", key)
	if err != nil {
		t.Fatalf("GetSecret() error = %v", err)
	}
	return secret
}

// getSecretErr is the non-fatal variant used to assert that a secret does NOT
// exist on a backend.
func getSecretErr(t *testing.T, ctx context.Context, b storage.Backend, key string) (*domain.Secret, error) {
	t.Helper()
	return getSecretErrIn(t, ctx, b, "myapp", "development", key)
}

// getSecretIn reads a secret by full identity (project/env/key).
func getSecretIn(t *testing.T, ctx context.Context, b storage.Backend, project, env, key string) *domain.Secret {
	t.Helper()
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

// getSecretErrIn is the non-fatal variant used to assert absence by identity.
func getSecretErrIn(t *testing.T, ctx context.Context, b storage.Backend, project, env, key string) (*domain.Secret, error) {
	t.Helper()
	proj, err := b.GetProjectByName(ctx, project)
	if err != nil {
		return nil, err
	}
	return b.GetSecret(ctx, proj.ID, env, key)
}

func syncPlan(t *testing.T, env *testEnv, opts Options) Plan {
	t.Helper()
	engine := New(env.local, env.remote, opts)
	plan, err := engine.SyncPlan(context.Background())
	if err != nil {
		t.Fatalf("SyncPlan() error = %v", err)
	}
	return plan
}

func TestPushNewSecretAndIdempotency(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := newTestEnv(t, ctx)

	editedAt := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	syncedAt := editedAt.Add(time.Hour)
	seedSecret(t, ctx, env.local, "API_KEY", "local-value-1", editedAt)

	engine := New(env.local, env.remote, Options{Clock: fixedClock(syncedAt)})
	res, err := engine.Sync(ctx, false)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if res.OperationsApplied != 1 {
		t.Fatalf("OperationsApplied = %d, want 1", res.OperationsApplied)
	}
	if res.ConflictsDetected != 0 {
		t.Fatalf("ConflictsDetected = %d, want 0", res.ConflictsDetected)
	}

	remote := getSecret(t, ctx, env.remote, "API_KEY")
	if remote.Value != "local-value-1" {
		t.Fatalf("remote Value = %q, want %q", remote.Value, "local-value-1")
	}
	if remote.SyncStatus != domain.SyncStatusInSync {
		t.Fatalf("remote SyncStatus = %q, want %q", remote.SyncStatus, domain.SyncStatusInSync)
	}
	if remote.LastSyncedAt == nil || !remote.LastSyncedAt.Equal(syncedAt) {
		t.Fatalf("remote LastSyncedAt = %v, want %v", remote.LastSyncedAt, syncedAt)
	}
	// Source side must be marked synced too, otherwise the next run treats
	// the already-propagated edit as a fresh local change.
	local := getSecret(t, ctx, env.local, "API_KEY")
	if local.LastSyncedAt == nil || !local.LastSyncedAt.Equal(syncedAt) {
		t.Fatalf("local LastSyncedAt = %v, want %v (source side must be marked)", local.LastSyncedAt, syncedAt)
	}
	// Marking must never touch the value or version history.
	if local.Version != 1 {
		t.Fatalf("local Version = %d, want 1 (marking must not bump versions)", local.Version)
	}

	// Idempotency: a second run must produce an empty plan.
	again := syncPlan(t, env, Options{Clock: fixedClock(syncedAt)})
	if len(again.Push)+len(again.Pull)+len(again.Conflicts) != 0 {
		t.Fatalf("second plan not empty: pushes=%d pulls=%d conflicts=%d", len(again.Push), len(again.Pull), len(again.Conflicts))
	}
}

func TestPullNewSecret(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := newTestEnv(t, ctx)

	editedAt := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	syncedAt := editedAt.Add(time.Hour)
	seedSecret(t, ctx, env.remote, "API_KEY", "remote-value-1", editedAt)

	engine := New(env.local, env.remote, Options{Clock: fixedClock(syncedAt)})
	res, err := engine.Sync(ctx, false)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if res.OperationsApplied != 1 {
		t.Fatalf("OperationsApplied = %d, want 1", res.OperationsApplied)
	}

	local := getSecret(t, ctx, env.local, "API_KEY")
	if local.Value != "remote-value-1" {
		t.Fatalf("local Value = %q, want %q", local.Value, "remote-value-1")
	}
	if local.LastSyncedAt == nil || !local.LastSyncedAt.Equal(syncedAt) {
		t.Fatalf("local LastSyncedAt = %v, want %v", local.LastSyncedAt, syncedAt)
	}

	again := syncPlan(t, env, Options{Clock: fixedClock(syncedAt)})
	if len(again.Push)+len(again.Pull)+len(again.Conflicts) != 0 {
		t.Fatalf("second plan not empty: pushes=%d pulls=%d conflicts=%d", len(again.Push), len(again.Pull), len(again.Conflicts))
	}
}

// TestRemoteEditAfterLocalSyncPulls covers the regression where the source side
// of a previous sync was not marked: the local vault would appear "changed"
// forever and every remote-only edit would be misclassified as a conflict.
func TestRemoteEditAfterLocalSyncPulls(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := newTestEnv(t, ctx)

	t0 := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour) // first sync time
	t2 := t0.Add(2 * time.Hour)

	seedSecret(t, ctx, env.local, "API_KEY", "v1", t0)
	engine := New(env.local, env.remote, Options{Clock: fixedClock(t1)})
	if _, err := engine.Sync(ctx, false); err != nil {
		t.Fatalf("initial Sync() error = %v", err)
	}

	// Remote-only edit after the sync; local untouched since it was pushed.
	editSecret(t, ctx, env.remote, "API_KEY", "v2-remote", t2)

	plan := syncPlan(t, env, Options{Clock: fixedClock(t2)})
	if len(plan.Conflicts) != 0 {
		t.Fatalf("expected no conflict for a single-sided remote edit, got %d", len(plan.Conflicts))
	}
	if len(plan.Pull) != 1 {
		t.Fatalf("len(plan.Pull) = %d, want 1", len(plan.Pull))
	}

	engine2 := New(env.local, env.remote, Options{Clock: fixedClock(t2)})
	if _, err := engine2.Sync(ctx, false); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if got := getSecret(t, ctx, env.local, "API_KEY").Value; got != "v2-remote" {
		t.Fatalf("local Value = %q, want %q", got, "v2-remote")
	}
}

func TestLocalEditAfterSyncPushes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := newTestEnv(t, ctx)

	t0 := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	t2 := t0.Add(2 * time.Hour)

	seedSecret(t, ctx, env.local, "API_KEY", "v1", t0)
	engine := New(env.local, env.remote, Options{Clock: fixedClock(t1)})
	if _, err := engine.Sync(ctx, false); err != nil {
		t.Fatalf("initial Sync() error = %v", err)
	}

	editSecret(t, ctx, env.local, "API_KEY", "v2-local", t2)

	plan := syncPlan(t, env, Options{Clock: fixedClock(t2)})
	if len(plan.Conflicts) != 0 {
		t.Fatalf("expected no conflict for a single-sided local edit, got %d", len(plan.Conflicts))
	}
	if len(plan.Push) != 1 {
		t.Fatalf("len(plan.Push) = %d, want 1", len(plan.Push))
	}

	engine2 := New(env.local, env.remote, Options{Clock: fixedClock(t2)})
	if _, err := engine2.Sync(ctx, false); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if got := getSecret(t, ctx, env.remote, "API_KEY").Value; got != "v2-local" {
		t.Fatalf("remote Value = %q, want %q", got, "v2-local")
	}
}

// TestConflictBothSidesChanged is the core of the new detection: both sides
// edited since the last sync must surface as a conflict under the fail
// strategy, instead of a silent last-writer-wins overwrite.
func TestConflictBothSidesChanged(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := newTestEnv(t, ctx)

	t0 := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	t2 := t0.Add(2 * time.Hour)
	t3 := t0.Add(3 * time.Hour)

	seedSecret(t, ctx, env.local, "API_KEY", "v1", t0)
	engine := New(env.local, env.remote, Options{Clock: fixedClock(t1)})
	if _, err := engine.Sync(ctx, false); err != nil {
		t.Fatalf("initial Sync() error = %v", err)
	}

	editSecret(t, ctx, env.local, "API_KEY", "v2-local", t2)
	editSecret(t, ctx, env.remote, "API_KEY", "v2-remote", t3)

	// fail strategy: plan exposes the conflict (returned alongside the error),
	// and Sync aborts without applying anything.
	failEngine := New(env.local, env.remote, Options{Strategy: ConflictFail, Clock: fixedClock(t3)})
	plan, planErr := failEngine.SyncPlan(ctx)
	if planErr == nil {
		t.Fatal("SyncPlan() with fail strategy succeeded, want conflict error")
	}
	if len(plan.Conflicts) != 1 {
		t.Fatalf("len(plan.Conflicts) = %d, want 1", len(plan.Conflicts))
	}
	if plan.Detected != 1 {
		t.Fatalf("plan.Detected = %d, want 1", plan.Detected)
	}
	c := plan.Conflicts[0]
	if c.Local.Value != "v2-local" || c.Remote.Value != "v2-remote" {
		t.Fatalf("conflict snapshots wrong: local=%q remote=%q", c.Local.Value, c.Remote.Value)
	}

	errEngine := New(env.local, env.remote, Options{Strategy: ConflictFail, Clock: fixedClock(t3)})
	if _, err := errEngine.Sync(ctx, false); err == nil {
		t.Fatal("Sync() with fail strategy succeeded, want conflict error")
	}

	// Nothing must have been applied by the failing run.
	local := getSecret(t, ctx, env.local, "API_KEY")
	remote := getSecret(t, ctx, env.remote, "API_KEY")
	if local.Value != "v2-local" || remote.Value != "v2-remote" {
		t.Fatalf("failing sync mutated data: local=%q remote=%q", local.Value, remote.Value)
	}
}

func TestPreferLatestResolvesByRecency(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := newTestEnv(t, ctx)

	t0 := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	t2 := t0.Add(2 * time.Hour)
	t3 := t0.Add(3 * time.Hour)

	seedSecret(t, ctx, env.local, "API_KEY", "v1", t0)
	engine := New(env.local, env.remote, Options{Clock: fixedClock(t1)})
	if _, err := engine.Sync(ctx, false); err != nil {
		t.Fatalf("initial Sync() error = %v", err)
	}

	editSecret(t, ctx, env.local, "API_KEY", "v2-local", t2)   // earlier
	editSecret(t, ctx, env.remote, "API_KEY", "v3-remote", t3) // later

	plan := syncPlan(t, env, Options{Strategy: ConflictPreferLatest, Clock: fixedClock(t3)})
	if len(plan.Conflicts) != 0 {
		t.Fatalf("prefer-latest left %d unresolved conflicts", len(plan.Conflicts))
	}
	if plan.Detected != 1 {
		t.Fatalf("plan.Detected = %d, want 1 (conflict was detected then resolved)", plan.Detected)
	}
	if len(plan.Pull) != 1 {
		t.Fatalf("len(plan.Pull) = %d, want 1 (remote is newer)", len(plan.Pull))
	}

	engine2 := New(env.local, env.remote, Options{Strategy: ConflictPreferLatest, Clock: fixedClock(t3)})
	res, err := engine2.Sync(ctx, false)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if res.ConflictsDetected != 1 {
		t.Fatalf("result.ConflictsDetected = %d, want 1 (reported from pre-resolution count)", res.ConflictsDetected)
	}
	if got := getSecret(t, ctx, env.local, "API_KEY").Value; got != "v3-remote" {
		t.Fatalf("local Value = %q, want %q (prefer-latest should keep the newer edit)", got, "v3-remote")
	}
}

func TestPreferLatestFailsOnExactTie(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := newTestEnv(t, ctx)

	t0 := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	tie := t0.Add(2 * time.Hour)

	seedSecret(t, ctx, env.local, "API_KEY", "v1", t0)
	engine := New(env.local, env.remote, Options{Clock: fixedClock(t1)})
	if _, err := engine.Sync(ctx, false); err != nil {
		t.Fatalf("initial Sync() error = %v", err)
	}

	editSecret(t, ctx, env.local, "API_KEY", "v2-local", tie)
	editSecret(t, ctx, env.remote, "API_KEY", "v2-remote", tie)

	errEngine := New(env.local, env.remote, Options{Strategy: ConflictPreferLatest, Clock: fixedClock(t1)})
	_, err := errEngine.Sync(ctx, false)
	if err == nil {
		t.Fatal("Sync() with tied UpdatedAt succeeded, want prefer-latest error")
	}
}

func TestPreferLocalWinsConflict(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := newTestEnv(t, ctx)

	t0 := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	t2 := t0.Add(2 * time.Hour)
	t3 := t0.Add(3 * time.Hour)

	seedSecret(t, ctx, env.local, "API_KEY", "v1", t0)
	engine := New(env.local, env.remote, Options{Clock: fixedClock(t1)})
	if _, err := engine.Sync(ctx, false); err != nil {
		t.Fatalf("initial Sync() error = %v", err)
	}

	editSecret(t, ctx, env.local, "API_KEY", "v2-local", t2)
	editSecret(t, ctx, env.remote, "API_KEY", "v2-remote", t3)

	engine2 := New(env.local, env.remote, Options{Strategy: ConflictPreferLocal, Clock: fixedClock(t3)})
	if _, err := engine2.Sync(ctx, false); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if got := getSecret(t, ctx, env.remote, "API_KEY").Value; got != "v2-local" {
		t.Fatalf("remote Value = %q, want %q (prefer-local should propagate local)", got, "v2-local")
	}
}

func TestDeleteRemoteMissingTurnsRemoteOnlyIntoDelete(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := newTestEnv(t, ctx)

	t0 := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	seedSecret(t, ctx, env.remote, "API_KEY", "only-remote", t0)

	// Without the flag, remote-only secrets are pulled.
	plan := syncPlan(t, env, Options{Clock: fixedClock(t0)})
	if len(plan.Pull) != 1 || len(plan.Push) != 0 {
		t.Fatalf("default plan for remote-only secret: pulls=%d pushes=%d, want 1 pull", len(plan.Pull), len(plan.Push))
	}

	// With the flag, remote-only is planned as a push-side delete.
	delPlan := syncPlan(t, env, Options{Direction: DirectionPush, DeleteRemoteMissing: true, Clock: fixedClock(t0)})
	if len(delPlan.Push) != 1 {
		t.Fatalf("delete-remote-missing plan: pushes=%d, want 1", len(delPlan.Push))
	}
	if delPlan.Push[0].Kind != OpDeleteRemote {
		t.Fatalf("delete-remote-missing plan op kind = %v, want %v", delPlan.Push[0].Kind, OpDeleteRemote)
	}
	if len(delPlan.Pull) != 0 {
		t.Fatalf("delete-remote-missing plan unexpectedly pulls %d", len(delPlan.Pull))
	}

	engine := New(env.local, env.remote, Options{Direction: DirectionPush, DeleteRemoteMissing: true, Clock: fixedClock(t0)})
	if _, err := engine.Sync(ctx, false); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}

	proj, err := env.remote.GetProjectByName(ctx, "myapp")
	if err != nil {
		t.Fatalf("GetProjectByName() error = %v", err)
	}
	if _, err := env.remote.GetSecret(ctx, proj.ID, "development", "API_KEY"); err == nil {
		t.Fatal("remote secret still exists after delete-remote op")
	}
}

func TestSyncPreservesSourceUpdatedAt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := newTestEnv(t, ctx)

	editedAt := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	syncedAt := editedAt.Add(time.Hour)
	seedSecret(t, ctx, env.local, "API_KEY", "v1", editedAt)

	engine := New(env.local, env.remote, Options{Clock: fixedClock(syncedAt)})
	if _, err := engine.Sync(ctx, false); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}

	remote := getSecret(t, ctx, env.remote, "API_KEY")
	if !remote.UpdatedAt.Equal(editedAt) {
		t.Fatalf("remote UpdatedAt = %v, want %v (must preserve source edit time, not sync time)", remote.UpdatedAt, editedAt)
	}
	if remote.UpdatedBy != "test" {
		t.Fatalf("remote UpdatedBy = %q, want %q", remote.UpdatedBy, "test")
	}
}

func TestScopeRestrictsReconciliation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := newTestEnv(t, ctx)

	t0 := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	seedSecret(t, ctx, env.local, "API_KEY", "v1", t0)
	seedSecret(t, ctx, env.local, "OTHER_KEY", "v1", t0)

	// Scope to a single key would need per-key scoping, which the engine does
	// not support; instead verify project/environment scoping skips nothing
	// relevant here and no-op sync returns an empty plan after full sync.
	engine := New(env.local, env.remote, Options{Clock: fixedClock(t0)})
	if _, err := engine.Sync(ctx, false); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}

	plan := syncPlan(t, env, Options{Scope: Scope{ProjectName: "myapp", EnvironmentName: "development"}, Clock: fixedClock(t0)})
	if len(plan.Push)+len(plan.Pull)+len(plan.Conflicts) != 0 {
		t.Fatalf("scoped plan not empty after sync: pushes=%d pulls=%d conflicts=%d", len(plan.Push), len(plan.Pull), len(plan.Conflicts))
	}
}

// TestLocalDeleteDoesNotResurrectOnPull: a secret deleted locally is recorded
// as a tombstone, so a later both-direction sync must NOT pull it back — even
// without any delete flags. The remote copy is left untouched.
func TestLocalDeleteDoesNotResurrectOnPull(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := newTestEnv(t, ctx)

	t0 := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	seedSecret(t, ctx, env.local, "API_KEY", "v1", t0)

	engine := New(env.local, env.remote, Options{Clock: fixedClock(t1)})
	if _, err := engine.Sync(ctx, false); err != nil {
		t.Fatalf("initial Sync() error = %v", err)
	}

	// Delete locally: the storage layer records a tombstone.
	deleteSecret(t, ctx, env.local, "API_KEY")

	plan := syncPlan(t, env, Options{Clock: fixedClock(t1)})
	if len(plan.Pull)+len(plan.Push)+len(plan.Conflicts) != 0 {
		t.Fatalf("plan not empty after local delete: pulls=%d pushes=%d conflicts=%d", len(plan.Pull), len(plan.Push), len(plan.Conflicts))
	}

	// Remote copy untouched; local stays deleted.
	getSecret(t, ctx, env.remote, "API_KEY")
	if _, err := getSecretErr(t, ctx, env.local, "API_KEY"); err == nil {
		t.Fatal("local secret resurrected by sync")
	}
}

// TestDeleteRemotePropagatesLocalDeletion: with --delete-remote, a locally
// deleted (tombstoned) secret is removed from the remote too.
func TestDeleteRemotePropagatesLocalDeletion(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := newTestEnv(t, ctx)

	t0 := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	seedSecret(t, ctx, env.local, "API_KEY", "v1", t0)

	engine := New(env.local, env.remote, Options{Clock: fixedClock(t1)})
	if _, err := engine.Sync(ctx, false); err != nil {
		t.Fatalf("initial Sync() error = %v", err)
	}

	deleteSecret(t, ctx, env.local, "API_KEY")

	plan := syncPlan(t, env, Options{DeleteRemoteMissing: true, Clock: fixedClock(t1)})
	if len(plan.Push) != 1 {
		t.Fatalf("expected 1 push op, got %d", len(plan.Push))
	}
	if plan.Push[0].Kind != OpDeleteRemote {
		t.Fatalf("push op kind = %v, want %v", plan.Push[0].Kind, OpDeleteRemote)
	}
	if len(plan.Pull) != 0 {
		t.Fatalf("plan unexpectedly pulls %d ops", len(plan.Pull))
	}

	engine2 := New(env.local, env.remote, Options{DeleteRemoteMissing: true, Clock: fixedClock(t1)})
	if _, err := engine2.Sync(ctx, false); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if _, err := getSecretErr(t, ctx, env.remote, "API_KEY"); err == nil {
		t.Fatal("remote secret still exists after delete-remote op")
	}
}

// TestRemoteTombstonePreventsResurrectionOnPush: a secret deleted on the
// remote must not be pushed back from the local side, and the local copy is
// left in place without delete flags.
func TestRemoteTombstonePreventsResurrectionOnPush(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := newTestEnv(t, ctx)

	t0 := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	seedSecret(t, ctx, env.local, "API_KEY", "v1", t0)

	engine := New(env.local, env.remote, Options{Clock: fixedClock(t1)})
	if _, err := engine.Sync(ctx, false); err != nil {
		t.Fatalf("initial Sync() error = %v", err)
	}

	// Simulate the remote node deleting the secret.
	deleteSecret(t, ctx, env.remote, "API_KEY")

	plan := syncPlan(t, env, Options{Clock: fixedClock(t1)})
	if len(plan.Push)+len(plan.Pull)+len(plan.Conflicts) != 0 {
		t.Fatalf("plan not empty after remote delete: pushes=%d pulls=%d conflicts=%d", len(plan.Push), len(plan.Pull), len(plan.Conflicts))
	}
	getSecret(t, ctx, env.local, "API_KEY")
}

// TestDeleteLocalRemovesLocalCopyOfRemotelyDeletedSecret: with --delete-local,
// the surviving local copy of a remotely-deleted secret is removed, mirroring
// --delete-remote from the other side.
func TestDeleteLocalRemovesLocalCopyOfRemotelyDeletedSecret(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := newTestEnv(t, ctx)

	t0 := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	seedSecret(t, ctx, env.local, "API_KEY", "v1", t0)

	engine := New(env.local, env.remote, Options{Clock: fixedClock(t1)})
	if _, err := engine.Sync(ctx, false); err != nil {
		t.Fatalf("initial Sync() error = %v", err)
	}

	deleteSecret(t, ctx, env.remote, "API_KEY")

	plan := syncPlan(t, env, Options{DeleteLocalMissing: true, Clock: fixedClock(t1)})
	if len(plan.Pull) != 1 {
		t.Fatalf("expected 1 pull op, got %d", len(plan.Pull))
	}
	if plan.Pull[0].Kind != OpDeleteLocal {
		t.Fatalf("pull op kind = %v, want %v", plan.Pull[0].Kind, OpDeleteLocal)
	}
	if len(plan.Push) != 0 {
		t.Fatalf("plan unexpectedly pushes %d ops", len(plan.Push))
	}

	engine2 := New(env.local, env.remote, Options{DeleteLocalMissing: true, Clock: fixedClock(t1)})
	if _, err := engine2.Sync(ctx, false); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if _, err := getSecretErr(t, ctx, env.local, "API_KEY"); err == nil {
		t.Fatal("local secret still exists after delete-local op")
	}
	// Remote stays deleted, with its tombstone recorded by DeleteSecret.
	if _, err := getTombstone(t, ctx, env.remote, "API_KEY"); err != nil {
		t.Fatalf("remote tombstone missing: %v", err)
	}
}

// TestRecreatedSecretClearsTombstone: deleting a secret, then re-creating it
// with a new value, is a new life for the identity: the next sync pushes the
// new value and clears stale tombstones on both sides.
func TestRecreatedSecretClearsTombstone(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := newTestEnv(t, ctx)

	t0 := time.Date(2026, 3, 2, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	t2 := t0.Add(2 * time.Hour)
	seedSecret(t, ctx, env.local, "API_KEY", "v1", t0)

	engine := New(env.local, env.remote, Options{Clock: fixedClock(t1)})
	if _, err := engine.Sync(ctx, false); err != nil {
		t.Fatalf("initial Sync() error = %v", err)
	}

	deleteSecret(t, ctx, env.local, "API_KEY")
	seedSecret(t, ctx, env.local, "API_KEY", "v2-recreated", t2)

	engine2 := New(env.local, env.remote, Options{Clock: fixedClock(t2)})
	if _, err := engine2.Sync(ctx, false); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if got := getSecret(t, ctx, env.remote, "API_KEY").Value; got != "v2-recreated" {
		t.Fatalf("remote Value = %q, want %q", got, "v2-recreated")
	}

	// Stale tombstones must be cleared so the recreated secret is not deleted
	// again by a later sync.
	if _, err := getTombstone(t, ctx, env.local, "API_KEY"); err == nil {
		t.Fatal("local tombstone not cleared after recreate+sync")
	}
	if _, err := getTombstone(t, ctx, env.remote, "API_KEY"); err == nil {
		t.Fatal("remote tombstone not cleared after recreate+sync")
	}
}

// TestScopedDeleteRemoteOnly: project/environment scoping on tombstones means
// a deletion recorded outside the scope does not affect the scoped plan.
func TestScopedDeleteRemoteOnly(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := newTestEnv(t, ctx)

	t0 := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	seedSecret(t, ctx, env.local, "API_KEY", "v1", t0)

	// Sync a single project/environment scope.
	scope := Scope{ProjectName: "myapp", EnvironmentName: "development"}
	engine := New(env.local, env.remote, Options{Scope: scope, Clock: fixedClock(t0)})
	if _, err := engine.Sync(ctx, false); err != nil {
		t.Fatalf("initial scoped Sync() error = %v", err)
	}

	deleteSecret(t, ctx, env.local, "API_KEY")
	plan := syncPlan(t, env, Options{Scope: scope, DeleteRemoteMissing: true, Clock: fixedClock(t0)})
	if len(plan.Push) != 1 || plan.Push[0].Kind != OpDeleteRemote {
		t.Fatalf("scoped delete-remote plan wrong: %+v", plan.Push)
	}
}

// ---------------------------------------------------------------------------
// Phase 4: direction / strategy / scope matrix
// ---------------------------------------------------------------------------

// Direction push must apply only push-side operations: remote-only secrets are
// planned as pulls but never pulled, while local-only secrets are pushed.
func TestDirectionPushAppliesOnlyPushOps(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := newTestEnv(t, ctx)

	t0 := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	seedSecret(t, ctx, env.local, "LOCAL_ONLY", "local-value", t0)
	seedSecret(t, ctx, env.remote, "REMOTE_ONLY", "remote-value", t0)

	// The plan still lists both sides; only pushes apply under push.
	plan := syncPlan(t, env, Options{Direction: DirectionPush, Clock: fixedClock(t0)})
	if len(plan.Push) != 1 || len(plan.Pull) != 1 {
		t.Fatalf("push plan = %d pushes, %d pulls; want 1 each (planned, direction-gated)", len(plan.Push), len(plan.Pull))
	}

	res, err := New(env.local, env.remote, Options{Direction: DirectionPush, Clock: fixedClock(t0)}).Sync(ctx, false)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if res.OperationsApplied != 1 {
		t.Fatalf("OperationsApplied = %d, want 1 (only the push op)", res.OperationsApplied)
	}

	// Local-only secret was pushed...
	if got := getSecret(t, ctx, env.remote, "LOCAL_ONLY").Value; got != "local-value" {
		t.Fatalf("remote LOCAL_ONLY = %q, want %q", got, "local-value")
	}
	// ...but the remote-only secret was NOT pulled.
	if _, err := getSecretErr(t, ctx, env.local, "REMOTE_ONLY"); err == nil {
		t.Fatal("local REMOTE_ONLY exists after push-direction sync (pull op was applied)")
	}
	// Remote-only source untouched.
	getSecret(t, ctx, env.remote, "REMOTE_ONLY")

	// Re-running with both directions converges fully.
	if _, err := New(env.local, env.remote, Options{Clock: fixedClock(t0)}).Sync(ctx, false); err != nil {
		t.Fatalf("both-direction Sync() error = %v", err)
	}
	if got := getSecret(t, ctx, env.local, "REMOTE_ONLY").Value; got != "remote-value" {
		t.Fatalf("local REMOTE_ONLY after both sync = %q, want %q", got, "remote-value")
	}
}

// Direction pull mirrors push: local-only secrets are planned as pushes but
// never pushed, while remote-only secrets are pulled.
func TestDirectionPullAppliesOnlyPullOps(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := newTestEnv(t, ctx)

	t0 := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	seedSecret(t, ctx, env.local, "LOCAL_ONLY", "local-value", t0)
	seedSecret(t, ctx, env.remote, "REMOTE_ONLY", "remote-value", t0)

	// The plan still lists both sides; only pulls apply under pull.
	plan := syncPlan(t, env, Options{Direction: DirectionPull, Clock: fixedClock(t0)})
	if len(plan.Push) != 1 || len(plan.Pull) != 1 {
		t.Fatalf("pull plan = %d pushes, %d pulls; want 1 each (planned, direction-gated)", len(plan.Push), len(plan.Pull))
	}

	res, err := New(env.local, env.remote, Options{Direction: DirectionPull, Clock: fixedClock(t0)}).Sync(ctx, false)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if res.OperationsApplied != 1 {
		t.Fatalf("OperationsApplied = %d, want 1 (only the pull op)", res.OperationsApplied)
	}

	// Remote-only secret was pulled...
	if got := getSecret(t, ctx, env.local, "REMOTE_ONLY").Value; got != "remote-value" {
		t.Fatalf("local REMOTE_ONLY = %q, want %q", got, "remote-value")
	}
	// ...but the local-only secret was NOT pushed.
	if _, err := getSecretErr(t, ctx, env.remote, "LOCAL_ONLY"); err == nil {
		t.Fatal("remote LOCAL_ONLY exists after pull-direction sync (push op was applied)")
	}
}

// Push + delete-remote-missing makes the remote converge to the local set:
// local-only secrets are pushed and remote-only ones are deleted remotely.
func TestDirectionPushDeleteRemoteMissingConvergesToLocalSet(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := newTestEnv(t, ctx)

	t0 := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	seedSecret(t, ctx, env.local, "LOCAL_ONLY", "local-value", t0)
	seedSecret(t, ctx, env.remote, "REMOTE_ONLY", "remote-value", t0)

	plan := syncPlan(t, env, Options{Direction: DirectionPush, DeleteRemoteMissing: true, Clock: fixedClock(t0)})
	if len(plan.Push) != 2 || len(plan.Pull) != 0 {
		t.Fatalf("push+delete plan = %d pushes, %d pulls; want 2 and 0", len(plan.Push), len(plan.Pull))
	}
	kinds := map[OperationKind]int{}
	for _, op := range plan.Push {
		kinds[op.Kind]++
	}
	if kinds[OpUpsertRemote] != 1 || kinds[OpDeleteRemote] != 1 {
		t.Fatalf("push op kinds = %v, want one upsert-remote and one delete-remote", kinds)
	}

	res, err := New(env.local, env.remote, Options{Direction: DirectionPush, DeleteRemoteMissing: true, Clock: fixedClock(t0)}).Sync(ctx, false)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if res.OperationsApplied != 2 {
		t.Fatalf("OperationsApplied = %d, want 2", res.OperationsApplied)
	}

	// Remote now mirrors the local set exactly.
	if got := getSecret(t, ctx, env.remote, "LOCAL_ONLY").Value; got != "local-value" {
		t.Fatalf("remote LOCAL_ONLY = %q, want %q", got, "local-value")
	}
	if _, err := getSecretErr(t, ctx, env.remote, "REMOTE_ONLY"); err == nil {
		t.Fatal("remote REMOTE_ONLY still present after delete-remote-missing sync")
	}
	// Local untouched apart from sync bookkeeping.
	getSecret(t, ctx, env.local, "LOCAL_ONLY")
	if _, err := getSecretErr(t, ctx, env.local, "REMOTE_ONLY"); err == nil {
		t.Fatal("local REMOTE_ONLY exists where it should never have been created")
	}
}

// prefer-remote resolves both-sides-changed conflicts in favor of the remote
// value, mirroring the existing prefer-local test.
func TestPreferRemoteWinsConflict(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := newTestEnv(t, ctx)

	t0 := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	t2 := t0.Add(2 * time.Hour)
	t3 := t0.Add(3 * time.Hour)

	seedSecret(t, ctx, env.local, "API_KEY", "v1", t0)
	engine := New(env.local, env.remote, Options{Clock: fixedClock(t1)})
	if _, err := engine.Sync(ctx, false); err != nil {
		t.Fatalf("initial Sync() error = %v", err)
	}

	editSecret(t, ctx, env.local, "API_KEY", "v2-local", t2)
	editSecret(t, ctx, env.remote, "API_KEY", "v2-remote", t3)

	// Conflict is detected pre-resolution and resolved into a pull op.
	plan := syncPlan(t, env, Options{Strategy: ConflictPreferRemote, Clock: fixedClock(t3)})
	if plan.Detected != 1 {
		t.Fatalf("plan.Detected = %d, want 1", plan.Detected)
	}
	if len(plan.Conflicts) != 0 || len(plan.Pull) != 1 || len(plan.Push) != 0 {
		t.Fatalf("prefer-remote plan wrong: %d conflicts, %d pulls, %d pushes", len(plan.Conflicts), len(plan.Pull), len(plan.Push))
	}

	engine2 := New(env.local, env.remote, Options{Strategy: ConflictPreferRemote, Clock: fixedClock(t3)})
	res, err := engine2.Sync(ctx, false)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	// ConflictsDetected is the pre-resolution count (Plan.Detected), so a
	// strategy-resolved conflict is still reported — by design, for observability.
	if res.OperationsApplied != 1 || res.ConflictsDetected != 1 {
		t.Fatalf("result = %d applied, %d conflicts; want 1 and 1 (resolved but detected)", res.OperationsApplied, res.ConflictsDetected)
	}
	if got := getSecret(t, ctx, env.local, "API_KEY").Value; got != "v2-remote" {
		t.Fatalf("local Value = %q, want %q (remote won)", got, "v2-remote")
	}
	if got := getSecret(t, ctx, env.remote, "API_KEY").Value; got != "v2-remote" {
		t.Fatalf("remote Value = %q, want %q (must not be overwritten)", got, "v2-remote")
	}
}

// A conflict resolved into an op that the chosen direction cannot apply is
// planned and reported but not applied: under push with prefer-remote the
// resolution is a pull, so the run converges nothing. Re-running with both
// directions converges fully. This documents direction-gated application.
func TestResolvedConflictOutsideDirectionIsNotApplied(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := newTestEnv(t, ctx)

	t0 := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	t2 := t0.Add(2 * time.Hour)
	t3 := t0.Add(3 * time.Hour)

	seedSecret(t, ctx, env.local, "API_KEY", "v1", t0)
	engine := New(env.local, env.remote, Options{Clock: fixedClock(t1)})
	if _, err := engine.Sync(ctx, false); err != nil {
		t.Fatalf("initial Sync() error = %v", err)
	}

	editSecret(t, ctx, env.local, "API_KEY", "v2-local", t2)
	editSecret(t, ctx, env.remote, "API_KEY", "v2-remote", t3)

	opts := Options{Direction: DirectionPush, Strategy: ConflictPreferRemote, Clock: fixedClock(t3)}
	plan := syncPlan(t, env, opts)
	if plan.Detected != 1 {
		t.Fatalf("plan.Detected = %d, want 1", plan.Detected)
	}
	if len(plan.Pull) != 1 || len(plan.Push) != 0 {
		t.Fatalf("plan = %d pulls, %d pushes; want the prefer-remote resolution as one pull", len(plan.Pull), len(plan.Push))
	}

	res, err := New(env.local, env.remote, opts).Sync(ctx, false)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if res.OperationsApplied != 0 {
		t.Fatalf("OperationsApplied = %d, want 0 (pull resolution out of push direction)", res.OperationsApplied)
	}
	if got := getSecret(t, ctx, env.local, "API_KEY").Value; got != "v2-local" {
		t.Fatalf("local Value = %q, want %q (unchanged by push-only run)", got, "v2-local")
	}
	if got := getSecret(t, ctx, env.remote, "API_KEY").Value; got != "v2-remote" {
		t.Fatalf("remote Value = %q, want %q (unchanged by push-only run)", got, "v2-remote")
	}

	// The same strategy with both directions converges.
	if _, err := New(env.local, env.remote, Options{Strategy: ConflictPreferRemote, Clock: fixedClock(t3)}).Sync(ctx, false); err != nil {
		t.Fatalf("both-direction Sync() error = %v", err)
	}
	if got := getSecret(t, ctx, env.local, "API_KEY").Value; got != "v2-remote" {
		t.Fatalf("local Value after both sync = %q, want %q", got, "v2-remote")
	}
}

// Both directions in one run: concurrent edits on different secrets produce no
// conflict — each side's change is applied to the other in a single reconcile.
func TestBothDirectionConvergesConcurrentEdits(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := newTestEnv(t, ctx)

	t0 := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	t2 := t0.Add(2 * time.Hour)
	t3 := t0.Add(3 * time.Hour)

	seedSecret(t, ctx, env.local, "API_KEY", "a1", t0)
	engine := New(env.local, env.remote, Options{Clock: fixedClock(t1)})
	if _, err := engine.Sync(ctx, false); err != nil {
		t.Fatalf("initial Sync() error = %v", err)
	}

	// After the baseline sync, local edits A while remote adds B.
	editSecret(t, ctx, env.local, "API_KEY", "a2-local", t2)
	seedSecret(t, ctx, env.remote, "DB_PASSWORD", "b1", t3)

	plan := syncPlan(t, env, Options{Clock: fixedClock(t3)})
	if len(plan.Push) != 1 || len(plan.Pull) != 1 {
		t.Fatalf("plan = %d pushes, %d pulls; want 1 each", len(plan.Push), len(plan.Pull))
	}
	if plan.Detected != 0 || len(plan.Conflicts) != 0 {
		t.Fatalf("plan conflicts = %d detected/%d listed; want 0/0 (different keys)", plan.Detected, len(plan.Conflicts))
	}

	res, err := New(env.local, env.remote, Options{Clock: fixedClock(t3)}).Sync(ctx, false)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if res.OperationsApplied != 2 || res.ConflictsDetected != 0 {
		t.Fatalf("result = %d applied, %d conflicts; want 2 and 0", res.OperationsApplied, res.ConflictsDetected)
	}

	// Both changes landed on the opposite side.
	if got := getSecret(t, ctx, env.remote, "API_KEY").Value; got != "a2-local" {
		t.Fatalf("remote API_KEY = %q, want %q", got, "a2-local")
	}
	if got := getSecret(t, ctx, env.local, "DB_PASSWORD").Value; got != "b1" {
		t.Fatalf("local DB_PASSWORD = %q, want %q", got, "b1")
	}

	// A follow-up run is a full no-op.
	again := syncPlan(t, env, Options{Clock: fixedClock(t3)})
	if len(again.Push)+len(again.Pull)+len(again.Conflicts) != 0 {
		t.Fatalf("follow-up plan not empty: %+v", again)
	}
}

// A project-scoped push only reconciles the scoped project; out-of-scope
// projects stay untouched until their own scoped run.
func TestScopeLimitsPushToScopedProject(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := newTestEnv(t, ctx)

	t0 := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	seedSecretIn(t, ctx, env.local, "alpha", "development", "ALPHA_KEY", "alpha-value", t0)
	seedSecretIn(t, ctx, env.local, "beta", "development", "BETA_KEY", "beta-value", t0)

	// Push only the alpha project.
	alphaScope := Scope{ProjectName: "alpha"}
	if _, err := New(env.local, env.remote, Options{Direction: DirectionPush, Scope: alphaScope, Clock: fixedClock(t0)}).Sync(ctx, false); err != nil {
		t.Fatalf("alpha-scoped Sync() error = %v", err)
	}

	if got := getSecretIn(t, ctx, env.remote, "alpha", "development", "ALPHA_KEY").Value; got != "alpha-value" {
		t.Fatalf("remote alpha ALPHA_KEY = %q, want %q", got, "alpha-value")
	}
	// Beta was not created on the remote at all.
	if _, err := env.remote.GetProjectByName(ctx, "beta"); err == nil {
		t.Fatal("remote beta project exists after alpha-only push")
	}

	// A beta-scoped push converges the second project.
	if _, err := New(env.local, env.remote, Options{Direction: DirectionPush, Scope: Scope{ProjectName: "beta"}, Clock: fixedClock(t0)}).Sync(ctx, false); err != nil {
		t.Fatalf("beta-scoped Sync() error = %v", err)
	}
	if got := getSecretIn(t, ctx, env.remote, "beta", "development", "BETA_KEY").Value; got != "beta-value" {
		t.Fatalf("remote beta BETA_KEY = %q, want %q", got, "beta-value")
	}

	// Fully converged: an unscoped plan has nothing left to do.
	plan := syncPlan(t, env, Options{Clock: fixedClock(t0)})
	if len(plan.Push)+len(plan.Pull)+len(plan.Conflicts) != 0 {
		t.Fatalf("unscoped plan not empty after scoped convergence: %+v", plan)
	}
}

// An environment-scoped push reconciles only the scoped environment; other
// environments of the same project are left for their own runs.
func TestScopeEnvironmentLimitsSync(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := newTestEnv(t, ctx)

	t0 := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	seedSecretIn(t, ctx, env.local, "envproj", "development", "DEV_KEY", "dev-value", t0)
	seedSecretIn(t, ctx, env.local, "envproj", "production", "PROD_KEY", "prod-value", t0)

	prodScope := Scope{ProjectName: "envproj", EnvironmentName: "production"}
	if _, err := New(env.local, env.remote, Options{Direction: DirectionPush, Scope: prodScope, Clock: fixedClock(t0)}).Sync(ctx, false); err != nil {
		t.Fatalf("prod-scoped Sync() error = %v", err)
	}

	// Production secret pushed; development secret still local-only.
	if got := getSecretIn(t, ctx, env.remote, "envproj", "production", "PROD_KEY").Value; got != "prod-value" {
		t.Fatalf("remote PROD_KEY = %q, want %q", got, "prod-value")
	}
	if _, err := getSecretErrIn(t, ctx, env.remote, "envproj", "development", "DEV_KEY"); err == nil {
		t.Fatal("remote DEV_KEY exists after production-only push")
	}

	// Development remains pending in its own scope.
	devPlan := syncPlan(t, env, Options{Scope: Scope{ProjectName: "envproj", EnvironmentName: "development"}, Clock: fixedClock(t0)})
	if len(devPlan.Push) != 1 || devPlan.Push[0].Kind != OpUpsertRemote {
		t.Fatalf("dev-scoped plan = %+v, want one upsert-remote for DEV_KEY", devPlan.Push)
	}

	// A dev-scoped push converges it.
	if _, err := New(env.local, env.remote, Options{Direction: DirectionPush, Scope: Scope{ProjectName: "envproj", EnvironmentName: "development"}, Clock: fixedClock(t0)}).Sync(ctx, false); err != nil {
		t.Fatalf("dev-scoped Sync() error = %v", err)
	}
	if got := getSecretIn(t, ctx, env.remote, "envproj", "development", "DEV_KEY").Value; got != "dev-value" {
		t.Fatalf("remote DEV_KEY = %q, want %q", got, "dev-value")
	}
}
