package postgres

// Stage B5: backend method parity tests, mirroring the SQLite suite in
// internal/storage/sqlite/methods_test.go and sync_runs_test.go so both
// storage backends behave identically for the sync engine.
//
// These tests share one database: never call t.Parallel.

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"vault/internal/crypto"
	"vault/internal/domain"
)

func TestListSecretMetadataSkipsDecryption(t *testing.T) {
	ctx := context.Background()
	b := newUnlockedBackend(t)

	proj := mustProject(t, b, "demo")

	secret, err := domain.NewSecret(proj.ID, "development", "API_KEY", "super-secret", domain.SecretTypeAPIKey, "test")
	if err != nil {
		t.Fatalf("NewSecret() error = %v", err)
	}
	secret.Tags = []string{"critical", "api"}
	secret.Checksum = crypto.Hash([]byte(secret.Value))
	if err := b.CreateSecret(ctx, secret); err != nil {
		t.Fatalf("CreateSecret() error = %v", err)
	}

	secrets, err := b.ListSecretMetadata(ctx, proj.ID, "development")
	if err != nil {
		t.Fatalf("ListSecretMetadata() error = %v", err)
	}
	if len(secrets) != 1 {
		t.Fatalf("len(ListSecretMetadata()) = %d, want 1", len(secrets))
	}
	if secrets[0].Value != "" {
		t.Errorf("Value = %q, want empty (metadata listing must not decrypt)", secrets[0].Value)
	}
	if secrets[0].Key != secret.Key {
		t.Errorf("Key = %q, want %q", secrets[0].Key, secret.Key)
	}
	if len(secrets[0].Tags) != 2 {
		t.Errorf("tags len = %d, want 2", len(secrets[0].Tags))
	}
}

func TestMarkSyncedSetsSyncMetadataWithoutBumpingVersion(t *testing.T) {
	ctx := context.Background()
	b := newUnlockedBackend(t)

	proj := mustProject(t, b, "syncmark")

	secret, err := domain.NewSecret(proj.ID, "development", "TOKEN", "s3cr3t", domain.SecretTypeOAuthToken, "test")
	if err != nil {
		t.Fatalf("NewSecret() error = %v", err)
	}
	if err := b.CreateSecret(ctx, secret); err != nil {
		t.Fatalf("CreateSecret() error = %v", err)
	}

	syncedAt := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	if err := b.MarkSynced(ctx, secret.ID, syncedAt); err != nil {
		t.Fatalf("MarkSynced() error = %v", err)
	}

	got, err := b.GetSecretByID(ctx, secret.ID)
	if err != nil {
		t.Fatalf("GetSecretByID() error = %v", err)
	}
	if got.SyncStatus != domain.SyncStatusInSync {
		t.Errorf("SyncStatus = %q, want %q", got.SyncStatus, domain.SyncStatusInSync)
	}
	if got.LastSyncedAt == nil || !got.LastSyncedAt.Equal(syncedAt) {
		t.Errorf("LastSyncedAt = %v, want %v", got.LastSyncedAt, syncedAt)
	}
	// Value and version history must be untouched by sync bookkeeping.
	if got.Value != "s3cr3t" {
		t.Errorf("Value = %q, want %q", got.Value, "s3cr3t")
	}
	if got.Version != 1 {
		t.Errorf("Version = %d, want 1", got.Version)
	}

	// ListSecrets must round-trip last_synced_at for conflict detection.
	listed, err := b.ListSecrets(ctx, proj.ID, "development")
	if err != nil {
		t.Fatalf("ListSecrets() error = %v", err)
	}
	if len(listed) != 1 || listed[0].LastSyncedAt == nil || !listed[0].LastSyncedAt.Equal(syncedAt) {
		t.Errorf("ListSecrets() did not round-trip last_synced_at: %+v", listed)
	}
}

func TestDeleteSecretRecordsTombstone(t *testing.T) {
	ctx := context.Background()
	b := newUnlockedBackend(t)

	proj := mustProject(t, b, "tombproj")

	secret, err := domain.NewSecret(proj.ID, "development", "API_KEY", "s3cr3t", domain.SecretTypeAPIKey, "test")
	if err != nil {
		t.Fatalf("NewSecret() error = %v", err)
	}
	secret.Checksum = crypto.Hash([]byte(secret.Value))
	if err := b.CreateSecret(ctx, secret); err != nil {
		t.Fatalf("CreateSecret() error = %v", err)
	}

	if err := b.DeleteSecret(ctx, secret.ID); err != nil {
		t.Fatalf("DeleteSecret() error = %v", err)
	}

	got, err := b.GetTombstone(ctx, proj.ID, "development", "API_KEY")
	if err != nil {
		t.Fatalf("GetTombstone() error = %v", err)
	}
	if got.Key != "API_KEY" || got.ProjectID != proj.ID || got.Environment != "development" {
		t.Errorf("tombstone identity wrong: %+v", got)
	}
	if got.Checksum != crypto.Hash([]byte("s3cr3t")) {
		t.Errorf("tombstone checksum = %q, want %q", got.Checksum, crypto.Hash([]byte("s3cr3t")))
	}
	if got.DeletedAt.IsZero() {
		t.Errorf("tombstone missing deleted_at: %+v", got)
	}

	list, err := b.ListTombstones(ctx, proj.ID, "development")
	if err != nil {
		t.Fatalf("ListTombstones() error = %v", err)
	}
	if len(list) != 1 || list[0].Key != "API_KEY" {
		t.Errorf("len(ListTombstones()) = %d, want 1", len(list))
	}

	// Deleting an unknown secret must not invent a tombstone.
	other, err := domain.NewSecret(proj.ID, "development", "OTHER", "v", domain.SecretTypeGeneric, "test")
	if err != nil {
		t.Fatalf("NewSecret(OTHER) error = %v", err)
	}
	if err := b.CreateSecret(ctx, other); err != nil {
		t.Fatalf("CreateSecret(OTHER) error = %v", err)
	}
	// Delete by an id that was never stored: no identity to tombstone.
	if err := b.DeleteSecret(ctx, "nonexistent-id"); err != nil {
		t.Fatalf("DeleteSecret(nonexistent) error = %v", err)
	}
	list, err = b.ListTombstones(ctx, proj.ID, "development")
	if err != nil {
		t.Fatalf("ListTombstones() error = %v", err)
	}
	if len(list) != 1 {
		t.Errorf("len(ListTombstones()) after unknown-id delete = %d, want 1", len(list))
	}

	if err := b.DeleteTombstone(ctx, proj.ID, "development", "API_KEY"); err != nil {
		t.Fatalf("DeleteTombstone() error = %v", err)
	}
	if _, err := b.GetTombstone(ctx, proj.ID, "development", "API_KEY"); err == nil {
		t.Error("tombstone still present after DeleteTombstone")
	}
}

func TestSearchSecretMetadataSkipsDecryption(t *testing.T) {
	ctx := context.Background()
	b := newUnlockedBackend(t)

	proj := mustProject(t, b, "searchdemo")

	secret, err := domain.NewSecret(proj.ID, "development", "DATABASE_URL", "postgres://secret", domain.SecretTypeDatabase, "test")
	if err != nil {
		t.Fatalf("NewSecret() error = %v", err)
	}
	secret.Tags = []string{"database"}
	secret.Checksum = crypto.Hash([]byte(secret.Value))
	if err := b.CreateSecret(ctx, secret); err != nil {
		t.Fatalf("CreateSecret() error = %v", err)
	}

	// plainto_tsquery stems "DATABASE" to "databas", which to_tsvector makes
	// from "DATABASE_URL" — the same result SQLite's FTS5 gives.
	results, err := b.SearchSecretMetadata(ctx, "DATABASE")
	if err != nil {
		t.Fatalf("SearchSecretMetadata() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("len(SearchSecretMetadata(DATABASE)) = %d, want 1", len(results))
	}
	if results[0].Value != "" {
		t.Errorf("Value = %q, want empty", results[0].Value)
	}

	// Decrypting search must return the same hits with values attached.
	full, err := b.SearchSecrets(ctx, "DATABASE")
	if err != nil {
		t.Fatalf("SearchSecrets() error = %v", err)
	}
	if len(full) != 1 || full[0].Value != "postgres://secret" {
		t.Errorf("SearchSecrets() = %+v, want 1 result with decrypted value", full)
	}
}

func TestListProjectsLoadsEnvironmentsInBatch(t *testing.T) {
	ctx := context.Background()
	b := newUnlockedBackend(t)

	for _, name := range []string{"alpha", "beta"} {
		mustProject(t, b, name)
	}

	projects, err := b.ListProjects(ctx)
	if err != nil {
		t.Fatalf("ListProjects() error = %v", err)
	}
	if len(projects) != 2 {
		t.Fatalf("len(ListProjects()) = %d, want 2", len(projects))
	}
	for _, p := range projects {
		if len(p.Environments) != 3 {
			t.Errorf("project %q environments = %d, want 3", p.Name, len(p.Environments))
		}
	}
}

func TestSecretCRUDAndVersionHistory(t *testing.T) {
	ctx := context.Background()
	b := newUnlockedBackend(t)

	proj := mustProject(t, b, "crud")

	secret, err := domain.NewSecret(proj.ID, "development", "API_KEY", "v1-value", domain.SecretTypeAPIKey, "test")
	if err != nil {
		t.Fatalf("NewSecret() error = %v", err)
	}
	secret.UpdatedAt = us(secret.UpdatedAt)
	secret.CreatedAt = us(secret.CreatedAt)
	if err := b.CreateSecret(ctx, secret); err != nil {
		t.Fatalf("CreateSecret() error = %v", err)
	}

	got := getSecret(t, b, proj.ID, "development", "API_KEY")
	if got.Value != "v1-value" || got.Version != 1 {
		t.Fatalf("after create: value=%q version=%d", got.Value, got.Version)
	}

	// Update: version bumps, value changes; version 1 stays retrievable.
	got.Value = "v2-value"
	got.Checksum = crypto.Hash([]byte("v2-value"))
	got.UpdatedAt = us(time.Now())
	got.UpdatedBy = "test"
	if err := b.UpdateSecret(ctx, got); err != nil {
		t.Fatalf("UpdateSecret() error = %v", err)
	}

	// The CLI records history explicitly; mirror that so the history table is
	// exercised end to end.
	if err := b.CreateSecretVersion(ctx, &domain.SecretVersion{
		ID:        domain.GenerateID(),
		SecretID:  secret.ID,
		Value:     "v2-value",
		Version:   2,
		CreatedAt: us(time.Now()),
		CreatedBy: "test",
		Checksum:  crypto.Hash([]byte("v2-value")),
	}); err != nil {
		t.Fatalf("CreateSecretVersion() error = %v", err)
	}

	updated := getSecret(t, b, proj.ID, "development", "API_KEY")
	if updated.Value != "v2-value" || updated.Version != 2 {
		t.Fatalf("after update: value=%q version=%d, want v2-value/2", updated.Value, updated.Version)
	}

	versions, err := b.ListSecretVersions(ctx, secret.ID)
	if err != nil {
		t.Fatalf("ListSecretVersions() error = %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("len(ListSecretVersions()) = %d, want 2", len(versions))
	}

	v1, err := b.GetSecretVersion(ctx, secret.ID, 1)
	if err != nil {
		t.Fatalf("GetSecretVersion(1) error = %v", err)
	}
	if v1.Value != "v1-value" {
		t.Errorf("version 1 value = %q, want v1-value", v1.Value)
	}

	if _, err := b.GetSecretVersion(ctx, secret.ID, 99); err == nil {
		t.Error("GetSecretVersion(99) succeeded, want error")
	}

	// Deletion removes the row.
	if err := b.DeleteSecret(ctx, secret.ID); err != nil {
		t.Fatalf("DeleteSecret() error = %v", err)
	}
	if _, err := b.GetSecret(ctx, proj.ID, "development", "API_KEY"); err == nil {
		t.Error("GetSecret() after delete succeeded, want error")
	}
}

// TestVaultLifecycle covers initialization, double-initialization, unlock with
// wrong/correct password, and the locked-backend guards.
func TestVaultLifecycle(t *testing.T) {
	ctx := context.Background()
	b := newTestBackend(t)

	init, err := b.IsInitialized(ctx)
	if err != nil {
		t.Fatalf("IsInitialized() error = %v", err)
	}
	if init {
		t.Fatal("IsInitialized() = true on fresh database, want false")
	}

	if err := b.CreateVault(ctx, testPassword); err != nil {
		t.Fatalf("CreateVault() error = %v", err)
	}
	if init, err = b.IsInitialized(ctx); err != nil || !init {
		t.Fatalf("IsInitialized() = %v, %v; want true, nil", init, err)
	}

	// Second CreateVault must fail (single-row vault_metadata).
	if err := b.CreateVault(ctx, testPassword); err == nil {
		t.Error("second CreateVault() succeeded, want error")
	}

	// Wrong password must be rejected.
	if _, err := b.UnlockVault(ctx, "wrong-password"); err == nil {
		t.Error("UnlockVault(wrong) succeeded, want error")
	}
	if _, err := b.UnlockVault(ctx, testPassword); err != nil {
		t.Errorf("UnlockVault(correct) error = %v", err)
	}

	// Lock the backend again and assert the unlocked-only guards.
	b.key = nil
	if _, err := b.GetSecret(ctx, "any", "development", "KEY"); err == nil || !strings.Contains(err.Error(), "not unlocked") {
		t.Errorf("GetSecret() on locked vault error = %v, want 'vault not unlocked'", err)
	}
	if _, err := b.ListSecretMetadata(ctx, "any", "development"); err == nil {
		t.Error("ListSecretMetadata() on locked vault succeeded, want error")
	}
	if err := b.CreateVault(ctx, "another"); err == nil {
		t.Error("CreateVault() on initialized vault succeeded, want error")
	}
}

// TestSyncRunWorksOnLockedVault proves sync observability never needs the
// encryption key: `vault sync status` must read history without unlocking.
func TestSyncRunWorksOnLockedVault(t *testing.T) {
	ctx := context.Background()
	b := newTestBackend(t)

	if err := b.CreateVault(ctx, testPassword); err != nil {
		t.Fatalf("CreateVault() error = %v", err)
	}
	b.key = nil // explicitly locked: RecordSyncRun/ListSyncRuns must not care

	now := us(time.Now())
	if err := b.RecordSyncRun(ctx, &domain.SyncRun{
		ID:         domain.GenerateID(),
		StartedAt:  now,
		FinishedAt: now,
		Direction:  "both",
		Strategy:   "fail",
		Status:     domain.SyncStatusInSync,
		Pushed:     1,
	}); err != nil {
		t.Fatalf("RecordSyncRun() on locked vault error = %v", err)
	}

	runs, err := b.ListSyncRuns(ctx, 10)
	if err != nil {
		t.Fatalf("ListSyncRuns() on locked vault error = %v", err)
	}
	if len(runs) != 1 || runs[0].Pushed != 1 {
		t.Errorf("ListSyncRuns() = %+v, want 1 run with Pushed=1", runs)
	}
}

func TestSyncRunRoundTripAndOrdering(t *testing.T) {
	ctx := context.Background()
	b := newTestBackend(t)

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
			Pushed:     3,
			Pulled:     1,
		},
		{
			ID:         domain.GenerateID(),
			StartedAt:  base.Add(time.Hour),
			FinishedAt: base.Add(time.Hour + time.Minute),
			Direction:  "pull",
			Strategy:   "fail",
			Scope:      "myapp/development",
			Status:     domain.SyncStatusFailed,
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
		},
	}

	for _, r := range runs {
		if err := b.RecordSyncRun(ctx, r); err != nil {
			t.Fatalf("RecordSyncRun() error = %v", err)
		}
	}

	got, err := b.ListSyncRuns(ctx, 2)
	if err != nil {
		t.Fatalf("ListSyncRuns(2) error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len(ListSyncRuns(2)) = %d, want 2", len(got))
	}
	if first := got[0]; first.Status != domain.SyncStatusDryRun || !first.DryRun {
		t.Errorf("newest run wrong: %+v", first)
	}
	if second := got[1]; second.Status != domain.SyncStatusFailed || second.Conflicts != 2 || second.Error == "" {
		t.Errorf("second run wrong: %+v", second)
	}
	if !got[0].StartedAt.Equal(base.Add(2 * time.Hour)) {
		t.Errorf("newest StartedAt = %v, want %v", got[0].StartedAt, base.Add(2*time.Hour))
	}

	all, err := b.ListSyncRuns(ctx, 10)
	if err != nil {
		t.Fatalf("ListSyncRuns(10) error = %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("len(ListSyncRuns(10)) = %d, want 3", len(all))
	}
	oldest := all[2]
	if oldest.Status != domain.SyncStatusInSync || oldest.Pushed != 3 || oldest.Pulled != 1 {
		t.Errorf("oldest run fields wrong: %+v", oldest)
	}
	if oldest.Scope != "myapp/development" || oldest.Strategy != "prefer-latest" {
		t.Errorf("oldest run scope/strategy wrong: %+v", oldest)
	}
}

// TestTimestampRoundTripPreservesInstants is the semantics probe flagged in
// the Stage B plan: Postgres columns are `timestamp without time zone`, so a
// round trip must preserve the instant regardless of the writer's location
// (this machine runs IST; CI and servers run UTC).
func TestTimestampRoundTripPreservesInstants(t *testing.T) {
	ctx := context.Background()
	b := newUnlockedBackend(t)

	ist := time.FixedZone("IST", 5*3600+1800)
	cases := []struct {
		name string
		when time.Time
	}{
		{"utc", time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)},
		{"ist", time.Date(2026, 3, 1, 10, 0, 0, 0, ist)},
		{"utc-micros", time.Date(2026, 6, 15, 23, 59, 59, 123456000, time.UTC)},
		{"ist-micros", time.Date(2026, 6, 15, 23, 59, 59, 123456000, ist)},
	}

	proj := mustProject(t, b, "tstamp")
	deadline := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)

	for _, tc := range cases {
		secret, err := domain.NewSecret(proj.ID, "development", "TS_"+strings.ToUpper(tc.name), "v", domain.SecretTypeGeneric, "test")
		if err != nil {
			t.Fatalf("NewSecret(%s) error = %v", tc.name, err)
		}
		secret.CreatedAt = us(tc.when)
		secret.UpdatedAt = us(tc.when)
		secret.ExpiresAt = &deadline
		if err := b.CreateSecret(ctx, secret); err != nil {
			t.Fatalf("CreateSecret(%s) error = %v", tc.name, err)
		}

		got := getSecret(t, b, proj.ID, "development", "TS_"+strings.ToUpper(tc.name))
		if !got.UpdatedAt.Equal(secret.UpdatedAt) {
			t.Errorf("%s: UpdatedAt round trip = %v, want %v (instant shifted)",
				tc.name, got.UpdatedAt, secret.UpdatedAt)
		}
		if !got.CreatedAt.Equal(secret.CreatedAt) {
			t.Errorf("%s: CreatedAt round trip = %v, want %v",
				tc.name, got.CreatedAt, secret.CreatedAt)
		}
		if got.ExpiresAt == nil || !got.ExpiresAt.Equal(deadline) {
			t.Errorf("%s: ExpiresAt round trip = %v, want %v",
				tc.name, got.ExpiresAt, deadline)
		}

		// MarkSynced takes an arbitrary instant too.
		if err := b.MarkSynced(ctx, secret.ID, us(tc.when)); err != nil {
			t.Fatalf("MarkSynced(%s) error = %v", tc.name, err)
		}
		got = getSecret(t, b, proj.ID, "development", "TS_"+strings.ToUpper(tc.name))
		if got.LastSyncedAt == nil || !got.LastSyncedAt.Equal(secret.UpdatedAt) {
			t.Errorf("%s: LastSyncedAt = %v, want %v",
				tc.name, got.LastSyncedAt, secret.UpdatedAt)
		}
	}
}

// TestSecretValueEncryptedAtRest verifies the BYTEA column never holds
// plaintext: what the driver sees is ciphertext, what GetSecret returns is
// the plaintext.
func TestSecretValueEncryptedAtRest(t *testing.T) {
	ctx := context.Background()
	b := newUnlockedBackend(t)

	const plaintext = "hunter2-plaintext-check"
	proj := mustProject(t, b, "atrest")
	secret := seedProjectSecret(t, b, "atrest", "development", "DB_PASS", plaintext, us(time.Now()))

	var raw []byte
	if err := b.db.QueryRowContext(ctx,
		`SELECT value FROM secrets WHERE id = $1`, secret.ID).Scan(&raw); err != nil {
		t.Fatalf("raw SELECT value error = %v", err)
	}
	if bytes.Contains(raw, []byte(plaintext)) {
		t.Fatal("secrets.value contains plaintext; encryption at rest is broken")
	}
	if len(raw) == 0 {
		t.Fatal("secrets.value is empty")
	}

	got := getSecret(t, b, proj.ID, "development", "DB_PASS")
	if got.Value != plaintext {
		t.Errorf("GetSecret() value = %q, want %q", got.Value, plaintext)
	}
}

// TestTransactionCommitRollback exercises the BeginTx wrapper: commit and
// rollback must both complete, and a stale transaction must report an error.
func TestTransactionCommitRollback(t *testing.T) {
	ctx := context.Background()
	b := newUnlockedBackend(t)

	tx, err := b.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx() error = %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Errorf("Commit() error = %v", err)
	}
	if err := tx.Commit(); err == nil {
		t.Error("second Commit() succeeded, want error")
	}

	tx2, err := b.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx() #2 error = %v", err)
	}
	if err := tx2.Rollback(); err != nil {
		t.Errorf("Rollback() error = %v", err)
	}
}

func TestDeleteProjectCascadesSecrets(t *testing.T) {
	ctx := context.Background()
	b := newUnlockedBackend(t)

	proj := mustProject(t, b, "cascade")
	seedProjectSecret(t, b, "cascade", "development", "API_KEY", "v", us(time.Now()))

	if err := b.DeleteProject(ctx, proj.ID); err != nil {
		t.Fatalf("DeleteProject() error = %v", err)
	}

	if _, err := b.GetProjectByName(ctx, "cascade"); err == nil {
		t.Error("GetProjectByName() after delete succeeded, want error")
	}
	// Secrets of the deleted project must be gone too (FK cascade).
	var count int
	if err := b.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM secrets WHERE project_id = $1`, proj.ID).Scan(&count); err != nil {
		t.Fatalf("COUNT(secrets) error = %v", err)
	}
	if count != 0 {
		t.Errorf("secrets rows for deleted project = %d, want 0", count)
	}
}
