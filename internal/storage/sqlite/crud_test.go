package sqlite

// Stage A3: close the coverage gaps the original suite left open — secret
// CRUD with version history, the vault lifecycle, project/environment CRUD,
// transactions, timestamp instant-safety, and the locked/closed-backend
// guards. Helpers mirror internal/storage/postgres/harness_test.go so both
// backends are exercised through the same scenarios.

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vault/internal/crypto"
	"vault/internal/domain"
	"vault/internal/storage"
)

const testPassword = "password123"

// newRawBackend returns an initialized backend with schema but no vault
// (nothing to unlock) — the starting point for lifecycle tests.
func newRawBackend(t *testing.T, ctx context.Context) *Backend {
	t.Helper()

	cfg := &storage.Config{
		Type: "sqlite",
		Path: filepath.Join(t.TempDir(), "vault.db"),
	}

	backend, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		_ = backend.Close()
	})

	if err := backend.Initialize(ctx, cfg); err != nil {
		if strings.Contains(err.Error(), "requires cgo") {
			t.Skipf("sqlite backend unavailable in this test environment: %v", err)
		}
		t.Fatalf("Initialize() error = %v", err)
	}

	return backend
}

func mustProject(t *testing.T, b *Backend, name string) *domain.Project {
	t.Helper()

	ctx := context.Background()
	proj, err := b.GetProjectByName(ctx, name)
	if err == nil {
		return proj
	}

	proj, err = domain.NewProject(name, "", "test")
	if err != nil {
		t.Fatalf("NewProject(%q) error = %v", name, err)
	}
	if err := b.CreateProject(ctx, proj); err != nil {
		t.Fatalf("CreateProject(%q) error = %v", name, err)
	}
	proj, err = b.GetProjectByName(ctx, name)
	if err != nil {
		t.Fatalf("GetProjectByName(%q) error = %v", name, err)
	}
	return proj
}

// seedProjectSecret creates project + secret in one step and returns the
// created secret (already persisted). updatedAt overrides the clock so tests
// can pin exact timestamps.
func seedProjectSecret(t *testing.T, b *Backend, project, env, key, value string, updatedAt time.Time) *domain.Secret {
	t.Helper()

	proj := mustProject(t, b, project)

	secret, err := domain.NewSecret(proj.ID, env, key, value, domain.SecretTypeGeneric, "test")
	if err != nil {
		t.Fatalf("NewSecret(%s/%s/%s) error = %v", project, env, key, err)
	}
	secret.UpdatedBy = "test"
	secret.Checksum = crypto.Hash([]byte(value))
	secret.UpdatedAt = us(updatedAt)
	secret.CreatedAt = us(updatedAt)

	if err := b.CreateSecret(context.Background(), secret); err != nil {
		t.Fatalf("CreateSecret(%s/%s/%s) error = %v", project, env, key, err)
	}
	return secret
}

// getSecret is the read-back counterpart of seedProjectSecret.
func getSecret(t *testing.T, b *Backend, projectID, env, key string) *domain.Secret {
	t.Helper()

	secret, err := b.GetSecret(context.Background(), projectID, env, key)
	if err != nil {
		t.Fatalf("GetSecret(%s/%s/%s) error = %v", projectID, env, key, err)
	}
	return secret
}

// us truncates to microsecond precision so pinned instants survive a round
// trip exactly (SQLite stores nanoseconds, but the tests assert equality).
func us(t time.Time) time.Time {
	return t.Truncate(time.Microsecond)
}

func TestSecretCRUDAndVersionHistory(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	b := newTestBackend(t, ctx)

	proj := mustProject(t, b, "crud")

	secret, err := domain.NewSecret(proj.ID, "development", "API_KEY", "v1-value", domain.SecretTypeAPIKey, "test")
	if err != nil {
		t.Fatalf("NewSecret() error = %v", err)
	}
	secret.CreatedAt = us(secret.CreatedAt)
	secret.UpdatedAt = us(secret.UpdatedAt)
	if err := b.CreateSecret(ctx, secret); err != nil {
		t.Fatalf("CreateSecret() error = %v", err)
	}

	got := getSecret(t, b, proj.ID, "development", "API_KEY")
	if got.Value != "v1-value" || got.Version != 1 {
		t.Fatalf("after create: value=%q version=%d", got.Value, got.Version)
	}

	// Duplicate identity is rejected by the unique(project, environment, key)
	// constraint.
	dup, err := domain.NewSecret(proj.ID, "development", "API_KEY", "other", domain.SecretTypeAPIKey, "test")
	if err != nil {
		t.Fatalf("NewSecret(dup) error = %v", err)
	}
	if err := b.CreateSecret(ctx, dup); err == nil || !strings.Contains(err.Error(), "failed to insert secret") {
		t.Errorf("duplicate CreateSecret() error = %v, want failed to insert secret", err)
	}

	// Update: version bumps, value changes.
	got.Value = "v2-value"
	got.Checksum = crypto.Hash([]byte("v2-value"))
	got.UpdatedAt = us(time.Now())
	got.UpdatedBy = "test"
	if err := b.UpdateSecret(ctx, got); err != nil {
		t.Fatalf("UpdateSecret() error = %v", err)
	}

	// The CLI records history explicitly; mirror that so the history table is
	// exercised end to end.
	v2 := &domain.SecretVersion{
		ID:        domain.GenerateID(),
		SecretID:  secret.ID,
		Value:     "v2-value",
		Version:   2,
		CreatedAt: us(time.Now()),
		CreatedBy: "test",
		Checksum:  crypto.Hash([]byte("v2-value")),
	}
	if err := b.CreateSecretVersion(ctx, v2); err != nil {
		t.Fatalf("CreateSecretVersion() error = %v", err)
	}
	if err := b.CreateSecretVersion(ctx, v2); err == nil || !strings.Contains(err.Error(), "failed to insert secret version") {
		t.Errorf("duplicate CreateSecretVersion() error = %v, want failed to insert secret version", err)
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

	if _, err := b.GetSecretVersion(ctx, secret.ID, 99); err == nil || !strings.Contains(err.Error(), "version not found") {
		t.Errorf("GetSecretVersion(99) error = %v, want version not found", err)
	}

	// Deletion removes the row; GetSecret reports it gone.
	if err := b.DeleteSecret(ctx, secret.ID); err != nil {
		t.Fatalf("DeleteSecret() error = %v", err)
	}
	if _, err := b.GetSecret(ctx, proj.ID, "development", "API_KEY"); err == nil || !strings.Contains(err.Error(), "secret not found") {
		t.Errorf("GetSecret() after delete error = %v, want secret not found", err)
	}
}

// TestVaultLifecycle covers initialization, double-initialization, unlock
// with wrong/correct password, corrupt stored salt, and the locked-backend
// guards on every decrypting method.
func TestVaultLifecycle(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	b := newRawBackend(t, ctx)

	if init, err := b.IsInitialized(ctx); err != nil || init {
		t.Fatalf("IsInitialized() = %v, %v; want false, nil", init, err)
	}
	if err := b.Health(ctx); err != nil {
		t.Errorf("Health() on fresh database error = %v", err)
	}
	// Unlocking a database that has no vault row must say so.
	if _, err := b.UnlockVault(ctx, testPassword); err == nil || !strings.Contains(err.Error(), "vault not initialized") {
		t.Errorf("UnlockVault() before CreateVault error = %v, want vault not initialized", err)
	}

	if err := b.CreateVault(ctx, testPassword); err != nil {
		t.Fatalf("CreateVault() error = %v", err)
	}
	if init, err := b.IsInitialized(ctx); err != nil || !init {
		t.Fatalf("IsInitialized() = %v, %v; want true, nil", init, err)
	}
	if err := b.Health(ctx); err != nil {
		t.Errorf("Health() error = %v", err)
	}

	// Second CreateVault must fail (single-row vault_metadata).
	if err := b.CreateVault(ctx, testPassword); err == nil {
		t.Error("second CreateVault() succeeded, want error")
	}

	// Wrong password must be rejected, right password accepted.
	if _, err := b.UnlockVault(ctx, "wrong-password"); err == nil {
		t.Error("UnlockVault(wrong) succeeded, want error")
	}
	if _, err := b.UnlockVault(ctx, testPassword); err != nil {
		t.Errorf("UnlockVault(correct) error = %v", err)
	}

	// Every method that decrypts must refuse to run on a locked vault.
	b.key = nil
	guardSecret, err := domain.NewSecret("any-project", "development", "API_KEY", "value", domain.SecretTypeAPIKey, "test")
	if err != nil {
		t.Fatalf("NewSecret() error = %v", err)
	}
	guards := map[string]func() error{
		"CreateSecret":         func() error { return b.CreateSecret(ctx, guardSecret) },
		"UpdateSecret":         func() error { return b.UpdateSecret(ctx, guardSecret) },
		"GetSecret":            func() error { _, err := b.GetSecret(ctx, "any", "development", "KEY"); return err },
		"GetSecretByID":        func() error { _, err := b.GetSecretByID(ctx, "any"); return err },
		"SearchSecrets":        func() error { _, err := b.SearchSecrets(ctx, "KEY"); return err },
		"SearchSecretMetadata": func() error { _, err := b.SearchSecretMetadata(ctx, "KEY"); return err },
		"ListSecretMetadata":   func() error { _, err := b.ListSecretMetadata(ctx, "any", "development"); return err },
		"ListSecrets":          func() error { _, err := b.ListSecrets(ctx, "any", "development"); return err },
		"CreateSecretVersion": func() error {
			return b.CreateSecretVersion(ctx, &domain.SecretVersion{
				ID: "x", SecretID: "y", Version: 1, CreatedAt: time.Now(), CreatedBy: "test",
			})
		},
		"GetSecretVersion":   func() error { _, err := b.GetSecretVersion(ctx, "y", 1); return err },
		"ListSecretVersions": func() error { _, err := b.ListSecretVersions(ctx, "y"); return err },
	}
	for name, guard := range guards {
		if err := guard(); err == nil || !strings.Contains(err.Error(), "not unlocked") {
			t.Errorf("%s() on locked vault error = %v, want 'vault not unlocked'", name, err)
		}
	}

	// Creating a vault on an initialized database stays refused while locked.
	if err := b.CreateVault(ctx, "another"); err == nil {
		t.Error("CreateVault() on initialized vault succeeded, want error")
	}

	// A corrupt stored salt surfaces a decode error rather than a
	// wrong-password error. (Must run last: it makes the vault unusable.)
	if _, err := b.db.ExecContext(ctx, `UPDATE vault_metadata SET salt = '!!!not-base64!!!'`); err != nil {
		t.Fatalf("corrupt salt error = %v", err)
	}
	if _, err := b.UnlockVault(ctx, testPassword); err == nil || !strings.Contains(err.Error(), "failed to decode salt") {
		t.Errorf("UnlockVault() with corrupt salt error = %v, want failed to decode salt", err)
	}
}

func TestProjectAndEnvironmentCRUD(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	b := newTestBackend(t, ctx)

	proj := mustProject(t, b, "envcrud")

	// GetProject by ID loads the environments.
	p, err := b.GetProject(ctx, proj.ID)
	if err != nil {
		t.Fatalf("GetProject() error = %v", err)
	}
	if p.Name != "envcrud" || len(p.Environments) != 3 {
		t.Errorf("GetProject() = %q/%d envs, want envcrud/3", p.Name, len(p.Environments))
	}
	if _, err := b.GetProject(ctx, "missing-id"); err == nil || !strings.Contains(err.Error(), "project not found") {
		t.Errorf("GetProject(missing) error = %v, want project not found", err)
	}

	byName, err := b.GetProjectByName(ctx, "envcrud")
	if err != nil {
		t.Fatalf("GetProjectByName() error = %v", err)
	}
	if byName.ID != proj.ID {
		t.Errorf("GetProjectByName() ID = %q, want %q", byName.ID, proj.ID)
	}
	if _, err := b.GetProjectByName(ctx, "missing-name"); err == nil || !strings.Contains(err.Error(), "project not found") {
		t.Errorf("GetProjectByName(missing) error = %v, want project not found", err)
	}

	// Duplicate project names are rejected.
	dup, err := domain.NewProject("envcrud", "", "test")
	if err != nil {
		t.Fatalf("NewProject(dup) error = %v", err)
	}
	if err := b.CreateProject(ctx, dup); err == nil || !strings.Contains(err.Error(), "failed to insert project") {
		t.Errorf("duplicate CreateProject() error = %v, want failed to insert project", err)
	}

	// UpdateProject persists description and timestamp.
	proj.Description = "updated description"
	proj.UpdatedAt = us(time.Now())
	if err := b.UpdateProject(ctx, proj); err != nil {
		t.Fatalf("UpdateProject() error = %v", err)
	}
	refetched, err := b.GetProjectByName(ctx, "envcrud")
	if err != nil {
		t.Fatalf("GetProjectByName() after update error = %v", err)
	}
	if refetched.Description != "updated description" {
		t.Errorf("description after update = %q, want %q", refetched.Description, "updated description")
	}

	// A config that cannot be marshalled surfaces the marshal error.
	proj.Config.Metadata = map[string]any{"bad": make(chan int)}
	if err := b.UpdateProject(ctx, proj); err == nil || !strings.Contains(err.Error(), "failed to marshal config") {
		t.Errorf("UpdateProject(bad config) error = %v, want failed to marshal config", err)
	}

	// Environment CRUD.
	env, err := b.GetEnvironment(ctx, proj.ID, "development")
	if err != nil {
		t.Fatalf("GetEnvironment(development) error = %v", err)
	}
	if env.Name != "development" || env.Type != domain.EnvDevelopment {
		t.Errorf("GetEnvironment() = %+v, want development", env)
	}
	if _, err := b.GetEnvironment(ctx, proj.ID, "nope"); err == nil || !strings.Contains(err.Error(), "environment not found") {
		t.Errorf("GetEnvironment(missing) error = %v, want environment not found", err)
	}

	envs, err := b.ListEnvironments(ctx, proj.ID)
	if err != nil {
		t.Fatalf("ListEnvironments() error = %v", err)
	}
	if len(envs) != 3 {
		t.Fatalf("len(ListEnvironments()) = %d, want 3", len(envs))
	}
	wantOrder := []string{"development", "production", "staging"}
	for i, e := range envs {
		if e.Name != wantOrder[i] {
			t.Errorf("ListEnvironments()[%d] = %q, want %q (ordered by name)", i, e.Name, wantOrder[i])
		}
	}

	qa := &domain.Environment{ID: domain.GenerateID(), Name: "qa", Type: domain.EnvCustom}
	if err := b.CreateEnvironment(ctx, proj.ID, qa); err != nil {
		t.Fatalf("CreateEnvironment() error = %v", err)
	}
	if envs, _ := b.ListEnvironments(ctx, proj.ID); len(envs) != 4 {
		t.Fatalf("len(ListEnvironments()) after create = %d, want 4", len(envs))
	}
	if got, err := b.GetEnvironment(ctx, proj.ID, "qa"); err != nil || got.ID != qa.ID {
		t.Errorf("GetEnvironment(qa) = %+v, %v; want %q, nil", got, err, qa.ID)
	}

	if err := b.DeleteEnvironment(ctx, proj.ID, qa.ID); err != nil {
		t.Fatalf("DeleteEnvironment() error = %v", err)
	}
	if _, err := b.GetEnvironment(ctx, proj.ID, "qa"); err == nil {
		t.Error("GetEnvironment(qa) after delete succeeded, want error")
	}
}

func TestSearchSecretsReturnsDecryptedValues(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	b := newTestBackend(t, ctx)

	seedProjectSecret(t, b, "searchdec", "development", "DATABASE_URL",
		"postgres://secret-host:5432/db", us(time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)))

	results, err := b.SearchSecrets(ctx, "DATABASE")
	if err != nil {
		t.Fatalf("SearchSecrets() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("len(SearchSecrets()) = %d, want 1", len(results))
	}
	if results[0].Value != "postgres://secret-host:5432/db" {
		t.Errorf("SearchSecrets() value = %q, want the decrypted plaintext", results[0].Value)
	}
	if results[0].Key != "DATABASE_URL" {
		t.Errorf("SearchSecrets() key = %q, want DATABASE_URL", results[0].Key)
	}
}

func TestDeleteSecretOfMissingRowIsNoop(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	b := newTestBackend(t, ctx)

	// Nothing to tombstone: the delete commits cleanly.
	if err := b.DeleteSecret(ctx, "no-such-secret"); err != nil {
		t.Fatalf("DeleteSecret(missing) error = %v", err)
	}
	tombstones, err := b.ListTombstones(ctx, "any", "development")
	if err != nil {
		t.Fatalf("ListTombstones() error = %v", err)
	}
	if len(tombstones) != 0 {
		t.Errorf("tombstones after deleting a missing secret = %d, want 0", len(tombstones))
	}
}

func TestTransactionCommitRollback(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	b := newTestBackend(t, ctx)

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
	t.Parallel()

	ctx := context.Background()
	b := newTestBackend(t, ctx)

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
		`SELECT COUNT(*) FROM secrets WHERE project_id = ?`, proj.ID).Scan(&count); err != nil {
		t.Fatalf("COUNT(secrets) error = %v", err)
	}
	if count != 0 {
		t.Errorf("secrets rows for deleted project = %d, want 0", count)
	}
}

// TestTimestampRoundTripPreservesInstants proves SQLite stores and returns
// the instant regardless of the writer's location (this machine runs IST;
// CI and servers run UTC) — the cross-backend counterpart of the Postgres
// zone-shift regression fixed in Stage B.
func TestTimestampRoundTripPreservesInstants(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	b := newTestBackend(t, ctx)

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
		key := "TS_" + strings.ToUpper(tc.name)
		secret, err := domain.NewSecret(proj.ID, "development", key, "v", domain.SecretTypeGeneric, "test")
		if err != nil {
			t.Fatalf("NewSecret(%s) error = %v", tc.name, err)
		}
		secret.CreatedAt = us(tc.when)
		secret.UpdatedAt = us(tc.when)
		secret.ExpiresAt = &deadline
		if err := b.CreateSecret(ctx, secret); err != nil {
			t.Fatalf("CreateSecret(%s) error = %v", tc.name, err)
		}

		got := getSecret(t, b, proj.ID, "development", key)
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
		got = getSecret(t, b, proj.ID, "development", key)
		if got.LastSyncedAt == nil || !got.LastSyncedAt.Equal(secret.UpdatedAt) {
			t.Errorf("%s: LastSyncedAt = %v, want %v",
				tc.name, got.LastSyncedAt, secret.UpdatedAt)
		}
	}
}

// TestSecretValueEncryptedAtRest verifies the value column never holds
// plaintext: what the driver sees is ciphertext, what GetSecret returns is
// the plaintext.
func TestSecretValueEncryptedAtRest(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	b := newTestBackend(t, ctx)

	const plaintext = "hunter2-plaintext-check"
	proj := mustProject(t, b, "atrest")
	secret := seedProjectSecret(t, b, "atrest", "development", "DB_PASS", plaintext, us(time.Now()))

	var raw []byte
	if err := b.db.QueryRowContext(ctx,
		`SELECT value FROM secrets WHERE id = ?`, secret.ID).Scan(&raw); err != nil {
		t.Fatalf("raw SELECT value error = %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("secrets.value is empty")
	}
	if bytes.Contains(raw, []byte(plaintext)) {
		t.Fatal("secrets.value contains plaintext; encryption at rest is broken")
	}

	if got := getSecret(t, b, proj.ID, "development", "DB_PASS"); got.Value != plaintext {
		t.Errorf("GetSecret() value = %q, want %q", got.Value, plaintext)
	}
}

// TestClosedDatabaseSurfacesErrors drives every backend method against a
// closed handle: each must report a wrapping error instead of panicking or
// silently succeeding. This covers the failure branches of the whole method
// surface in one pass.
func TestClosedDatabaseSurfacesErrors(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	b := newTestBackend(t, ctx)
	mustProject(t, b, "closed")

	if err := b.Health(ctx); err != nil {
		t.Fatalf("Health() before close error = %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	ops := map[string]func() error{
		"Health":        func() error { return b.Health(ctx) },
		"IsInitialized": func() error { _, err := b.IsInitialized(ctx); return err },
		"CreateVault":   func() error { return b.CreateVault(ctx, testPassword) },
		"UnlockVault":   func() error { _, err := b.UnlockVault(ctx, testPassword); return err },
		"BeginTx":       func() error { _, err := b.BeginTx(ctx); return err },
		"Export":        func() error { _, err := b.Export(ctx); return err },
		"Import":        func() error { return b.Import(ctx, []byte("{}")) },
		"CreateSecret": func() error {
			s, err := domain.NewSecret("p", "development", "K", "v", domain.SecretTypeGeneric, "test")
			if err != nil {
				return err
			}
			return b.CreateSecret(ctx, s)
		},
		"UpdateSecret": func() error {
			s, err := domain.NewSecret("p", "development", "K", "v", domain.SecretTypeGeneric, "test")
			if err != nil {
				return err
			}
			return b.UpdateSecret(ctx, s)
		},
		"GetSecret":            func() error { _, err := b.GetSecret(ctx, "p", "development", "K"); return err },
		"GetSecretByID":        func() error { _, err := b.GetSecretByID(ctx, "id"); return err },
		"SearchSecrets":        func() error { _, err := b.SearchSecrets(ctx, "K"); return err },
		"SearchSecretMetadata": func() error { _, err := b.SearchSecretMetadata(ctx, "K"); return err },
		"ListSecretMetadata":   func() error { _, err := b.ListSecretMetadata(ctx, "p", "development"); return err },
		"ListSecrets":          func() error { _, err := b.ListSecrets(ctx, "p", "development"); return err },
		"CreateSecretVersion": func() error {
			return b.CreateSecretVersion(ctx, &domain.SecretVersion{
				ID: "x", SecretID: "y", Version: 1, CreatedAt: time.Now(), CreatedBy: "test",
			})
		},
		"GetSecretVersion":   func() error { _, err := b.GetSecretVersion(ctx, "y", 1); return err },
		"ListSecretVersions": func() error { _, err := b.ListSecretVersions(ctx, "y"); return err },
		"MarkSynced":         func() error { return b.MarkSynced(ctx, "id", time.Now()) },
		"DeleteSecret":       func() error { return b.DeleteSecret(ctx, "id") },
		"GetTombstone":       func() error { _, err := b.GetTombstone(ctx, "p", "development", "K"); return err },
		"ListTombstones":     func() error { _, err := b.ListTombstones(ctx, "p", "development"); return err },
		"DeleteTombstone":    func() error { return b.DeleteTombstone(ctx, "p", "development", "K") },
		"CreateProject": func() error {
			p, err := domain.NewProject("closedproj", "", "test")
			if err != nil {
				return err
			}
			return b.CreateProject(ctx, p)
		},
		"GetProject":       func() error { _, err := b.GetProject(ctx, "id"); return err },
		"GetProjectByName": func() error { _, err := b.GetProjectByName(ctx, "closedproj"); return err },
		"ListProjects":     func() error { _, err := b.ListProjects(ctx); return err },
		"UpdateProject":    func() error { return b.UpdateProject(ctx, &domain.Project{ID: "id"}) },
		"DeleteProject":    func() error { return b.DeleteProject(ctx, "id") },
		"CreateEnvironment": func() error {
			return b.CreateEnvironment(ctx, "p", &domain.Environment{
				ID: "e", Name: "qa", Type: domain.EnvCustom,
			})
		},
		"GetEnvironment":    func() error { _, err := b.GetEnvironment(ctx, "p", "development"); return err },
		"ListEnvironments":  func() error { _, err := b.ListEnvironments(ctx, "p"); return err },
		"DeleteEnvironment": func() error { return b.DeleteEnvironment(ctx, "p", "e") },
		"RecordSyncRun": func() error {
			return b.RecordSyncRun(ctx, &domain.SyncRun{
				ID: domain.GenerateID(), StartedAt: time.Now(), Direction: "both",
				Strategy: "fail", Status: domain.SyncStatusInSync,
			})
		},
		"ListSyncRuns": func() error { _, err := b.ListSyncRuns(ctx, 5); return err },
	}

	for name, op := range ops {
		if err := op(); err == nil {
			t.Errorf("%s() on closed database succeeded, want error", name)
		}
	}
}

func TestCloseWithoutDatabase(t *testing.T) {
	t.Parallel()

	// A zero Backend (no database handle) must close cleanly.
	if err := (&Backend{}).Close(); err != nil {
		t.Errorf("Close() on zero Backend error = %v", err)
	}
}
