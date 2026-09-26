package postgres

// Stage B7: export/import round trips.
//
// A vault dump carries the salt, auth hash, and still-encrypted values, so it
// must restore into a fresh backend and unlock with the same master password,
// with byte-identical plaintext after decryption. The reverse direction
// (SQLite dump → Postgres restore) proves the dump format is backend-neutral.

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vault/internal/crypto"
	"vault/internal/storage"
	"vault/internal/storage/sqlite"
)

func TestExportImportRoundTripBetweenPostgresVaults(t *testing.T) {
	ctx := context.Background()

	src := newUnlockedBackend(t)

	// Seed a non-trivial vault: two projects, a version bump, tags, pinned
	// timestamps.
	t1 := us(time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC))
	keep := seedProjectSecret(t, src, "export-src", "development", "API_KEY", "round-trip-value", t1)
	keep.Tags = []string{"tier", "core"}
	keep.Value = "round-trip-updated"
	keep.Checksum = crypto.Hash([]byte("round-trip-updated"))
	keep.UpdatedAt = us(t1.Add(time.Hour))
	if err := src.UpdateSecret(ctx, keep); err != nil {
		t.Fatalf("UpdateSecret() error = %v", err)
	}
	seedProjectSecret(t, src, "export-src", "production", "DB_PASSWORD", "prod-value", t1)
	mustProject(t, src, "export-dst")

	dump, err := src.Export(ctx)
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}
	if len(dump) == 0 {
		t.Fatal("Export() returned empty dump")
	}

	// Restore into a fresh backend (schema present, no vault yet).
	dst := newTestBackend(t)
	if err := dst.Import(ctx, dump); err != nil {
		t.Fatalf("Import() error = %v", err)
	}

	init, err := dst.IsInitialized(ctx)
	if err != nil || !init {
		t.Fatalf("IsInitialized() after import = %v, %v; want true, nil", init, err)
	}

	// The imported auth hash guards the vault: wrong password rejected.
	if _, err := dst.UnlockVault(ctx, "wrong-password"); err == nil {
		t.Error("UnlockVault(wrong) on imported vault succeeded, want error")
	}
	if _, err := dst.UnlockVault(ctx, testPassword); err != nil {
		t.Fatalf("UnlockVault(correct) on imported vault error = %v", err)
	}

	// Every secret must come back with identical plaintext and metadata.
	dstProj := mustProject(t, dst, "export-src")
	got := getSecret(t, dst, dstProj.ID, "development", "API_KEY")
	if got.Value != "round-trip-updated" {
		t.Errorf("API_KEY value after import = %q, want round-trip-updated", got.Value)
	}
	if got.Version != 2 {
		t.Errorf("API_KEY version after import = %d, want 2", got.Version)
	}
	if len(got.Tags) != 2 || got.Tags[0] != "tier" || got.Tags[1] != "core" {
		t.Errorf("API_KEY tags after import = %v, want [tier core]", got.Tags)
	}
	if !got.UpdatedAt.Equal(keep.UpdatedAt) {
		t.Errorf("API_KEY UpdatedAt after import = %v, want %v", got.UpdatedAt, keep.UpdatedAt)
	}

	prod := getSecret(t, dst, dstProj.ID, "production", "DB_PASSWORD")
	if prod.Value != "prod-value" {
		t.Errorf("DB_PASSWORD value after import = %q, want prod-value", prod.Value)
	}

	// Version 1 must survive alongside the bumped current version.
	versions, err := dst.ListSecretVersions(ctx, keep.ID)
	if err != nil {
		t.Fatalf("ListSecretVersions() error = %v", err)
	}
	if len(versions) == 0 {
		t.Fatal("no secret versions after import")
	}
	v1, err := dst.GetSecretVersion(ctx, keep.ID, 1)
	if err != nil {
		t.Fatalf("GetSecretVersion(1) error = %v", err)
	}
	if v1.Value != "round-trip-value" {
		t.Errorf("version 1 value after import = %q, want round-trip-value", v1.Value)
	}

	// The untouched sibling project must exist with its three environments.
	dstDst, err := dst.GetProjectByName(ctx, "export-dst")
	if err != nil {
		t.Fatalf("GetProjectByName(export-dst) after import error = %v", err)
	}
	if len(dstDst.Environments) != 3 {
		t.Errorf("export-dst environments = %d, want 3", len(dstDst.Environments))
	}
	// A second export must describe the restored vault.
	dump2, err := dst.Export(ctx)
	if err != nil {
		t.Fatalf("Export() after import error = %v", err)
	}
	if len(dump2) == 0 {
		t.Fatal("Export() after import returned empty dump")
	}
}

// TestExportImportCrossBackendFromSQLite proves the dump format is
// backend-neutral: a SQLite dump restores into Postgres and unlocks with the
// same master password.
func TestExportImportCrossBackendFromSQLite(t *testing.T) {
	ctx := context.Background()

	// Source: SQLite vault with the same schema and master password.
	cfg := &storage.Config{Type: "sqlite", Path: filepath.Join(t.TempDir(), "vault.db")}
	src, err := sqlite.New(cfg)
	if err != nil {
		t.Skipf("sqlite unavailable (requires cgo): %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })
	if err := src.Initialize(ctx, cfg); err != nil {
		msg := err.Error()
		if strings.Contains(msg, "requires cgo") ||
			strings.Contains(msg, "fts5") ||
			strings.Contains(msg, "no such module") {
			t.Skipf("sqlite unavailable (run with -tags sqlite_fts5): %v", err)
		}
		t.Fatalf("sqlite Initialize() error = %v", err)
	}
	if err := src.CreateVault(ctx, testPassword); err != nil {
		t.Fatalf("sqlite CreateVault() error = %v", err)
	}

	engineSeed(t, src, "crossdb", "development", "CROSS_KEY", "from-sqlite",
		us(time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)))

	dump, err := src.Export(ctx)
	if err != nil {
		t.Fatalf("sqlite Export() error = %v", err)
	}

	// Destination: fresh Postgres backend.
	dst := newTestBackend(t)
	if err := dst.Import(ctx, dump); err != nil {
		t.Fatalf("Import() into postgres error = %v", err)
	}
	if _, err := dst.UnlockVault(ctx, testPassword); err != nil {
		t.Fatalf("UnlockVault() on cross-imported vault error = %v", err)
	}

	got := getSecret(t, dst, mustProject(t, dst, "crossdb").ID, "development", "CROSS_KEY")
	if got.Value != "from-sqlite" {
		t.Errorf("CROSS_KEY value after cross-import = %q, want from-sqlite", got.Value)
	}

	// The dump must never leak plaintext: the value stays ciphertext at rest.
	var raw []byte
	if err := dst.db.QueryRowContext(ctx,
		`SELECT value FROM secrets WHERE key = 'CROSS_KEY'`).Scan(&raw); err != nil {
		t.Fatalf("raw SELECT value error = %v", err)
	}
	if strings.Contains(string(raw), "from-sqlite") {
		t.Error("imported value stored as plaintext; encryption at rest lost in transit")
	}
}
