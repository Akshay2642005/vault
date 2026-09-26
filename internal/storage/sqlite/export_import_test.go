package sqlite

// Export/import round trips: a vault dump carries the salt, auth hash, and
// still-encrypted values, so it must restore into a fresh backend and unlock
// with the same master password, with byte-identical plaintext after
// decryption. The error branches cover the pre-flight rejections (no vault,
// no database, malformed dump, future schema).

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"vault/internal/crypto"
)

func TestExportImportRoundTrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	src := newTestBackend(t, ctx)

	// Seed a non-trivial vault: two environments, a version bump, tags,
	// pinned timestamps.
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

	// Restore into a fresh backend (schema present, own vault wiped by import).
	dst := newTestBackend(t, ctx)
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
	if !got.CreatedAt.Equal(t1) {
		t.Errorf("API_KEY CreatedAt after import = %v, want %v", got.CreatedAt, t1)
	}

	prod := getSecret(t, dst, dstProj.ID, "production", "DB_PASSWORD")
	if prod.Value != "prod-value" {
		t.Errorf("DB_PASSWORD value after import = %q, want prod-value", prod.Value)
	}

	// Version history survives alongside the bumped current version.
	versions, err := dst.ListSecretVersions(ctx, keep.ID)
	if err != nil {
		t.Fatalf("ListSecretVersions() error = %v", err)
	}
	if len(versions) != 1 {
		t.Fatalf("len(ListSecretVersions()) after import = %d, want 1", len(versions))
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

	// The dump must never leak plaintext: the value stays ciphertext at rest.
	var raw []byte
	if err := dst.db.QueryRowContext(ctx,
		`SELECT value FROM secrets WHERE id = ?`, keep.ID).Scan(&raw); err != nil {
		t.Fatalf("raw SELECT value error = %v", err)
	}
	if bytes.Contains(raw, []byte("round-trip-updated")) {
		t.Error("imported value stored as plaintext; encryption at rest lost in the round trip")
	}
}

func TestExportRequiresVault(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// Schema exists but no vault row yet.
	raw := newRawBackend(t, ctx)
	if _, err := raw.Export(ctx); err == nil || !strings.Contains(err.Error(), "vault not initialized") {
		t.Errorf("Export() without vault error = %v, want vault not initialized", err)
	}

	// No database handle at all.
	bare := &Backend{}
	if _, err := bare.Export(ctx); err == nil || !strings.Contains(err.Error(), "database not initialized") {
		t.Errorf("Export() without database error = %v, want database not initialized", err)
	}
	if err := bare.Import(ctx, []byte("{}")); err == nil || !strings.Contains(err.Error(), "database not initialized") {
		t.Errorf("Import() without database error = %v, want database not initialized", err)
	}
}

func TestImportRejectsInvalidData(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	b := newTestBackend(t, ctx)

	if err := b.Import(ctx, []byte("{not json")); err == nil || !strings.Contains(err.Error(), "failed to parse vault data") {
		t.Errorf("Import(malformed) error = %v, want failed to parse vault data", err)
	}

	future := `{"schema_version":999,"salt":"","auth_hash":"","projects":[]}`
	if err := b.Import(ctx, []byte(future)); err == nil || !strings.Contains(err.Error(), "unsupported vault schema version") {
		t.Errorf("Import(future schema) error = %v, want unsupported vault schema version", err)
	}
}
