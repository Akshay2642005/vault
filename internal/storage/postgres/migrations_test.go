package postgres

import (
	"strings"
	"testing"
)

// TestMigrationsSequentialVersions guards the version-gated autoMigrate: every
// pre-existing vault only runs migrations with Version > its recorded version,
// so versions must be sequential from 1 and never renumbered in place.
func TestMigrationsSequentialVersions(t *testing.T) {
	for i, m := range migrations {
		if m.Version != i+1 {
			t.Fatalf("migrations[%d].Version = %d, want %d (versions must be sequential from 1)", i, m.Version, i+1)
		}
		if strings.TrimSpace(m.Description) == "" {
			t.Fatalf("migrations[%d] has empty description", i)
		}
		if strings.TrimSpace(m.SQL) == "" {
			t.Fatalf("migrations[%d] has empty SQL", i)
		}
	}
}

// TestSyncSchemaMigrationHealsV1Vaults ensures migration 2 re-creates the sync
// tables for vaults that recorded v1 before those tables existed. This is the
// regression guard for the live Supabase vault that was stuck at v1 missing
// secret_tombstones/sync_runs.
func TestSyncSchemaMigrationHealsV1Vaults(t *testing.T) {
	var v2 *Migration
	for i := range migrations {
		if migrations[i].Version == 2 {
			v2 = &migrations[i]
			break
		}
	}
	if v2 == nil {
		t.Fatal("migration 2 missing: sync schema healing migration was removed")
	}
	if !strings.Contains(v2.Description, "secret_tombstones") || !strings.Contains(v2.Description, "sync_runs") {
		t.Fatalf("migration 2 description does not mention sync tables: %q", v2.Description)
	}
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS secret_tombstones",
		"CREATE TABLE IF NOT EXISTS sync_runs",
		"idx_sync_runs_started",
	} {
		if !strings.Contains(v2.SQL, want) {
			t.Fatalf("migration 2 SQL missing %q", want)
		}
	}
}
