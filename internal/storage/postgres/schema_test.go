package postgres

// Stage B3/B4: live schema tests.
//
//   - TestSchemaMatchesSQLite asserts the Postgres schema is column-for-column
//     identical to the SQLite schema (the migration contract is "matches
//     SQLite structure exactly"), plus the Postgres-only type/index
//     expectations (bytea values, timestamp columns, boolean flags,
//     idx_sync_runs_started).
//   - TestSyncSchemaHealsLiveV1Vault drops the sync tables, rewinds
//     schema_version to 1, re-opens the backend and asserts migration 2
//     re-creates everything while existing vault data survives — the live
//     version of the SQL-text regression guards in migrations_test.go.

import (
	"context"
	"database/sql"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"vault/internal/domain"
	"vault/internal/storage"
	"vault/internal/storage/sqlite"
)

// sharedTables are the tables both backends define with the same column names.
var sharedTables = []string{
	"vault_metadata",
	"projects",
	"environments",
	"secrets",
	"secret_versions",
	"secret_tombstones",
	"sync_runs",
}

// openSchemaSQLite creates a temporary SQLite database with the production
// schema and returns a raw connection for PRAGMA introspection. Skips when the
// sqlite_fts5 build tag (or cgo) is unavailable.
func openSchemaSQLite(t *testing.T) *sql.DB {
	t.Helper()

	path := filepath.Join(t.TempDir(), "parity.db")
	cfg := &storage.Config{Type: "sqlite", Path: path}

	b, err := sqlite.New(cfg)
	if err != nil {
		t.Skipf("sqlite unavailable (requires cgo): %v", err)
	}
	defer b.Close()

	if err := b.Initialize(context.Background(), cfg); err != nil {
		msg := err.Error()
		if strings.Contains(msg, "requires cgo") ||
			strings.Contains(msg, "fts5") ||
			strings.Contains(msg, "no such module") {
			t.Skipf("sqlite schema unavailable (run with -tags sqlite_fts5): %v", err)
		}
		t.Fatalf("sqlite Initialize() error = %v", err)
	}

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatalf("sql.Open(sqlite3) error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// sqliteColumns returns the column names of a table via PRAGMA table_info.
func sqliteColumns(t *testing.T, db *sql.DB, table string) []string {
	t.Helper()

	// PRAGMA does not support bound parameters; table is a test constant.
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		t.Fatalf("PRAGMA table_info(%s) error = %v", table, err)
	}
	defer rows.Close()

	var cols []string
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dflt, &pk); err != nil {
			t.Fatalf("scan PRAGMA table_info(%s) error = %v", table, err)
		}
		cols = append(cols, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate PRAGMA table_info(%s) error = %v", table, err)
	}
	if len(cols) == 0 {
		t.Fatalf("sqlite table %q has no columns (schema not created?)", table)
	}
	return cols
}

// pgColumns returns the column names of a table via information_schema.
func pgColumns(t *testing.T, b *Backend, table string) []string {
	t.Helper()

	rows, err := b.db.QueryContext(context.Background(), `
		SELECT column_name
		FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = $1
		ORDER BY ordinal_position
	`, table)
	if err != nil {
		t.Fatalf("information_schema.columns(%s) error = %v", table, err)
	}
	defer rows.Close()

	var cols []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan information_schema.columns(%s) error = %v", table, err)
		}
		cols = append(cols, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate information_schema.columns(%s) error = %v", table, err)
	}
	if len(cols) == 0 {
		t.Fatalf("postgres table %q has no columns", table)
	}
	return cols
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func TestSchemaMatchesSQLite(t *testing.T) {
	sq := openSchemaSQLite(t)
	pg := newTestBackend(t)

	for _, table := range sharedTables {
		want := sortedCopy(sqliteColumns(t, sq, table))
		got := sortedCopy(pgColumns(t, pg, table))

		if strings.Join(want, ",") != strings.Join(got, ",") {
			t.Errorf("table %q columns:\n  sqlite:    %v\n  postgres:  %v", table, want, got)
		}
	}
}

// TestPostgresTypeAndIndexExpectations pins the dialect-specific types and the
// sync indexes that the sync engine depends on.
func TestPostgresTypeAndIndexExpectations(t *testing.T) {
	pg := newTestBackend(t)
	ctx := context.Background()

	typeExpectations := []struct {
		table, column, dataType string
	}{
		{"secrets", "value", "bytea"}, // encrypted at rest
		{"secrets", "updated_at", "timestamp without time zone"},
		{"secrets", "last_synced_at", "timestamp without time zone"},
		{"secret_tombstones", "deleted_at", "timestamp without time zone"},
		{"sync_runs", "started_at", "timestamp without time zone"},
		{"sync_runs", "dry_run", "boolean"},
		{"sync_runs", "pushed", "integer"},
		{"sync_runs", "conflicts", "integer"},
	}
	for _, tc := range typeExpectations {
		var got string
		err := pg.db.QueryRowContext(ctx, `
			SELECT data_type
			FROM information_schema.columns
			WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2
		`, tc.table, tc.column).Scan(&got)
		if err != nil {
			t.Fatalf("data_type(%s.%s) error = %v", tc.table, tc.column, err)
		}
		if got != tc.dataType {
			t.Errorf("data_type(%s.%s) = %q, want %q", tc.table, tc.column, got, tc.dataType)
		}
	}

	indexes := []string{
		"idx_sync_runs_started",
		"idx_secrets_project",
		"idx_secrets_updated",
		"idx_secret_versions_secret",
	}
	for _, idx := range indexes {
		var name string
		err := pg.db.QueryRowContext(ctx,
			`SELECT indexname FROM pg_indexes WHERE schemaname = 'public' AND indexname = $1`,
			idx).Scan(&name)
		if err != nil {
			t.Errorf("pg index %q missing: %v", idx, err)
		}
	}

	// The sync-run history must be ordered newest-first by the planner's
	// preferred index.
	var idxDef string
	if err := pg.db.QueryRowContext(ctx,
		`SELECT indexdef FROM pg_indexes WHERE schemaname = 'public' AND indexname = 'idx_sync_runs_started'`,
	).Scan(&idxDef); err != nil {
		t.Fatalf("idx_sync_runs_started definition error = %v", err)
	}
	if !strings.Contains(idxDef, "started_at DESC") {
		t.Errorf("idx_sync_runs_started = %q, want started_at DESC", idxDef)
	}
}

func mustExec(t *testing.T, b *Backend, query string, args ...any) {
	t.Helper()
	if _, err := b.db.ExecContext(context.Background(), query, args...); err != nil {
		t.Fatalf("exec %q error = %v", query, err)
	}
}

// TestSyncSchemaHealsLiveV1Vault simulates a vault whose sync tables are
// missing (the pre-fix migration-1-only state) and asserts that re-opening the
// backend applies migration 2 without touching existing vault data.
func TestSyncSchemaHealsLiveV1Vault(t *testing.T) {
	b := newUnlockedBackend(t) // migrations 1 + 2 applied, vault unlocked
	ctx := context.Background()

	// Data that must survive the heal.
	proj := mustProject(t, b, "healproj")
	keep := seedProjectSecret(t, b, "healproj", "development", "KEEP_ME", "value-1", us(time.Now()))

	// Rewind to the broken v1 state.
	mustExec(t, b, `DROP TABLE secret_tombstones`)
	mustExec(t, b, `DROP TABLE sync_runs`)
	mustExec(t, b, `DELETE FROM schema_version WHERE version = 2`)

	// Re-open: autoMigrate must notice version 1 and apply migration 2.
	cfg := testConfig(t)
	b2, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = b2.Close() })
	if err := b2.Initialize(ctx, cfg); err != nil {
		t.Fatalf("Initialize() on healed vault error = %v", err)
	}
	if _, err := b2.UnlockVault(ctx, testPassword); err != nil {
		t.Fatalf("UnlockVault() after heal error = %v", err)
	}

	// Migration bookkeeping: both versions recorded exactly once.
	var count int
	if err := b2.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM schema_version WHERE version IN (1, 2)`).Scan(&count); err != nil {
		t.Fatalf("COUNT(schema_version) error = %v", err)
	}
	if count != 2 {
		t.Errorf("schema_version rows for (1,2) = %d, want 2", count)
	}

	// Tables recreated with the expected columns.
	for _, table := range []string{"secret_tombstones", "sync_runs"} {
		if cols := pgColumns(t, b2, table); len(cols) == 0 {
			t.Errorf("table %q not recreated after heal", table)
		}
	}

	// Existing vault data untouched.
	if _, err := b2.GetProjectByName(ctx, "healproj"); err != nil {
		t.Errorf("GetProjectByName(healproj) after heal error = %v", err)
	}
	got := getSecret(t, b2, proj.ID, "development", "KEEP_ME")
	if got.Value != keep.Value {
		t.Errorf("secret value after heal = %q, want %q", got.Value, keep.Value)
	}

	// Functional: sync observability works on the healed schema.
	now := us(time.Now())
	run := &domain.SyncRun{
		ID:         domain.GenerateID(),
		StartedAt:  now,
		FinishedAt: now,
		Direction:  "both",
		Strategy:   "fail",
		Status:     domain.SyncStatusInSync,
	}
	if err := b2.RecordSyncRun(ctx, run); err != nil {
		t.Fatalf("RecordSyncRun() after heal error = %v", err)
	}
	runs, err := b2.ListSyncRuns(ctx, 10)
	if err != nil {
		t.Fatalf("ListSyncRuns() after heal error = %v", err)
	}
	if len(runs) != 1 {
		t.Errorf("len(ListSyncRuns()) after heal = %d, want 1", len(runs))
	}

	// Functional: deletions record tombstones on the healed schema.
	victim := seedProjectSecret(t, b2, "healproj", "development", "DELETE_ME", "value-2", us(time.Now()))
	if err := b2.DeleteSecret(ctx, victim.ID); err != nil {
		t.Fatalf("DeleteSecret() after heal error = %v", err)
	}
	var tombstones int
	if err := b2.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM secret_tombstones
		WHERE project_id = $1 AND environment = 'development' AND key = 'DELETE_ME'
	`, proj.ID).Scan(&tombstones); err != nil {
		t.Fatalf("COUNT(secret_tombstones) error = %v", err)
	}
	if tombstones != 1 {
		t.Errorf("tombstone rows = %d, want 1", tombstones)
	}
}
