// Package roles provides helpers for selecting storage configurations by role.
//
// In this repository we distinguish between:
//   - Primary: the system-of-record database (intended to be SQLite).
//   - Backup: a local backup database/file (intended to be SQLite).
//   - Sync:   an optional remote sync target (intended to be Postgres).
//
// The actual config keys are owned by internal/config; this package focuses on
// role semantics and safe defaults that callers can use consistently.
package roles

import (
	"fmt"
	"path/filepath"

	"vault/internal/storage"
)

type Role string

const (
	RolePrimary Role = "primary"
	RoleBackup  Role = "backup"
	RoleSync    Role = "sync"
)

// DefaultSQLitePrimary returns a default SQLite config for primary storage.
// The caller should pass the project's data directory (e.g. ~/.local/share/vault).
func DefaultSQLitePrimary(dataDir string) *storage.Config {
	return &storage.Config{
		Type: "sqlite",
		Path: filepath.Join(dataDir, "vault.db"),
	}
}

// DefaultSQLiteBackup returns a default SQLite config for backup storage.
// The caller should pass the project's data directory (e.g. ~/.local/share/vault).
func DefaultSQLiteBackup(dataDir string) *storage.Config {
	return &storage.Config{
		Type: "sqlite",
		Path: filepath.Join(dataDir, "vault.backup.db"),
	}
}

// IsSQLite returns true if cfg is a SQLite config.
func IsSQLite(cfg *storage.Config) bool {
	return cfg != nil && cfg.Type == "sqlite"
}

// IsPostgres returns true if cfg is a Postgres config.
func IsPostgres(cfg *storage.Config) bool {
	return cfg != nil && cfg.Type == "postgres"
}

// ValidatePrimary enforces that the primary config is usable (and normally SQLite).
// This is intentionally strict because primary is your source of truth.
func ValidatePrimary(cfg *storage.Config) error {
	if cfg == nil {
		return fmt.Errorf("primary storage config is nil")
	}
	if cfg.Type == "" {
		return fmt.Errorf("primary storage type is required")
	}
	if cfg.Type != "sqlite" {
		return fmt.Errorf("primary storage must be sqlite (got %q)", cfg.Type)
	}
	if cfg.Path == "" {
		return fmt.Errorf("primary sqlite path is required")
	}
	return nil
}

// ValidateBackup enforces that the backup config is usable (and normally SQLite).
func ValidateBackup(cfg *storage.Config) error {
	if cfg == nil {
		return fmt.Errorf("backup storage config is nil")
	}
	if cfg.Type == "" {
		return fmt.Errorf("backup storage type is required")
	}
	if cfg.Type != "sqlite" {
		return fmt.Errorf("backup storage must be sqlite (got %q)", cfg.Type)
	}
	if cfg.Path == "" {
		return fmt.Errorf("backup sqlite path is required")
	}
	return nil
}

// ValidateSyncTarget validates that a sync target config is usable.
// Sync is optional: callers should treat nil as "sync disabled".
func ValidateSyncTarget(cfg *storage.Config) error {
	if cfg == nil {
		return fmt.Errorf("sync storage config is nil (sync disabled)")
	}
	if cfg.Type == "" {
		return fmt.Errorf("sync storage type is required")
	}
	if cfg.Type != "postgres" {
		return fmt.Errorf("sync storage must be postgres (got %q)", cfg.Type)
	}
	if cfg.Host == "" {
		return fmt.Errorf("sync postgres host is required")
	}
	if cfg.Port == 0 {
		return fmt.Errorf("sync postgres port is required")
	}
	if cfg.Database == "" {
		return fmt.Errorf("sync postgres database is required")
	}
	if cfg.User == "" {
		return fmt.Errorf("sync postgres user is required")
	}
	// Password may legitimately be empty if using other auth mechanisms, but this
	// codebase currently assumes password-based auth; keep it permissive here.
	if cfg.SSLMode == "" {
		return fmt.Errorf("sync postgres sslmode is required")
	}
	return nil
}

// SyncEnabled returns whether a sync target is configured.
func SyncEnabled(syncTarget *storage.Config) bool {
	// nil means disabled by design
	if syncTarget == nil {
		return false
	}
	// Treat any non-postgres as disabled; callers should still validate explicitly.
	return syncTarget.Type == "postgres"
}
