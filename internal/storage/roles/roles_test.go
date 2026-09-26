package roles

import (
	"path/filepath"
	"strings"
	"testing"

	"vault/internal/storage"
)

func TestDefaultSQLiteConfigs(t *testing.T) {
	t.Parallel()

	primary := DefaultSQLitePrimary("/data")
	if primary.Type != "sqlite" {
		t.Fatalf("primary Type = %q, want sqlite", primary.Type)
	}
	if want := filepath.Join("/data", "vault.db"); primary.Path != want {
		t.Fatalf("primary Path = %q, want %q", primary.Path, want)
	}

	backup := DefaultSQLiteBackup("/data")
	if backup.Type != "sqlite" {
		t.Fatalf("backup Type = %q, want sqlite", backup.Type)
	}
	if want := filepath.Join("/data", "vault.backup.db"); backup.Path != want {
		t.Fatalf("backup Path = %q, want %q", backup.Path, want)
	}
}

func TestIsSQLiteAndIsPostgres(t *testing.T) {
	t.Parallel()

	sqlite := &storage.Config{Type: "sqlite"}
	postgres := &storage.Config{Type: "postgres"}

	if IsSQLite(nil) {
		t.Fatal("IsSQLite(nil) = true, want false")
	}
	if !IsSQLite(sqlite) {
		t.Fatal("IsSQLite(sqlite) = false, want true")
	}
	if IsSQLite(postgres) {
		t.Fatal("IsSQLite(postgres) = true, want false")
	}

	if IsPostgres(nil) {
		t.Fatal("IsPostgres(nil) = true, want false")
	}
	if !IsPostgres(postgres) {
		t.Fatal("IsPostgres(postgres) = false, want true")
	}
	if IsPostgres(sqlite) {
		t.Fatal("IsPostgres(sqlite) = true, want false")
	}
}

func TestValidatePrimary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     *storage.Config
		wantErr string
	}{
		{"nil", nil, "nil"},
		{"empty type", &storage.Config{}, "type is required"},
		{"non-sqlite", &storage.Config{Type: "postgres", Host: "h"}, "must be sqlite"},
		{"missing path", &storage.Config{Type: "sqlite"}, "path is required"},
		{"valid", &storage.Config{Type: "sqlite", Path: "/tmp/v.db"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePrimary(tt.cfg)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidatePrimary() error = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ValidatePrimary() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateBackup(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     *storage.Config
		wantErr string
	}{
		{"nil", nil, "nil"},
		{"empty type", &storage.Config{}, "type is required"},
		{"non-sqlite", &storage.Config{Type: "postgres"}, "must be sqlite"},
		{"missing path", &storage.Config{Type: "sqlite"}, "path is required"},
		{"valid", &storage.Config{Type: "sqlite", Path: "/tmp/b.db"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBackup(tt.cfg)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateBackup() error = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ValidateBackup() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func validSyncConfig() *storage.Config {
	return &storage.Config{
		Type:     "postgres",
		Host:     "db.example.com",
		Port:     5432,
		Database: "postgres",
		User:     "vault",
		Password: "secret",
		SSLMode:  "require",
	}
}

func TestValidateSyncTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(*storage.Config)
		nilCfg  bool
		wantErr string
	}{
		{name: "nil", nilCfg: true, wantErr: "sync disabled"},
		{name: "empty type", mutate: func(c *storage.Config) { c.Type = "" }, wantErr: "type is required"},
		{name: "non-postgres", mutate: func(c *storage.Config) { c.Type = "sqlite" }, wantErr: "must be postgres"},
		{name: "missing host", mutate: func(c *storage.Config) { c.Host = "" }, wantErr: "host is required"},
		{name: "missing port", mutate: func(c *storage.Config) { c.Port = 0 }, wantErr: "port is required"},
		{name: "missing database", mutate: func(c *storage.Config) { c.Database = "" }, wantErr: "database is required"},
		{name: "missing user", mutate: func(c *storage.Config) { c.User = "" }, wantErr: "user is required"},
		{name: "missing sslmode", mutate: func(c *storage.Config) { c.SSLMode = "" }, wantErr: "sslmode is required"},
		{name: "valid", mutate: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validSyncConfig()
			var input *storage.Config
			if tt.nilCfg {
				input = nil
			} else {
				if tt.mutate != nil {
					tt.mutate(cfg)
				}
				input = cfg
			}
			err := ValidateSyncTarget(input)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateSyncTarget() error = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ValidateSyncTarget() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateSyncTargetAllowsEmptyPassword(t *testing.T) {
	t.Parallel()

	cfg := validSyncConfig()
	cfg.Password = ""
	if err := ValidateSyncTarget(cfg); err != nil {
		t.Fatalf("ValidateSyncTarget(empty password) error = %v, want nil (permissive by design)", err)
	}
}

func TestSyncEnabled(t *testing.T) {
	t.Parallel()

	if SyncEnabled(nil) {
		t.Fatal("SyncEnabled(nil) = true, want false")
	}
	if !SyncEnabled(&storage.Config{Type: "postgres"}) {
		t.Fatal("SyncEnabled(postgres) = false, want true")
	}
	if SyncEnabled(&storage.Config{Type: "sqlite"}) {
		t.Fatal("SyncEnabled(sqlite) = true, want false")
	}
}
