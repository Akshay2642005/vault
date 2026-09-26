package config

// Config tests manage two pieces of package-global state: the viper instance
// mutated by Init and the `cfg` pointer read by every getter. resetConfig
// clears both before and after each test, and tests never run in parallel
// (t.Setenv forbids it, and the globals forbid it anyway).

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/viper"

	"vault/internal/storage"
)

func resetConfig(t *testing.T) {
	t.Helper()
	viper.Reset()
	cfg = nil
	t.Cleanup(func() {
		viper.Reset()
		cfg = nil
	})
}

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write config error = %v", err)
	}
	return path
}

func TestVersion(t *testing.T) {
	if Version != "0.1.0" {
		t.Errorf("Version = %q, want 0.1.0", Version)
	}
}

func TestInitFromFile(t *testing.T) {
	resetConfig(t)
	t.Setenv("HOME", t.TempDir())

	path := writeConfig(t, `
storage:
  primary:
    type: sqlite
    path: /tmp/primary.db
  backup:
    type: sqlite
    path: /tmp/backup.db
  sync:
    postgres:
      host: db.example.com
      port: 6543
      database: vaultdb
      user: vault
      password: hunter2
      sslmode: require
crypto:
  argon2_time: 5
  argon2_memory: 131072
  argon2_threads: 2
  argon2_key_length: 64
`)
	if err := Init(path); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	primary := GetPrimaryStorageConfig()
	if primary.Type != "sqlite" || primary.Path != "/tmp/primary.db" {
		t.Errorf("primary = %+v, want sqlite:/tmp/primary.db", primary)
	}

	backup := GetBackupStorageConfig()
	if backup.Type != "sqlite" || backup.Path != "/tmp/backup.db" {
		t.Errorf("backup = %+v, want sqlite:/tmp/backup.db", backup)
	}

	sync := GetSyncStorageConfig()
	if sync == nil {
		t.Fatal("GetSyncStorageConfig() = nil, want the configured target")
	}
	if sync.Type != "postgres" || sync.Host != "db.example.com" || sync.Port != 6543 ||
		sync.Database != "vaultdb" || sync.User != "vault" ||
		sync.Password != "hunter2" || sync.SSLMode != "require" {
		t.Errorf("sync = %+v, want the configured postgres target", sync)
	}

	crypto := GetCryptoConfig()
	if crypto.Argon2Time != 5 || crypto.Argon2Memory != 131072 ||
		crypto.Argon2Threads != 2 || crypto.Argon2KeyLength != 64 {
		t.Errorf("crypto = %+v, want the configured argon2 parameters", crypto)
	}

	// GetStorageConfig is the legacy alias for the primary config.
	if got := GetStorageConfig(); !reflect.DeepEqual(got, primary) {
		t.Errorf("GetStorageConfig() = %+v, want %+v", got, primary)
	}
}

func TestInitLegacyFlatStorageConfig(t *testing.T) {
	resetConfig(t)
	t.Setenv("HOME", t.TempDir())

	// Pre-role configs stored storage.type/storage.path at the top level;
	// those keys must keep winning as the primary configuration.
	path := writeConfig(t, `
storage:
  type: postgres
  path: /tmp/legacy.db
  host: legacy-host
  port: 5433
  database: legacydb
  user: legacyuser
  password: legacypass
  sslmode: require
`)
	if err := Init(path); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	primary := GetPrimaryStorageConfig()
	if primary.Type != "postgres" || primary.Path != "/tmp/legacy.db" ||
		primary.Host != "legacy-host" || primary.Port != 5433 ||
		primary.Database != "legacydb" || primary.User != "legacyuser" ||
		primary.Password != "legacypass" || primary.SSLMode != "require" {
		t.Errorf("legacy primary = %+v, want the flat storage.* values", primary)
	}
}

func TestInitMissingConfigFileIsAnError(t *testing.T) {
	resetConfig(t)

	err := Init(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Fatal("Init(explicit missing file) error = nil, want error")
	}
	if !strings.Contains(err.Error(), "failed to read config") {
		t.Errorf("error = %v, want failed to read config", err)
	}
}

func TestInitInvalidYAMLIsAnError(t *testing.T) {
	resetConfig(t)

	err := Init(writeConfig(t, "storage: [unclosed"))
	if err == nil {
		t.Fatal("Init(invalid yaml) error = nil, want error")
	}
	if !strings.Contains(err.Error(), "failed to read config") {
		t.Errorf("error = %v, want failed to read config", err)
	}
}

func TestInitWithoutHomeDirectoryIsAnError(t *testing.T) {
	resetConfig(t)
	t.Setenv("HOME", "")

	err := Init("")
	if err == nil {
		t.Fatal("Init(\"\") without HOME error = nil, want error")
	}
	if !strings.Contains(err.Error(), "failed to get home directory") {
		t.Errorf("error = %v, want failed to get home directory", err)
	}
}

func TestInitSearchFallsBackToDefaults(t *testing.T) {
	resetConfig(t)
	home := t.TempDir()
	t.Setenv("HOME", home)

	// No config file anywhere the search looks: Init must succeed on
	// defaults (ConfigFileNotFoundError is not fatal).
	if err := Init(""); err != nil {
		t.Fatalf("Init(\"\") error = %v", err)
	}

	primary := GetPrimaryStorageConfig()
	wantPrimary := filepath.Join(home, ".local", "share", "vault", "vault.db")
	if primary.Type != "sqlite" || primary.Path != wantPrimary {
		t.Errorf("primary = %+v, want sqlite at %s", primary, wantPrimary)
	}

	backup := GetBackupStorageConfig()
	wantBackup := filepath.Join(home, ".local", "share", "vault", "vault.backup.db")
	if backup.Type != "sqlite" || backup.Path != wantBackup {
		t.Errorf("backup = %+v, want sqlite at %s", backup, wantBackup)
	}

	if sync := GetSyncStorageConfig(); sync != nil {
		t.Errorf("GetSyncStorageConfig() = %+v, want nil (sync not configured)", sync)
	}

	crypto := GetCryptoConfig()
	if crypto.Argon2Time != 3 || crypto.Argon2Memory != 65536 ||
		crypto.Argon2Threads != 4 || crypto.Argon2KeyLength != 32 {
		t.Errorf("crypto defaults = %+v, want 3/65536/4/32", crypto)
	}
}

func TestGetPrimaryStorageConfigDefaultsWithoutCfg(t *testing.T) {
	resetConfig(t)
	home := t.TempDir()
	t.Setenv("HOME", home)

	// cfg == nil (Init never ran): the getters still produce usable defaults.
	got := GetPrimaryStorageConfig()
	wantPath := filepath.Join(home, ".local", "share", "vault", "vault.db")
	if got.Type != "sqlite" || got.Path != wantPath {
		t.Errorf("primary = %+v, want sqlite at %s", got, wantPath)
	}
	if alias := GetStorageConfig(); !reflect.DeepEqual(alias, got) {
		t.Errorf("GetStorageConfig() = %+v, want %+v", alias, got)
	}
}

func TestGetPrimaryStorageConfigLegacyFallbacks(t *testing.T) {
	resetConfig(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	wantPath := filepath.Join(home, ".local", "share", "vault", "vault.db")

	// Legacy type without path: path falls back to the default location.
	cfg = &Config{Storage: StorageRootConfig{Type: "postgres", Host: "legacy-host"}}
	got := GetPrimaryStorageConfig()
	if got.Type != "postgres" || got.Host != "legacy-host" {
		t.Errorf("primary = %+v, want postgres with legacy host", got)
	}
	if got.Path != wantPath {
		t.Errorf("primary path = %q, want default %q", got.Path, wantPath)
	}

	// Legacy path without type: type falls back to sqlite.
	cfg = &Config{Storage: StorageRootConfig{Path: "/custom/x.db"}}
	got = GetPrimaryStorageConfig()
	if got.Type != "sqlite" || got.Path != "/custom/x.db" {
		t.Errorf("primary = %+v, want sqlite at /custom/x.db", got)
	}
}

func TestGetPrimaryStorageConfigFromSection(t *testing.T) {
	resetConfig(t)

	cfg = &Config{Storage: StorageRootConfig{Primary: StorageSectionConfig{
		Type: "sqlite", Path: "/p.db", Host: "ph", Port: 1,
		Database: "pdb", User: "pu", Password: "pp", SSLMode: "require",
	}}}

	got := GetPrimaryStorageConfig()
	want := &storage.Config{
		Type: "sqlite", Path: "/p.db", Host: "ph", Port: 1,
		Database: "pdb", User: "pu", Password: "pp", SSLMode: "require",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("primary = %+v, want %+v", got, want)
	}
}

func TestGetBackupStorageConfig(t *testing.T) {
	resetConfig(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	wantPath := filepath.Join(home, ".local", "share", "vault", "vault.backup.db")

	// No config at all.
	cfg = nil
	if got := GetBackupStorageConfig(); got.Type != "sqlite" || got.Path != wantPath {
		t.Errorf("backup (nil cfg) = %+v, want sqlite at %s", got, wantPath)
	}

	// Config present but backup section empty: same defaults.
	cfg = &Config{}
	if got := GetBackupStorageConfig(); got.Type != "sqlite" || got.Path != wantPath {
		t.Errorf("backup (empty section) = %+v, want sqlite at %s", got, wantPath)
	}

	// Fully configured section: pass through.
	cfg = &Config{Storage: StorageRootConfig{Backup: StorageSectionConfig{
		Type: "sqlite", Path: "/b.db", Host: "bh", Port: 2,
		Database: "bdb", User: "bu", Password: "bp", SSLMode: "disable",
	}}}
	got := GetBackupStorageConfig()
	want := &storage.Config{
		Type: "sqlite", Path: "/b.db", Host: "bh", Port: 2,
		Database: "bdb", User: "bu", Password: "bp", SSLMode: "disable",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("backup = %+v, want %+v", got, want)
	}
}

func TestGetSyncStorageConfig(t *testing.T) {
	resetConfig(t)

	// No config: sync disabled.
	cfg = nil
	if got := GetSyncStorageConfig(); got != nil {
		t.Errorf("sync (nil cfg) = %+v, want nil", got)
	}

	// Incomplete config (host + user only): still disabled.
	cfg = &Config{Storage: StorageRootConfig{Sync: StorageSyncConfig{Postgres: StorageSectionConfig{
		Host: "db.example.com", User: "vault",
	}}}}
	if got := GetSyncStorageConfig(); got != nil {
		t.Errorf("sync (incomplete) = %+v, want nil", got)
	}

	// Complete but minimal: port and sslmode defaults apply.
	cfg = &Config{Storage: StorageRootConfig{Sync: StorageSyncConfig{Postgres: StorageSectionConfig{
		Host: "db.example.com", Database: "vaultdb", User: "vault",
	}}}}
	got := GetSyncStorageConfig()
	if got == nil {
		t.Fatal("sync (complete) = nil, want a config")
	}
	if got.Type != "postgres" || got.Port != 5432 || got.SSLMode != "disable" {
		t.Errorf("sync defaults = %+v, want postgres:5432 sslmode=disable", got)
	}

	// Explicit values win over defaults.
	cfg = &Config{Storage: StorageRootConfig{Sync: StorageSyncConfig{Postgres: StorageSectionConfig{
		Host: "db.example.com", Port: 6543, Database: "vaultdb",
		User: "vault", Password: "pw", SSLMode: "require",
	}}}}
	got = GetSyncStorageConfig()
	if got.Port != 6543 || got.SSLMode != "require" || got.Password != "pw" {
		t.Errorf("sync explicit = %+v, want port 6543 sslmode require", got)
	}
}

func TestGetCryptoConfig(t *testing.T) {
	resetConfig(t)

	cfg = nil
	got := GetCryptoConfig()
	if got.Argon2Time != 3 || got.Argon2Memory != 65536 ||
		got.Argon2Threads != 4 || got.Argon2KeyLength != 32 {
		t.Errorf("crypto (nil cfg) = %+v, want 3/65536/4/32", got)
	}

	cfg = &Config{Crypto: CryptoConfig{
		Argon2Time: 9, Argon2Memory: 1024, Argon2Threads: 1, Argon2KeyLength: 64,
	}}
	got = GetCryptoConfig()
	if got.Argon2Time != 9 || got.Argon2Memory != 1024 ||
		got.Argon2Threads != 1 || got.Argon2KeyLength != 64 {
		t.Errorf("crypto = %+v, want the configured values", got)
	}
}

func TestGetDataDirAndConfigDir(t *testing.T) {
	resetConfig(t)
	home := t.TempDir()
	t.Setenv("HOME", home)

	if got, want := GetDataDir(), filepath.Join(home, ".local", "share", "vault"); got != want {
		t.Errorf("GetDataDir() = %q, want %q", got, want)
	}
	if got, want := GetConfigDir(), filepath.Join(home, ".config", "vault"); got != want {
		t.Errorf("GetConfigDir() = %q, want %q", got, want)
	}

	// Without a home directory both fall back to /tmp/vault.
	t.Setenv("HOME", "")
	if got := GetDataDir(); got != "/tmp/vault" {
		t.Errorf("GetDataDir() without HOME = %q, want /tmp/vault", got)
	}
	if got := GetConfigDir(); got != "/tmp/vault" {
		t.Errorf("GetConfigDir() without HOME = %q, want /tmp/vault", got)
	}
}
