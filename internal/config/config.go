// Package config handles configuration management
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"vault/internal/storage"

	"github.com/spf13/viper"
)

const (
	// Version is the application version
	Version = "0.1.0"
)

var cfg *Config

// Config holds the application configuration
type Config struct {
	Storage StorageRootConfig `mapstructure:"storage"`
	Crypto  CryptoConfig      `mapstructure:"crypto"`
}

// StorageRootConfig holds role-based storage configuration.
//
// Desired behavior:
// - primary: always SQLite (system of record)
// - backup: SQLite (separate db file used for backups)
// - sync: optional Postgres target; if not configured, sync is disabled
//
// Backward compatibility:
// - If old flat `storage.type/path/...` is present, we treat it as `storage.primary`.
type StorageRootConfig struct {
	Primary StorageSectionConfig `mapstructure:"primary"`
	Backup  StorageSectionConfig `mapstructure:"backup"`
	Sync    StorageSyncConfig    `mapstructure:"sync"`

	// Legacy flat config support (deprecated)
	Type     string `mapstructure:"type"`
	Path     string `mapstructure:"path"`
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Database string `mapstructure:"database"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	SSLMode  string `mapstructure:"sslmode"`
}

// StorageSectionConfig is a single storage backend config (sqlite or postgres).
type StorageSectionConfig struct {
	Type     string `mapstructure:"type"`
	Path     string `mapstructure:"path"`
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Database string `mapstructure:"database"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	SSLMode  string `mapstructure:"sslmode"`
}

// StorageSyncConfig holds sync configuration.
// Currently only postgres is supported as a sync target.
type StorageSyncConfig struct {
	Postgres StorageSectionConfig `mapstructure:"postgres"`
}

// CryptoConfig holds cryptographic configuration
type CryptoConfig struct {
	Argon2Time      uint32 `mapstructure:"argon2_time"`
	Argon2Memory    uint32 `mapstructure:"argon2_memory"`
	Argon2Threads   uint8  `mapstructure:"argon2_threads"`
	Argon2KeyLength uint32 `mapstructure:"argon2_key_length"`
}

// Init initializes the configuration
func Init(cfgFile string) error {
	if cfgFile != "" {
		// Use config file from the flag
		viper.SetConfigFile(cfgFile)
	} else {
		// Search for config in default locations
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}

		configDir := filepath.Join(home, ".config", "vault")
		viper.AddConfigPath(configDir)
		viper.AddConfigPath(".")
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}

	// Set defaults
	setDefaults()

	// Read config file if it exists
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return fmt.Errorf("failed to read config: %w", err)
		}
		// Config file not found; use defaults
	}

	// Unmarshal config
	cfg = &Config{}
	if err := viper.Unmarshal(cfg); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return nil
}

func setDefaults() {
	home, _ := os.UserHomeDir()
	dataDir := filepath.Join(home, ".local", "share", "vault")

	// Storage defaults (role-based)
	viper.SetDefault("storage.primary.type", "sqlite")
	viper.SetDefault("storage.primary.path", filepath.Join(dataDir, "vault.db"))

	// Backups default to a separate SQLite file
	viper.SetDefault("storage.backup.type", "sqlite")
	viper.SetDefault("storage.backup.path", filepath.Join(dataDir, "vault.backup.db"))

	// Sync is optional; leaving these unset disables sync.
	// We do not set defaults for storage.sync.postgres.* on purpose.

	// Backward-compatible defaults (legacy flat keys)
	// If a user still has storage.type/path, it will be read into cfg.Storage.Type/Path.
	viper.SetDefault("storage.type", "")
	viper.SetDefault("storage.path", "")

	// Crypto defaults
	viper.SetDefault("crypto.argon2_time", 3)
	viper.SetDefault("crypto.argon2_memory", 65536) // 64MB
	viper.SetDefault("crypto.argon2_threads", 4)
	viper.SetDefault("crypto.argon2_key_length", 32)
}

// GetStorageConfig returns the PRIMARY storage configuration.
//
// Primary is always SQLite as the system-of-record. If legacy flat config is set,
// we treat it as primary for backward compatibility.
func GetStorageConfig() *storage.Config {
	return GetPrimaryStorageConfig()
}

// GetPrimaryStorageConfig returns the PRIMARY storage config (SQLite).
func GetPrimaryStorageConfig() *storage.Config {
	// Defaults if config isn't initialized
	if cfg == nil {
		home, _ := os.UserHomeDir()
		dataDir := filepath.Join(home, ".local", "share", "vault")
		return &storage.Config{
			Type: "sqlite",
			Path: filepath.Join(dataDir, "vault.db"),
		}
	}

	// Legacy flat config support: if `storage.type` is set, use it as primary.
	if cfg.Storage.Type != "" || cfg.Storage.Path != "" {
		typ := cfg.Storage.Type
		if typ == "" {
			typ = "sqlite"
		}

		home, _ := os.UserHomeDir()
		dataDir := filepath.Join(home, ".local", "share", "vault")
		path := cfg.Storage.Path
		if path == "" {
			path = filepath.Join(dataDir, "vault.db")
		}

		return &storage.Config{
			Type:     typ,
			Path:     path,
			Host:     cfg.Storage.Host,
			Port:     cfg.Storage.Port,
			Database: cfg.Storage.Database,
			User:     cfg.Storage.User,
			Password: cfg.Storage.Password,
			SSLMode:  cfg.Storage.SSLMode,
		}
	}

	return &storage.Config{
		Type:     cfg.Storage.Primary.Type,
		Path:     cfg.Storage.Primary.Path,
		Host:     cfg.Storage.Primary.Host,
		Port:     cfg.Storage.Primary.Port,
		Database: cfg.Storage.Primary.Database,
		User:     cfg.Storage.Primary.User,
		Password: cfg.Storage.Primary.Password,
		SSLMode:  cfg.Storage.Primary.SSLMode,
	}
}

// GetBackupStorageConfig returns the BACKUP storage config (SQLite).
//
// This is intended for local backup operations. If not configured, defaults are used.
func GetBackupStorageConfig() *storage.Config {
	// Defaults if config isn't initialized
	if cfg == nil {
		home, _ := os.UserHomeDir()
		dataDir := filepath.Join(home, ".local", "share", "vault")
		return &storage.Config{
			Type: "sqlite",
			Path: filepath.Join(dataDir, "vault.backup.db"),
		}
	}

	// If backup section isn't set, fall back to default path.
	typ := cfg.Storage.Backup.Type
	if typ == "" {
		typ = "sqlite"
	}

	path := cfg.Storage.Backup.Path
	if path == "" {
		home, _ := os.UserHomeDir()
		dataDir := filepath.Join(home, ".local", "share", "vault")
		path = filepath.Join(dataDir, "vault.backup.db")
	}

	return &storage.Config{
		Type:     typ,
		Path:     path,
		Host:     cfg.Storage.Backup.Host,
		Port:     cfg.Storage.Backup.Port,
		Database: cfg.Storage.Backup.Database,
		User:     cfg.Storage.Backup.User,
		Password: cfg.Storage.Backup.Password,
		SSLMode:  cfg.Storage.Backup.SSLMode,
	}
}

// GetSyncStorageConfig returns the SYNC target config (Postgres) if configured,
// otherwise returns nil which indicates sync is disabled.
func GetSyncStorageConfig() *storage.Config {
	if cfg == nil {
		return nil
	}

	pg := cfg.Storage.Sync.Postgres

	// Heuristic: require at least host + db + user to consider it "configured".
	if pg.Host == "" || pg.Database == "" || pg.User == "" {
		return nil
	}

	sslMode := pg.SSLMode
	if sslMode == "" {
		sslMode = "disable"
	}

	port := pg.Port
	if port == 0 {
		port = 5432
	}

	return &storage.Config{
		Type:     "postgres",
		Host:     pg.Host,
		Port:     port,
		Database: pg.Database,
		User:     pg.User,
		Password: pg.Password,
		SSLMode:  sslMode,
	}
}

// GetCryptoConfig returns the crypto configuration
func GetCryptoConfig() *CryptoConfig {
	if cfg == nil {
		return &CryptoConfig{
			Argon2Time:      3,
			Argon2Memory:    65536,
			Argon2Threads:   4,
			Argon2KeyLength: 32,
		}
	}
	return &cfg.Crypto
}

// GetDataDir returns the data directory
func GetDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/vault"
	}
	return filepath.Join(home, ".local", "share", "vault")
}

// GetConfigDir returns the config directory
func GetConfigDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/vault"
	}
	return filepath.Join(home, ".config", "vault")
}
