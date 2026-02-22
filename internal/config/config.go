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
	Storage StorageConfig `mapstructure:"storage"`
	Crypto  CryptoConfig  `mapstructure:"crypto"`
}

// StorageConfig holds storage backend configuration
type StorageConfig struct {
	Type     string `mapstructure:"type"`
	Path     string `mapstructure:"path"`
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Database string `mapstructure:"database"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	SSLMode  string `mapstructure:"sslmode"`
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

	// Storage defaults
	viper.SetDefault("storage.type", "sqlite")
	viper.SetDefault("storage.path", filepath.Join(dataDir, "vault.db"))

	// Crypto defaults
	viper.SetDefault("crypto.argon2_time", 3)
	viper.SetDefault("crypto.argon2_memory", 65536) // 64MB
	viper.SetDefault("crypto.argon2_threads", 4)
	viper.SetDefault("crypto.argon2_key_length", 32)
}

// GetStorageConfig returns the storage configuration
func GetStorageConfig() *storage.Config {
	if cfg == nil {
		// Use defaults if not initialized
		home, _ := os.UserHomeDir()
		dataDir := filepath.Join(home, ".local", "share", "vault")
		return &storage.Config{
			Type: "sqlite",
			Path: filepath.Join(dataDir, "vault.db"),
		}
	}

	return &storage.Config{
		Type:     cfg.Storage.Type,
		Path:     cfg.Storage.Path,
		Host:     cfg.Storage.Host,
		Port:     cfg.Storage.Port,
		Database: cfg.Storage.Database,
		User:     cfg.Storage.User,
		Password: cfg.Storage.Password,
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
