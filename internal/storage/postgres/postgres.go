// Package postgres provides PostgreSQL storage backend
package postgres

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"time"

	"vault/internal/crypto"
	"vault/internal/storage"

	_ "github.com/lib/pq"
)

const (
	schemaVersion = 1
)

// Backend implements storage.Backend for PostgreSQL
type Backend struct {
	db     *sql.DB
	config *storage.Config
	engine *crypto.Engine
	key    []byte // Master encryption key
}

// New creates a new PostgreSQL backend
func New(config *storage.Config) (*Backend, error) {
	return &Backend{
		config: config,
		engine: crypto.NewEngine(),
	}, nil
}

// Initialize initializes the database connection
func (b *Backend) Initialize(ctx context.Context, config *storage.Config) error {
	b.config = config

	// Build connection string
	connStr := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		config.Host,
		config.Port,
		config.User,
		config.Password,
		config.Database,
		config.SSLMode,
	)

	// Open database
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	b.db = db

	// Configure connection pool
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(1 * time.Hour)
	db.SetConnMaxIdleTime(5 * time.Minute)

	// Test connection
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	// Auto-migrate schema
	if err := b.autoMigrate(ctx); err != nil {
		return fmt.Errorf("auto-migration failed: %w", err)
	}

	return nil
}

// CreateVault creates a new vault with the given password
func (b *Backend) CreateVault(ctx context.Context, password string) error {
	// Generate salt
	salt, err := crypto.GenerateSalt()
	if err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive key from password
	key := b.engine.DeriveKey(password, salt)
	b.key = key

	// Generate auth hash for password verification
	authHash := crypto.GenerateAuthHash(key)

	// Store vault metadata
	_, err = b.db.ExecContext(ctx, `
		INSERT INTO vault_metadata (id, version, salt, auth_hash, created_at, updated_at)
		VALUES (1, $1, $2, $3, $4, $5)
	`, schemaVersion, base64.StdEncoding.EncodeToString(salt), authHash, time.Now(), time.Now())

	if err != nil {
		return fmt.Errorf("failed to store vault metadata: %w", err)
	}

	return nil
}

// UnlockVault unlocks the vault with the given password
func (b *Backend) UnlockVault(ctx context.Context, password string) ([]byte, error) {
	var saltStr, authHash string
	err := b.db.QueryRowContext(ctx, `
		SELECT salt, auth_hash FROM vault_metadata WHERE id = 1
	`).Scan(&saltStr, &authHash)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("vault not initialized")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read vault metadata: %w", err)
	}

	// Decode salt
	salt, err := base64.StdEncoding.DecodeString(saltStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	// Derive key from password
	key := b.engine.DeriveKey(password, salt)

	// Verify password
	valid, err := crypto.VerifyAuthHash(key, authHash)
	if err != nil {
		return nil, fmt.Errorf("failed to verify password: %w", err)
	}
	if !valid {
		return nil, fmt.Errorf("invalid password")
	}

	b.key = key
	return key, nil
}

// IsInitialized checks if the vault is initialized
func (b *Backend) IsInitialized(ctx context.Context) (bool, error) {
	var count int
	err := b.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM vault_metadata WHERE id = 1
	`).Scan(&count)

	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// Close closes the database connection
func (b *Backend) Close() error {
	if b.db != nil {
		return b.db.Close()
	}
	return nil
}

// Health checks the health of the storage backend
func (b *Backend) Health(ctx context.Context) error {
	return b.db.PingContext(ctx)
}

// autoMigrate automatically applies all pending migrations
func (b *Backend) autoMigrate(ctx context.Context) error {
	// Ensure schema_version table exists
	if err := b.ensureSchemaVersionTable(ctx); err != nil {
		return fmt.Errorf("failed to create schema_version table: %w", err)
	}

	// Get current schema version
	currentVersion, err := b.getCurrentSchemaVersion(ctx)
	if err != nil {
		return fmt.Errorf("failed to get current schema version: %w", err)
	}

	// Apply all pending migrations
	for _, migration := range migrations {
		if migration.Version > currentVersion {
			if err := b.applyMigration(ctx, migration); err != nil {
				return fmt.Errorf("failed to apply migration %d: %w", migration.Version, err)
			}
		}
	}

	return nil
}

// ensureSchemaVersionTable creates the schema_version table if it doesn't exist
func (b *Backend) ensureSchemaVersionTable(ctx context.Context) error {
	_, err := b.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_version (
			version INTEGER PRIMARY KEY,
			description TEXT NOT NULL,
			applied_at TIMESTAMP NOT NULL DEFAULT NOW(),
			checksum TEXT
		)
	`)
	return err
}

// getCurrentSchemaVersion returns the current schema version
func (b *Backend) getCurrentSchemaVersion(ctx context.Context) (int, error) {
	var version int
	err := b.db.QueryRowContext(ctx, `
		SELECT COALESCE(MAX(version), 0) FROM schema_version
	`).Scan(&version)
	return version, err
}

// applyMigration applies a single migration in a transaction
func (b *Backend) applyMigration(ctx context.Context, migration Migration) error {
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Execute migration SQL
	if _, err := tx.ExecContext(ctx, migration.SQL); err != nil {
		return err
	}

	// Record migration
	_, err = tx.ExecContext(ctx, `
		INSERT INTO schema_version (version, description, applied_at)
		VALUES ($1, $2, $3)
	`, migration.Version, migration.Description, time.Now())

	if err != nil {
		return err
	}

	return tx.Commit()
}

// Migration represents a database schema migration
type Migration struct {
	Version     int
	Description string
	SQL         string
}

// migrations contains all schema migrations
var migrations = []Migration{
	{
		Version:     1,
		Description: "Initial schema - matches SQLite structure exactly",
		SQL: `
-- Vault metadata
CREATE TABLE IF NOT EXISTS vault_metadata (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	version INTEGER NOT NULL,
	salt TEXT NOT NULL,
	auth_hash TEXT NOT NULL,
	created_at TIMESTAMP NOT NULL,
	updated_at TIMESTAMP NOT NULL
);

-- Projects
CREATE TABLE IF NOT EXISTS projects (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL UNIQUE,
	description TEXT,
	config TEXT,
	created_at TIMESTAMP NOT NULL,
	created_by TEXT NOT NULL,
	updated_at TIMESTAMP NOT NULL
);

-- Environments
CREATE TABLE IF NOT EXISTS environments (
	id TEXT PRIMARY KEY,
	project_id TEXT NOT NULL,
	name TEXT NOT NULL,
	type TEXT NOT NULL,
	protected BOOLEAN DEFAULT FALSE,
	requires_mfa BOOLEAN DEFAULT FALSE,
	FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
	UNIQUE(project_id, name)
);

-- Secrets
CREATE TABLE IF NOT EXISTS secrets (
	id TEXT PRIMARY KEY,
	project_id TEXT NOT NULL,
	environment TEXT NOT NULL,
	key TEXT NOT NULL,
	value BYTEA NOT NULL,
	type TEXT NOT NULL,
	tags TEXT,
	metadata TEXT,
	version INTEGER NOT NULL DEFAULT 1,
	previous_id TEXT,
	created_at TIMESTAMP NOT NULL,
	created_by TEXT NOT NULL,
	updated_at TIMESTAMP NOT NULL,
	updated_by TEXT NOT NULL,
	expires_at TIMESTAMP,
	rotate_at TIMESTAMP,
	owner TEXT NOT NULL,
	checksum TEXT NOT NULL,
	sync_status TEXT NOT NULL DEFAULT 'not_enabled',
	last_synced_at TIMESTAMP,
	FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
	FOREIGN KEY (previous_id) REFERENCES secrets(id),
	UNIQUE(project_id, environment, key)
);

-- Secret versions
CREATE TABLE IF NOT EXISTS secret_versions (
	id TEXT PRIMARY KEY,
	secret_id TEXT NOT NULL,
	value BYTEA NOT NULL,
	version INTEGER NOT NULL,
	created_at TIMESTAMP NOT NULL,
	created_by TEXT NOT NULL,
	checksum TEXT NOT NULL,
	FOREIGN KEY (secret_id) REFERENCES secrets(id) ON DELETE CASCADE,
	UNIQUE(secret_id, version)
);

-- Indices
CREATE INDEX IF NOT EXISTS idx_secrets_project ON secrets(project_id);
CREATE INDEX IF NOT EXISTS idx_secrets_env ON secrets(environment);
CREATE INDEX IF NOT EXISTS idx_secrets_key ON secrets(key);
CREATE INDEX IF NOT EXISTS idx_secrets_updated ON secrets(updated_at);
CREATE INDEX IF NOT EXISTS idx_secrets_expires ON secrets(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_secrets_rotate ON secrets(rotate_at) WHERE rotate_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_secret_versions_secret ON secret_versions(secret_id);

-- Full-text search (PostgreSQL native)
CREATE INDEX IF NOT EXISTS idx_secrets_key_gin ON secrets USING gin(to_tsvector('english', key));
CREATE INDEX IF NOT EXISTS idx_secrets_tags_gin ON secrets USING gin(to_tsvector('english', COALESCE(tags, '')));
`,
	},
}

// BeginTx starts a transaction
func (b *Backend) BeginTx(ctx context.Context) (storage.Transaction, error) {
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &postgresTx{tx: tx}, nil
}

type postgresTx struct {
	tx *sql.Tx
}

func (t *postgresTx) Commit() error {
	return t.tx.Commit()
}

func (t *postgresTx) Rollback() error {
	return t.tx.Rollback()
}

// Export exports the entire vault
func (b *Backend) Export(ctx context.Context) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

// Import imports vault data
func (b *Backend) Import(ctx context.Context, data []byte) error {
	return fmt.Errorf("not implemented")
}
