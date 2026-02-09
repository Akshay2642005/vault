// Package sqlite provides SQLite storage backend
package sqlite

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"vault/internal/crypto"
	"vault/internal/domain"
	"vault/internal/storage"
)

const (
	schemaVersion = 1
)

type Backend struct {
	db     *sql.DB
	config *storage.Config
	engine *crypto.Engine
	key    []byte
}

func New(config *storage.Config) (*Backend, error) {
	return &Backend{
		config: config,
		engine: crypto.NewEngine(),
	}, nil
}

func (b *Backend) Initialize(ctx context.Context, config *storage.Config) error {
	b.config = config

	dir := filepath.Dir(config.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	db, err := sql.Open("sqlite3", config.Path+"?_foreign_keys=on&_journal_mode=WAL")
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	b.db = db

	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA cache_size=10000",
		"PRAGMA temp_store=MEMORY",
	}

	for _, pragma := range pragmas {
		if _, err := b.db.ExecContext(ctx, pragma); err != nil {
			return fmt.Errorf("failed to set pragma: %w", err)
		}
	}

	return nil
}

func (b *Backend) CreateVault(ctx context.Context, password string) error {
	salt, err := crypto.GenerateSalt()
	if err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	key := b.engine.DeriveKey(password, salt)
	b.key = key

	authHash := crypto.GenerateAuthHash(key)

	if err := b.createSchema(ctx); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	_, err = b.db.ExecContext(ctx, `
		INSERT INTO vault_metadata (id, version, salt, auth_hash, created_at, updated_at)
		VALUES (1, ?, ?, ?, ?, ?)
	`, schemaVersion, base64.StdEncoding.EncodeToString(salt), authHash, time.Now(), time.Now())
	if err != nil {
		return fmt.Errorf("failed to store vault metadata: %w", err)
	}

	return nil
}

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

	salt, err := base64.StdEncoding.DecodeString(saltStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	key := b.engine.DeriveKey(password, salt)

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

func (b *Backend) IsInitialized(ctx context.Context) (bool, error) {
	var count int
	err := b.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='vault_metadata'
	`).Scan(&count)
	if err != nil {
		return false, err
	}

	if count == 0 {
		return false, nil
	}

	err = b.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM vault_metadata WHERE id = 1
	`).Scan(&count)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

func (b *Backend) Close() error {
	if b.db != nil {
		return b.db.Close()
	}
	return nil
}

func (b *Backend) Health(ctx context.Context) error {
	return b.db.PingContext(ctx)
}

func (b *Backend) createSchema(ctx context.Context) error {
	schema := `
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
		config TEXT, -- JSON
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
		value BLOB NOT NULL, -- encrypted
		type TEXT NOT NULL,
		tags TEXT, -- JSON array
		metadata TEXT, -- JSON object
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

	-- Secret versions (history)
	CREATE TABLE IF NOT EXISTS secret_versions (
		id TEXT PRIMARY KEY,
		secret_id TEXT NOT NULL,
		value BLOB NOT NULL, -- encrypted
		version INTEGER NOT NULL,
		created_at TIMESTAMP NOT NULL,
		created_by TEXT NOT NULL,
		checksum TEXT NOT NULL,
		FOREIGN KEY (secret_id) REFERENCES secrets(id) ON DELETE CASCADE,
		UNIQUE(secret_id, version)
	);

	-- Indices for common queries
	CREATE INDEX IF NOT EXISTS idx_secrets_project ON secrets(project_id);
	CREATE INDEX IF NOT EXISTS idx_secrets_env ON secrets(environment);
	CREATE INDEX IF NOT EXISTS idx_secrets_key ON secrets(key);
	CREATE INDEX IF NOT EXISTS idx_secrets_updated ON secrets(updated_at);
	CREATE INDEX IF NOT EXISTS idx_secrets_expires ON secrets(expires_at);
	CREATE INDEX IF NOT EXISTS idx_secrets_rotate ON secrets(rotate_at);
	CREATE INDEX IF NOT EXISTS idx_secret_versions_secret ON secret_versions(secret_id);

	-- Full-text search
	CREATE VIRTUAL TABLE IF NOT EXISTS secrets_fts USING fts5(
		project_id, 
		environment,
		key, 
		tags,
		content=secrets,
		content_rowid=rowid
	);

	-- Triggers to keep FTS in sync
	CREATE TRIGGER IF NOT EXISTS secrets_ai AFTER INSERT ON secrets BEGIN
		INSERT INTO secrets_fts(rowid, project_id, environment, key, tags)
		VALUES (new.rowid, new.project_id, new.environment, new.key, new.tags);
	END;

	CREATE TRIGGER IF NOT EXISTS secrets_ad AFTER DELETE ON secrets BEGIN
		INSERT INTO secrets_fts(secrets_fts, rowid, project_id, environment, key, tags)
		VALUES('delete', old.rowid, old.project_id, old.environment, old.key, old.tags);
	END;

	CREATE TRIGGER IF NOT EXISTS secrets_au AFTER UPDATE ON secrets BEGIN
		INSERT INTO secrets_fts(secrets_fts, rowid, project_id, environment, key, tags)
		VALUES('delete', old.rowid, old.project_id, old.environment, old.key, old.tags);
		INSERT INTO secrets_fts(rowid, project_id, environment, key, tags)
		VALUES (new.rowid, new.project_id, new.environment, new.key, new.tags);
	END;
	`

	_, err := b.db.ExecContext(ctx, schema)
	return err
}

func (b *Backend) CreateSecret(ctx context.Context, secret *domain.Secret) error {
	if b.key == nil {
		return fmt.Errorf("vault not unlocked")
	}

	encryptedValue, err := b.engine.Encrypt([]byte(secret.Value), b.key)
	if err != nil {
		return fmt.Errorf("failed to encrypt secret: %w", err)
	}

	tags, err := json.Marshal(secret.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}

	metadata, err := json.Marshal(secret.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	_, err = b.db.ExecContext(ctx, `
		INSERT INTO secrets (
			id, project_id, environment, key, value, type, tags, metadata,
			version, created_at, created_by, updated_at, updated_by,
			expires_at, rotate_at, owner, checksum, sync_status
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		secret.ID, secret.ProjectID, secret.Environment, secret.Key,
		encryptedValue, secret.Type, tags, metadata,
		secret.Version, secret.CreatedAt, secret.CreatedBy,
		secret.UpdatedAt, secret.UpdatedBy,
		secret.ExpiresAt, secret.RotateAt, secret.Owner,
		secret.Checksum, secret.SyncStatus,
	)
	if err != nil {
		return fmt.Errorf("failed to insert secret: %w", err)
	}

	version := &domain.SecretVersion{
		ID:        domain.GenerateID(),
		SecretID:  secret.ID,
		Value:     secret.Value,
		Version:   secret.Version,
		CreatedAt: secret.CreatedAt,
		CreatedBy: secret.CreatedBy,
		Checksum:  secret.Checksum,
	}

	return b.CreateSecretVersion(ctx, version)
}

// GetSecret retrieves a secret by project, environment, and key
func (b *Backend) GetSecret(ctx context.Context, projectID, environment, key string) (*domain.Secret, error) {
	if b.key == nil {
		return nil, fmt.Errorf("vault not unlocked")
	}

	var secret domain.Secret
	var encryptedValue string
	var tags, metadata sql.NullString
	var expiresAt, rotateAt, lastSyncedAt sql.NullTime
	var previousID sql.NullString

	err := b.db.QueryRowContext(ctx, `
		SELECT id, project_id, environment, key, value, type, tags, metadata,
		       version, previous_id, created_at, created_by, updated_at, updated_by,
		       expires_at, rotate_at, owner, checksum, sync_status, last_synced_at
		FROM secrets
		WHERE project_id = ? AND environment = ? AND key = ?
	`, projectID, environment, key).Scan(
		&secret.ID, &secret.ProjectID, &secret.Environment, &secret.Key,
		&encryptedValue, &secret.Type, &tags, &metadata,
		&secret.Version, &previousID, &secret.CreatedAt, &secret.CreatedBy,
		&secret.UpdatedAt, &secret.UpdatedBy, &expiresAt, &rotateAt,
		&secret.Owner, &secret.Checksum, &secret.SyncStatus, &lastSyncedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("secret not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query secret: %w", err)
	}

	// Decrypt value
	decrypted, err := b.engine.Decrypt(encryptedValue, b.key)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt secret: %w", err)
	}
	secret.Value = string(decrypted)

	// Unmarshal tags and metadata
	if tags.Valid {
		if err := json.Unmarshal([]byte(tags.String), &secret.Tags); err != nil {
			return nil, fmt.Errorf("failed to unmarshal tags: %w", err)
		}
	}

	if metadata.Valid {
		if err := json.Unmarshal([]byte(metadata.String), &secret.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	if previousID.Valid {
		secret.PreviousID = &previousID.String
	}
	if expiresAt.Valid {
		secret.ExpiresAt = &expiresAt.Time
	}
	if rotateAt.Valid {
		secret.RotateAt = &rotateAt.Time
	}
	if lastSyncedAt.Valid {
		secret.LastSyncedAt = &lastSyncedAt.Time
	}

	return &secret, nil
}

// GetSecretByID retrieves a secret by ID
func (b *Backend) GetSecretByID(ctx context.Context, id string) (*domain.Secret, error) {
	if b.key == nil {
		return nil, fmt.Errorf("vault not unlocked")
	}

	var secret domain.Secret
	var encryptedValue string
	var tags, metadata sql.NullString
	var expiresAt, rotateAt, lastSyncedAt sql.NullTime
	var previousID sql.NullString

	err := b.db.QueryRowContext(ctx, `
		SELECT id, project_id, environment, key, value, type, tags, metadata,
		       version, previous_id, created_at, created_by, updated_at, updated_by,
		       expires_at, rotate_at, owner, checksum, sync_status, last_synced_at
		FROM secrets
		WHERE id = ?
	`, id).Scan(
		&secret.ID, &secret.ProjectID, &secret.Environment, &secret.Key,
		&encryptedValue, &secret.Type, &tags, &metadata,
		&secret.Version, &previousID, &secret.CreatedAt, &secret.CreatedBy,
		&secret.UpdatedAt, &secret.UpdatedBy, &expiresAt, &rotateAt,
		&secret.Owner, &secret.Checksum, &secret.SyncStatus, &lastSyncedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("secret not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query secret: %w", err)
	}

	// Decrypt value
	decrypted, err := b.engine.Decrypt(encryptedValue, b.key)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt secret: %w", err)
	}
	secret.Value = string(decrypted)

	// Unmarshal tags and metadata
	if tags.Valid {
		json.Unmarshal([]byte(tags.String), &secret.Tags)
	}
	if metadata.Valid {
		json.Unmarshal([]byte(metadata.String), &secret.Metadata)
	}
	if previousID.Valid {
		secret.PreviousID = &previousID.String
	}
	if expiresAt.Valid {
		secret.ExpiresAt = &expiresAt.Time
	}
	if rotateAt.Valid {
		secret.RotateAt = &rotateAt.Time
	}
	if lastSyncedAt.Valid {
		secret.LastSyncedAt = &lastSyncedAt.Time
	}

	return &secret, nil
}

// Additional methods will be implemented in subsequent files...
// (UpdateSecret, DeleteSecret, ListSecrets, SearchSecrets, etc.)

// BeginTx starts a transaction
func (b *Backend) BeginTx(ctx context.Context) (storage.Transaction, error) {
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &sqliteTx{tx: tx}, nil
}

type sqliteTx struct {
	tx *sql.Tx
}

func (t *sqliteTx) Commit() error {
	return t.tx.Commit()
}

func (t *sqliteTx) Rollback() error {
	return t.tx.Rollback()
}

// Export exports the entire vault
func (b *Backend) Export(ctx context.Context) ([]byte, error) {
	// Implementation will be added
	return nil, fmt.Errorf("not implemented")
}

// Import imports vault data
func (b *Backend) Import(ctx context.Context, data []byte) error {
	// Implementation will be added
	return fmt.Errorf("not implemented")
}
