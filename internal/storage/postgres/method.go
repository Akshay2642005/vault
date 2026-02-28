package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"vault/internal/domain"
)

// CreateSecret creates a new secret
func (b *Backend) CreateSecret(ctx context.Context, secret *domain.Secret) error {
	if b.key == nil {
		return fmt.Errorf("vault not unlocked")
	}

	// Encrypt the secret value
	encryptedValue, err := b.engine.Encrypt([]byte(secret.Value), b.key)
	if err != nil {
		return fmt.Errorf("failed to encrypt secret: %w", err)
	}

	// Marshal tags and metadata
	tags, err := json.Marshal(secret.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}

	metadata, err := json.Marshal(secret.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Insert into database
	_, err = b.db.ExecContext(ctx, `
		INSERT INTO secrets (
			id, project_id, environment, key, value, type, tags, metadata,
			version, created_at, created_by, updated_at, updated_by,
			expires_at, rotate_at, owner, checksum, sync_status
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
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

	// Create initial version
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
	var encryptedValue []byte
	var tags, metadata sql.NullString
	var expiresAt, rotateAt, lastSyncedAt sql.NullTime
	var previousID sql.NullString

	err := b.db.QueryRowContext(ctx, `
		SELECT id, project_id, environment, key, value, type, tags, metadata,
		       version, previous_id, created_at, created_by, updated_at, updated_by,
		       expires_at, rotate_at, owner, checksum, sync_status, last_synced_at
		FROM secrets
		WHERE project_id = $1 AND environment = $2 AND key = $3
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
	decrypted, err := b.engine.Decrypt(string(encryptedValue), b.key)
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
	var encryptedValue []byte
	var tags, metadata sql.NullString
	var expiresAt, rotateAt, lastSyncedAt sql.NullTime
	var previousID sql.NullString

	err := b.db.QueryRowContext(ctx, `
		SELECT id, project_id, environment, key, value, type, tags, metadata,
		       version, previous_id, created_at, created_by, updated_at, updated_by,
		       expires_at, rotate_at, owner, checksum, sync_status, last_synced_at
		FROM secrets
		WHERE id = $1
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
	decrypted, err := b.engine.Decrypt(string(encryptedValue), b.key)
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

// UpdateSecret updates an existing secret
func (b *Backend) UpdateSecret(ctx context.Context, secret *domain.Secret) error {
	if b.key == nil {
		return fmt.Errorf("vault not unlocked")
	}

	// Encrypt the new value
	encryptedValue, err := b.engine.Encrypt([]byte(secret.Value), b.key)
	if err != nil {
		return fmt.Errorf("failed to encrypt secret: %w", err)
	}

	// Marshal tags and metadata
	tags, err := json.Marshal(secret.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}

	metadata, err := json.Marshal(secret.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Update the secret
	_, err = b.db.ExecContext(ctx, `
		UPDATE secrets SET
			value = $1,
			type = $2,
			tags = $3,
			metadata = $4,
			version = version + 1,
			updated_at = $5,
			updated_by = $6,
			expires_at = $7,
			rotate_at = $8,
			checksum = $9
		WHERE id = $10
	`,
		encryptedValue, secret.Type, tags, metadata,
		secret.UpdatedAt, secret.UpdatedBy,
		secret.ExpiresAt, secret.RotateAt, secret.Checksum,
		secret.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}

	return nil
}

// DeleteSecret deletes a secret
func (b *Backend) DeleteSecret(ctx context.Context, id string) error {
	_, err := b.db.ExecContext(ctx, `DELETE FROM secrets WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}
	return nil
}

// ListSecrets lists all secrets in a project and environment
func (b *Backend) ListSecrets(ctx context.Context, projectID, environment string) ([]*domain.Secret, error) {
	if b.key == nil {
		return nil, fmt.Errorf("vault not unlocked")
	}

	query := `
		SELECT id, project_id, environment, key, value, type, tags, metadata,
		       version, created_at, created_by, updated_at, updated_by,
		       owner, checksum, sync_status
		FROM secrets
		WHERE project_id = $1 AND environment = $2
		ORDER BY key
	`

	rows, err := b.db.QueryContext(ctx, query, projectID, environment)
	if err != nil {
		return nil, fmt.Errorf("failed to query secrets: %w", err)
	}
	defer rows.Close()

	var secrets []*domain.Secret
	for rows.Next() {
		var secret domain.Secret
		var encryptedValue []byte
		var tags, metadata sql.NullString

		err := rows.Scan(
			&secret.ID, &secret.ProjectID, &secret.Environment, &secret.Key,
			&encryptedValue, &secret.Type, &tags, &metadata,
			&secret.Version, &secret.CreatedAt, &secret.CreatedBy,
			&secret.UpdatedAt, &secret.UpdatedBy,
			&secret.Owner, &secret.Checksum, &secret.SyncStatus,
		)

		if err != nil {
			return nil, err
		}

		// Decrypt value
		decrypted, err := b.engine.Decrypt(string(encryptedValue), b.key)
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

		secrets = append(secrets, &secret)
	}

	return secrets, rows.Err()
}

// SearchSecrets searches secrets using full-text search
func (b *Backend) SearchSecrets(ctx context.Context, query string) ([]*domain.Secret, error) {
	if b.key == nil {
		return nil, fmt.Errorf("vault not unlocked")
	}

	searchQuery := `
		SELECT id, project_id, environment, key, value, type, tags, metadata,
		       version, created_at, created_by, updated_at, updated_by,
		       owner, checksum, sync_status
		FROM secrets
		WHERE to_tsvector('english', key) @@ plainto_tsquery('english', $1)
		   OR to_tsvector('english', COALESCE(tags, '')) @@ plainto_tsquery('english', $1)
		ORDER BY key
	`

	rows, err := b.db.QueryContext(ctx, searchQuery, query)
	if err != nil {
		return nil, fmt.Errorf("failed to search secrets: %w", err)
	}
	defer rows.Close()

	var secrets []*domain.Secret
	for rows.Next() {
		var secret domain.Secret
		var encryptedValue []byte
		var tags, metadata sql.NullString

		err := rows.Scan(
			&secret.ID, &secret.ProjectID, &secret.Environment, &secret.Key,
			&encryptedValue, &secret.Type, &tags, &metadata,
			&secret.Version, &secret.CreatedAt, &secret.CreatedBy,
			&secret.UpdatedAt, &secret.UpdatedBy,
			&secret.Owner, &secret.Checksum, &secret.SyncStatus,
		)

		if err != nil {
			return nil, err
		}

		// Decrypt value
		decrypted, err := b.engine.Decrypt(string(encryptedValue), b.key)
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

		secrets = append(secrets, &secret)
	}

	return secrets, rows.Err()
}

// CreateSecretVersion creates a new secret version
func (b *Backend) CreateSecretVersion(ctx context.Context, version *domain.SecretVersion) error {
	if b.key == nil {
		return fmt.Errorf("vault not unlocked")
	}

	// Encrypt value
	encryptedValue, err := b.engine.Encrypt([]byte(version.Value), b.key)
	if err != nil {
		return fmt.Errorf("failed to encrypt secret version: %w", err)
	}

	_, err = b.db.ExecContext(ctx, `
		INSERT INTO secret_versions (id, secret_id, value, version, created_at, created_by, checksum)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`,
		version.ID, version.SecretID, encryptedValue,
		version.Version, version.CreatedAt, version.CreatedBy,
		version.Checksum,
	)

	if err != nil {
		return fmt.Errorf("failed to insert secret version: %w", err)
	}

	return nil
}

// GetSecretVersion retrieves a specific version of a secret
func (b *Backend) GetSecretVersion(ctx context.Context, secretID string, version int) (*domain.SecretVersion, error) {
	if b.key == nil {
		return nil, fmt.Errorf("vault not unlocked")
	}

	var sv domain.SecretVersion
	var encryptedValue []byte

	err := b.db.QueryRowContext(ctx, `
		SELECT id, secret_id, value, version, created_at, created_by, checksum
		FROM secret_versions
		WHERE secret_id = $1 AND version = $2
	`, secretID, version).Scan(
		&sv.ID, &sv.SecretID, &encryptedValue,
		&sv.Version, &sv.CreatedAt, &sv.CreatedBy, &sv.Checksum,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("version not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query version: %w", err)
	}

	// Decrypt value
	decrypted, err := b.engine.Decrypt(string(encryptedValue), b.key)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt version: %w", err)
	}
	sv.Value = string(decrypted)

	return &sv, nil
}

// ListSecretVersions lists all versions of a secret
func (b *Backend) ListSecretVersions(ctx context.Context, secretID string) ([]*domain.SecretVersion, error) {
	if b.key == nil {
		return nil, fmt.Errorf("vault not unlocked")
	}

	rows, err := b.db.QueryContext(ctx, `
		SELECT id, secret_id, value, version, created_at, created_by, checksum
		FROM secret_versions
		WHERE secret_id = $1
		ORDER BY version DESC
	`, secretID)

	if err != nil {
		return nil, fmt.Errorf("failed to query versions: %w", err)
	}
	defer rows.Close()

	var versions []*domain.SecretVersion
	for rows.Next() {
		var sv domain.SecretVersion
		var encryptedValue []byte

		err := rows.Scan(
			&sv.ID, &sv.SecretID, &encryptedValue,
			&sv.Version, &sv.CreatedAt, &sv.CreatedBy, &sv.Checksum,
		)

		if err != nil {
			return nil, err
		}

		// Decrypt value
		decrypted, err := b.engine.Decrypt(string(encryptedValue), b.key)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt version: %w", err)
		}
		sv.Value = string(decrypted)

		versions = append(versions, &sv)
	}

	return versions, rows.Err()
}

// CreateProject creates a new project
func (b *Backend) CreateProject(ctx context.Context, project *domain.Project) error {
	config, err := json.Marshal(project.Config)
	if err != nil {
		return fmt.Errorf("failed to marshal project config: %w", err)
	}

	_, err = b.db.ExecContext(ctx, `
		INSERT INTO projects (id, name, description, config, created_at, created_by, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`,
		project.ID, project.Name, project.Description, config,
		project.CreatedAt, project.CreatedBy, project.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create project: %w", err)
	}

	for _, env := range project.Environments {
		if err := b.CreateEnvironment(ctx, project.ID, env); err != nil {
			return err
		}
	}
	return nil
}

// GetProject retrieves a project by ID
func (b *Backend) GetProject(ctx context.Context, id string) (*domain.Project, error) {
	var project domain.Project
	var config sql.NullString

	err := b.db.QueryRowContext(ctx, `
		SELECT id, name, description, config, created_at, created_by, updated_at
		FROM projects
		WHERE id = $1
	`, id).Scan(
		&project.ID, &project.Name, &project.Description, &config,
		&project.CreatedAt, &project.CreatedBy, &project.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("project not found")
	}
	if err != nil {
		return nil, err
	}

	if config.Valid {
		json.Unmarshal([]byte(config.String), &project.Config)
	}

	project.Environments, err = b.ListEnvironments(ctx, project.ID)
	if err != nil {
		return nil, err
	}

	return &project, nil
}

// GetProjectByName retrieves a project by name
func (b *Backend) GetProjectByName(ctx context.Context, name string) (*domain.Project, error) {
	var project domain.Project
	var config sql.NullString

	err := b.db.QueryRowContext(ctx, `
		SELECT id, name, description, config, created_at, created_by, updated_at
		FROM projects
		WHERE name = $1
	`, name).Scan(
		&project.ID, &project.Name, &project.Description, &config,
		&project.CreatedAt, &project.CreatedBy, &project.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("project not found")
	}
	if err != nil {
		return nil, err
	}

	if config.Valid {
		json.Unmarshal([]byte(config.String), &project.Config)
	}
	project.Environments, err = b.ListEnvironments(ctx, project.ID)
	if err != nil {
		return nil, err
	}

	return &project, nil
}

// ListProjects lists all projects
func (b *Backend) ListProjects(ctx context.Context) ([]*domain.Project, error) {
	rows, err := b.db.QueryContext(ctx, `
		SELECT id, name, description, config, created_at, created_by, updated_at
		FROM projects
		ORDER BY name
	`)

	if err != nil {
		return nil, fmt.Errorf("failed to query projects: %w", err)
	}
	defer rows.Close()

	var projects []*domain.Project
	for rows.Next() {
		var project domain.Project
		var config sql.NullString

		err := rows.Scan(
			&project.ID, &project.Name, &project.Description, &config,
			&project.CreatedAt, &project.CreatedBy, &project.UpdatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan project: %w", err)
		}

		if config.Valid {
			json.Unmarshal([]byte(config.String), &project.Config)
		}

		project.Environments, _ = b.ListEnvironments(ctx, project.ID)
		projects = append(projects, &project)
	}

	return projects, rows.Err()
}

// UpdateProject updates a project
func (b *Backend) UpdateProject(ctx context.Context, project *domain.Project) error {
	_, err := b.db.ExecContext(ctx, `
		UPDATE projects SET
			name = $1,
			description = $2,
			config = $3,
			updated_at = $4
		WHERE id = $5
	`,
		project.Name, project.Description, project.Config,
		project.UpdatedAt, project.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update project: %w", err)
	}
	return nil
}

// DeleteProject deletes a project
func (b *Backend) DeleteProject(ctx context.Context, id string) error {
	_, err := b.db.ExecContext(ctx, `DELETE FROM projects WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("failed to delete project: %w", err)
	}
	return nil
}

// CreateEnvironment creates a new environment
func (b *Backend) CreateEnvironment(ctx context.Context, projectID string, env *domain.Environment) error {
	_, err := b.db.ExecContext(ctx, `
		INSERT INTO environments (id, project_id, name, type, protected, requires_mfa)
		VALUES ($1, $2, $3, $4, $5, $6)
	`,
		env.ID, projectID, env.Name, env.Type, env.Protected, env.RequiresMFA,
	)

	if err != nil {
		return fmt.Errorf("failed to create environment: %w", err)
	}
	return nil
}

// GetEnvironment retrieves an environment
func (b *Backend) GetEnvironment(ctx context.Context, projectID, name string) (*domain.Environment, error) {
	var env domain.Environment

	err := b.db.QueryRowContext(ctx, `
		SELECT id, project_id, name, type, protected, requires_mfa
		FROM environments
		WHERE project_id = $1 AND name = $2
	`, projectID, name).Scan(
		&env.ID, &env.ID, &env.Name, &env.Type, &env.Protected, &env.RequiresMFA,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("environment not found")
	}
	if err != nil {
		return nil, err
	}

	return &env, nil
}

// ListEnvironments lists all environments for a project
func (b *Backend) ListEnvironments(ctx context.Context, projectID string) ([]*domain.Environment, error) {
	rows, err := b.db.QueryContext(ctx, `
		SELECT id, project_id, name, type, protected, requires_mfa
		FROM environments
		WHERE project_id = $1
		ORDER BY name
	`, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to query environments: %w", err)
	}
	defer rows.Close()

	var environments []*domain.Environment
	for rows.Next() {
		var env domain.Environment
		err := rows.Scan(&env.ID, &env.ProjectID, &env.Name, &env.Type, &env.Protected, &env.RequiresMFA)
		if err != nil {
			return nil, fmt.Errorf("failed to scan environment: %w", err)
		}
		environments = append(environments, &env)
	}

	return environments, nil
}

// DeleteEnvironment deletes an environment
func (b *Backend) DeleteEnvironment(ctx context.Context, projectID, name string) error {
	_, err := b.db.ExecContext(ctx, `
		DELETE FROM environments WHERE project_id = $1 AND name = $2
	`, projectID, name)

	if err != nil {
		return fmt.Errorf("failed to delete environment: %w", err)
	}
	return nil
}
