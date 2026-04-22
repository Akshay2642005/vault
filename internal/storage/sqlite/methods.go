package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"vault/internal/domain"
)

const sqliteSecretMetadataSelect = `
	SELECT id, project_id, environment, key, type, tags, metadata,
	       version, previous_id, created_at, created_by, updated_at, updated_by,
	       expires_at, rotate_at, owner, checksum, sync_status, last_synced_at
	FROM secrets
`

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
			value = ?,
			type = ?,
			tags = ?,
			metadata = ?,
			version = version + 1,
			updated_at = ?,
			updated_by = ?,
			expires_at = ?,
			rotate_at = ?,
			checksum = ?
		WHERE id = ?
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
	_, err := b.db.ExecContext(ctx, `DELETE FROM secrets WHERE id = ?`, id)
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
		WHERE project_id = ? AND environment = ?
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
		var encryptedValue string
		var tags, metadata sql.NullString

		err := rows.Scan(
			&secret.ID, &secret.ProjectID, &secret.Environment, &secret.Key,
			&encryptedValue, &secret.Type, &tags, &metadata,
			&secret.Version, &secret.CreatedAt, &secret.CreatedBy,
			&secret.UpdatedAt, &secret.UpdatedBy,
			&secret.Owner, &secret.Checksum, &secret.SyncStatus,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan secret: %w", err)
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
		} else {
			secret.Tags = []string{}
		}

		if metadata.Valid {
			json.Unmarshal([]byte(metadata.String), &secret.Metadata)
		} else {
			secret.Metadata = make(map[string]any)
		}

		secrets = append(secrets, &secret)
	}

	return secrets, nil
}

// ListSecretMetadata lists secrets without decrypting secret values.
func (b *Backend) ListSecretMetadata(ctx context.Context, projectID, environment string) ([]*domain.Secret, error) {
	if b.key == nil {
		return nil, fmt.Errorf("vault not unlocked")
	}

	rows, err := b.db.QueryContext(ctx, sqliteSecretMetadataSelect+`
		WHERE project_id = ? AND environment = ?
		ORDER BY key
	`, projectID, environment)
	if err != nil {
		return nil, fmt.Errorf("failed to query secret metadata: %w", err)
	}
	defer rows.Close()

	return scanSecretMetadataRows(rows)
}

// SearchSecrets searches for secrets using full-text search
func (b *Backend) SearchSecrets(ctx context.Context, query string) ([]*domain.Secret, error) {
	if b.key == nil {
		return nil, fmt.Errorf("vault not unlocked")
	}

	sqlQuery := `
		SELECT s.id, s.project_id, s.environment, s.key, s.value, s.type, s.tags, s.metadata,
		       s.version, s.created_at, s.created_by, s.updated_at, s.updated_by,
		       s.owner, s.checksum, s.sync_status
		FROM secrets s
		INNER JOIN secrets_fts fts ON s.rowid = fts.rowid
		WHERE secrets_fts MATCH ?
		ORDER BY rank
	`

	rows, err := b.db.QueryContext(ctx, sqlQuery, query)
	if err != nil {
		return nil, fmt.Errorf("failed to search secrets: %w", err)
	}
	defer rows.Close()

	var secrets []*domain.Secret
	for rows.Next() {
		var secret domain.Secret
		var encryptedValue string
		var tags, metadata sql.NullString

		err := rows.Scan(
			&secret.ID, &secret.ProjectID, &secret.Environment, &secret.Key,
			&encryptedValue, &secret.Type, &tags, &metadata,
			&secret.Version, &secret.CreatedAt, &secret.CreatedBy,
			&secret.UpdatedAt, &secret.UpdatedBy,
			&secret.Owner, &secret.Checksum, &secret.SyncStatus,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan secret: %w", err)
		}

		// Decrypt value
		decrypted, err := b.engine.Decrypt(encryptedValue, b.key)
		if err != nil {
			continue // Skip secrets we can't decrypt
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

	return secrets, nil
}

// SearchSecretMetadata searches secrets without decrypting secret values.
func (b *Backend) SearchSecretMetadata(ctx context.Context, query string) ([]*domain.Secret, error) {
	if b.key == nil {
		return nil, fmt.Errorf("vault not unlocked")
	}

	rows, err := b.db.QueryContext(ctx, `
		SELECT s.id, s.project_id, s.environment, s.key, s.type, s.tags, s.metadata,
		       s.version, s.previous_id, s.created_at, s.created_by, s.updated_at, s.updated_by,
		       s.expires_at, s.rotate_at, s.owner, s.checksum, s.sync_status, s.last_synced_at
		FROM secrets s
		INNER JOIN secrets_fts fts ON s.rowid = fts.rowid
		WHERE secrets_fts MATCH ?
		ORDER BY rank
	`, query)
	if err != nil {
		return nil, fmt.Errorf("failed to search secret metadata: %w", err)
	}
	defer rows.Close()

	return scanSecretMetadataRows(rows)
}

// CreateSecretVersion creates a new secret version
func (b *Backend) CreateSecretVersion(ctx context.Context, version *domain.SecretVersion) error {
	if b.key == nil {
		return fmt.Errorf("vault not unlocked")
	}

	// Encrypt the version value
	encryptedValue, err := b.engine.Encrypt([]byte(version.Value), b.key)
	if err != nil {
		return fmt.Errorf("failed to encrypt version: %w", err)
	}

	_, err = b.db.ExecContext(ctx, `
		INSERT INTO secret_versions (id, secret_id, value, version, created_at, created_by, checksum)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, version.ID, version.SecretID, encryptedValue, version.Version, version.CreatedAt, version.CreatedBy, version.Checksum)
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

	var v domain.SecretVersion
	var encryptedValue string

	err := b.db.QueryRowContext(ctx, `
		SELECT id, secret_id, value, version, created_at, created_by, checksum
		FROM secret_versions
		WHERE secret_id = ? AND version = ?
	`, secretID, version).Scan(&v.ID, &v.SecretID, &encryptedValue, &v.Version, &v.CreatedAt, &v.CreatedBy, &v.Checksum)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("version not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query version: %w", err)
	}

	// Decrypt value
	decrypted, err := b.engine.Decrypt(encryptedValue, b.key)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt version: %w", err)
	}
	v.Value = string(decrypted)

	return &v, nil
}

// ListSecretVersions lists all versions of a secret
func (b *Backend) ListSecretVersions(ctx context.Context, secretID string) ([]*domain.SecretVersion, error) {
	if b.key == nil {
		return nil, fmt.Errorf("vault not unlocked")
	}

	rows, err := b.db.QueryContext(ctx, `
		SELECT id, secret_id, value, version, created_at, created_by, checksum
		FROM secret_versions
		WHERE secret_id = ?
		ORDER BY version DESC
	`, secretID)
	if err != nil {
		return nil, fmt.Errorf("failed to query versions: %w", err)
	}
	defer rows.Close()

	var versions []*domain.SecretVersion
	for rows.Next() {
		var v domain.SecretVersion
		var encryptedValue string

		err := rows.Scan(&v.ID, &v.SecretID, &encryptedValue, &v.Version, &v.CreatedAt, &v.CreatedBy, &v.Checksum)
		if err != nil {
			return nil, fmt.Errorf("failed to scan version: %w", err)
		}

		// Decrypt value
		decrypted, err := b.engine.Decrypt(encryptedValue, b.key)
		if err != nil {
			continue // Skip versions we can't decrypt
		}
		v.Value = string(decrypted)

		versions = append(versions, &v)
	}

	return versions, nil
}

// CreateProject creates a new project
func (b *Backend) CreateProject(ctx context.Context, project *domain.Project) error {
	// Marshal config
	config, err := json.Marshal(project.Config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Insert project
	_, err = b.db.ExecContext(ctx, `
		INSERT INTO projects (id, name, description, config, created_at, created_by, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, project.ID, project.Name, project.Description, config, project.CreatedAt, project.CreatedBy, project.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to insert project: %w", err)
	}

	// Insert environments
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
		FROM projects WHERE id = ?
	`, id).Scan(&project.ID, &project.Name, &project.Description, &config, &project.CreatedAt, &project.CreatedBy, &project.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("project not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query project: %w", err)
	}

	if config.Valid {
		json.Unmarshal([]byte(config.String), &project.Config)
	}

	// Load environments
	project.Environments, err = b.ListEnvironments(ctx, id)
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
		FROM projects WHERE name = ?
	`, name).Scan(&project.ID, &project.Name, &project.Description, &config, &project.CreatedAt, &project.CreatedBy, &project.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("project not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query project: %w", err)
	}

	if config.Valid {
		json.Unmarshal([]byte(config.String), &project.Config)
	}

	// Load environments
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
		FROM projects ORDER BY name
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query projects: %w", err)
	}
	defer rows.Close()

	var projects []*domain.Project
	projectIDs := make([]string, 0)
	for rows.Next() {
		var project domain.Project
		var config sql.NullString

		err := rows.Scan(&project.ID, &project.Name, &project.Description, &config, &project.CreatedAt, &project.CreatedBy, &project.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan project: %w", err)
		}

		if config.Valid {
			json.Unmarshal([]byte(config.String), &project.Config)
		}

		projects = append(projects, &project)
		projectIDs = append(projectIDs, project.ID)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate projects: %w", err)
	}

	envsByProjectID, err := b.listEnvironmentsByProjectIDs(ctx, projectIDs)
	if err != nil {
		return nil, err
	}
	for _, project := range projects {
		project.Environments = envsByProjectID[project.ID]
	}

	return projects, nil
}

// UpdateProject updates a project
func (b *Backend) UpdateProject(ctx context.Context, project *domain.Project) error {
	config, err := json.Marshal(project.Config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	_, err = b.db.ExecContext(ctx, `
		UPDATE projects SET
			name = ?,
			description = ?,
			config = ?,
			updated_at = ?
		WHERE id = ?
	`, project.Name, project.Description, config, project.UpdatedAt, project.ID)

	return err
}

// DeleteProject deletes a project and all its secrets
func (b *Backend) DeleteProject(ctx context.Context, id string) error {
	_, err := b.db.ExecContext(ctx, `DELETE FROM projects WHERE id = ?`, id)
	return err
}

// CreateEnvironment creates a new environment for a project
func (b *Backend) CreateEnvironment(ctx context.Context, projectID string, env *domain.Environment) error {
	_, err := b.db.ExecContext(ctx, `
		INSERT INTO environments (id, project_id, name, type, protected, requires_mfa)
		VALUES (?, ?, ?, ?, ?, ?)
	`, env.ID, projectID, env.Name, env.Type, env.Protected, env.RequiresMFA)

	return err
}

// GetEnvironment retrieves an environment
func (b *Backend) GetEnvironment(ctx context.Context, projectID, envName string) (*domain.Environment, error) {
	var env domain.Environment

	err := b.db.QueryRowContext(ctx, `
		SELECT id, name, type, protected, requires_mfa
		FROM environments
		WHERE project_id = ? AND name = ?
	`, projectID, envName).Scan(&env.ID, &env.Name, &env.Type, &env.Protected, &env.RequiresMFA)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("environment not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query environment: %w", err)
	}

	return &env, nil
}

// ListEnvironments lists all environments for a project
func (b *Backend) ListEnvironments(ctx context.Context, projectID string) ([]*domain.Environment, error) {
	rows, err := b.db.QueryContext(ctx, `
		SELECT id, name, type, protected, requires_mfa
		FROM environments
		WHERE project_id = ?
		ORDER BY name
	`, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to query environments: %w", err)
	}
	defer rows.Close()

	var environments []*domain.Environment
	for rows.Next() {
		var env domain.Environment
		err := rows.Scan(&env.ID, &env.Name, &env.Type, &env.Protected, &env.RequiresMFA)
		if err != nil {
			return nil, fmt.Errorf("failed to scan environment: %w", err)
		}
		environments = append(environments, &env)
	}

	return environments, nil
}

// DeleteEnvironment deletes an environment
func (b *Backend) DeleteEnvironment(ctx context.Context, projectID, envID string) error {
	_, err := b.db.ExecContext(ctx, `
		DELETE FROM environments WHERE project_id = ? AND id = ?
	`, projectID, envID)
	return err
}

func scanSecretMetadataRows(rows *sql.Rows) ([]*domain.Secret, error) {
	secrets := make([]*domain.Secret, 0)
	for rows.Next() {
		secret, err := scanSecretMetadataRow(rows)
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, secret)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate secret metadata: %w", err)
	}

	return secrets, nil
}

func scanSecretMetadataRow(scanner interface {
	Scan(dest ...any) error
}) (*domain.Secret, error) {
	var secret domain.Secret
	var tags, metadata sql.NullString
	var expiresAt, rotateAt, lastSyncedAt sql.NullTime
	var previousID sql.NullString

	err := scanner.Scan(
		&secret.ID, &secret.ProjectID, &secret.Environment, &secret.Key,
		&secret.Type, &tags, &metadata,
		&secret.Version, &previousID, &secret.CreatedAt, &secret.CreatedBy,
		&secret.UpdatedAt, &secret.UpdatedBy, &expiresAt, &rotateAt,
		&secret.Owner, &secret.Checksum, &secret.SyncStatus, &lastSyncedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to scan secret metadata: %w", err)
	}

	if tags.Valid {
		if err := json.Unmarshal([]byte(tags.String), &secret.Tags); err != nil {
			return nil, fmt.Errorf("failed to unmarshal secret tags: %w", err)
		}
	} else {
		secret.Tags = []string{}
	}

	if metadata.Valid {
		if err := json.Unmarshal([]byte(metadata.String), &secret.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal secret metadata: %w", err)
		}
	} else {
		secret.Metadata = make(map[string]any)
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

func (b *Backend) listEnvironmentsByProjectIDs(ctx context.Context, projectIDs []string) (map[string][]*domain.Environment, error) {
	envsByProjectID := make(map[string][]*domain.Environment, len(projectIDs))
	if len(projectIDs) == 0 {
		return envsByProjectID, nil
	}

	query := `
		SELECT id, project_id, name, type, protected, requires_mfa
		FROM environments
		WHERE project_id IN (?
	`
	args := make([]any, 0, len(projectIDs))
	args = append(args, projectIDs[0])
	for _, projectID := range projectIDs[1:] {
		query += ", ?"
		args = append(args, projectID)
	}
	query += `)
		ORDER BY name`

	rows, err := b.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query environments: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var env domain.Environment
		if err := rows.Scan(&env.ID, &env.ProjectID, &env.Name, &env.Type, &env.Protected, &env.RequiresMFA); err != nil {
			return nil, fmt.Errorf("failed to scan environment: %w", err)
		}
		envsByProjectID[env.ProjectID] = append(envsByProjectID[env.ProjectID], &env)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate environments: %w", err)
	}

	for _, projectID := range projectIDs {
		if envsByProjectID[projectID] == nil {
			envsByProjectID[projectID] = []*domain.Environment{}
		}
	}

	return envsByProjectID, nil
}
