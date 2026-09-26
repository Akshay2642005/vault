package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"vault/internal/storage"
)

// exportVault serializes the entire vault into a portable JSON dump.
func (b *Backend) exportVault(ctx context.Context) ([]byte, error) {
	if b.db == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	dump := &storage.VaultDump{}

	// Vault metadata
	err := b.db.QueryRowContext(ctx, `
		SELECT version, salt, auth_hash, created_at, updated_at
		FROM vault_metadata WHERE id = 1
	`).Scan(&dump.SchemaVersion, &dump.Salt, &dump.AuthHash, &dump.CreatedAt, &dump.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("vault not initialized")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read vault metadata: %w", err)
	}

	// Environments grouped by project
	envs, err := b.exportEnvironments(ctx)
	if err != nil {
		return nil, err
	}

	// Secrets grouped by project, with versions attached
	secrets, err := b.exportSecrets(ctx)
	if err != nil {
		return nil, err
	}

	// Projects
	rows, err := b.db.QueryContext(ctx, `
		SELECT id, name, description, config, created_at, created_by, updated_at
		FROM projects ORDER BY name
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query projects: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var p storage.ProjectDump
		var description, config sql.NullString
		if err := rows.Scan(&p.ID, &p.Name, &description, &config,
			&p.CreatedAt, &p.CreatedBy, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan project: %w", err)
		}
		p.Description = description.String
		p.Config = config.String

		p.Environments = envs[p.ID]
		if p.Environments == nil {
			p.Environments = []*storage.EnvironmentDump{}
		}

		for _, s := range secrets[p.ID] {
			p.Secrets = append(p.Secrets, s)
		}
		if p.Secrets == nil {
			p.Secrets = []*storage.SecretDump{}
		}

		dump.Projects = append(dump.Projects, &p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate projects: %w", err)
	}

	return json.Marshal(dump)
}

// exportEnvironments loads all environments grouped by project ID.
func (b *Backend) exportEnvironments(ctx context.Context) (map[string][]*storage.EnvironmentDump, error) {
	rows, err := b.db.QueryContext(ctx, `
		SELECT project_id, id, name, type, protected, requires_mfa
		FROM environments ORDER BY name
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query environments: %w", err)
	}
	defer rows.Close()

	envs := make(map[string][]*storage.EnvironmentDump)
	for rows.Next() {
		var projectID string
		var e storage.EnvironmentDump
		if err := rows.Scan(&projectID, &e.ID, &e.Name, &e.Type, &e.Protected, &e.RequiresMFA); err != nil {
			return nil, fmt.Errorf("failed to scan environment: %w", err)
		}
		envs[projectID] = append(envs[projectID], &e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate environments: %w", err)
	}
	return envs, nil
}

// exportSecrets loads all secrets (with encrypted values) grouped by project,
// together with all versions grouped by secret ID.
//
// The vault metadata (salt, auth hash) and encrypted values allow this dump to
// be imported into another backend while staying encrypted at rest.
func (b *Backend) exportSecrets(ctx context.Context) (map[string][]*storage.SecretDump, error) {
	rows, err := b.db.QueryContext(ctx, `
		SELECT id, project_id, environment, key, value, type, tags, metadata,
		       version, previous_id, created_at, created_by, updated_at, updated_by,
		       expires_at, rotate_at, owner, checksum, sync_status, last_synced_at
		FROM secrets ORDER BY key
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query secrets: %w", err)
	}

	secrets := make(map[string][]*storage.SecretDump)

	for rows.Next() {
		var s storage.SecretDump
		var projectID string
		var value []byte
		var tags, metadata, previousID sql.NullString
		var expiresAt, rotateAt, lastSyncedAt sql.NullTime

		if err := rows.Scan(&s.ID, &projectID, &s.Environment, &s.Key, &value,
			&s.Type, &tags, &metadata, &s.Version, &previousID,
			&s.CreatedAt, &s.CreatedBy, &s.UpdatedAt, &s.UpdatedBy,
			&expiresAt, &rotateAt, &s.Owner, &s.Checksum, &s.SyncStatus, &lastSyncedAt); err != nil {
			rows.Close()
			return nil, fmt.Errorf("failed to scan secret: %w", err)
		}

		s.Value = string(value)
		s.Tags = tags.String
		s.Metadata = metadata.String
		if previousID.Valid {
			s.PreviousID = &previousID.String
		}
		if expiresAt.Valid {
			s.ExpiresAt = &expiresAt.Time
		}
		if rotateAt.Valid {
			s.RotateAt = &rotateAt.Time
		}
		if lastSyncedAt.Valid {
			s.LastSyncedAt = &lastSyncedAt.Time
		}

		secrets[projectID] = append(secrets[projectID], &s)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("failed to iterate secrets: %w", err)
	}
	rows.Close()

	// Attach versions to secrets
	vers, err := b.exportVersions(ctx)
	if err != nil {
		return nil, err
	}
	for _, projectSecrets := range secrets {
		for _, s := range projectSecrets {
			s.Versions = vers[s.ID]
			if s.Versions == nil {
				s.Versions = []*storage.VersionDump{}
			}
		}
	}

	return secrets, nil
}

// exportVersions loads all secret versions grouped by secret ID.
func (b *Backend) exportVersions(ctx context.Context) (map[string][]*storage.VersionDump, error) {
	rows, err := b.db.QueryContext(ctx, `
		SELECT secret_id, id, value, version, created_at, created_by, checksum
		FROM secret_versions ORDER BY version
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query secret versions: %w", err)
	}
	defer rows.Close()

	vers := make(map[string][]*storage.VersionDump)
	for rows.Next() {
		var secretID string
		var value []byte
		var v storage.VersionDump
		if err := rows.Scan(&secretID, &v.ID, &value, &v.Version, &v.CreatedAt, &v.CreatedBy, &v.Checksum); err != nil {
			return nil, fmt.Errorf("failed to scan secret version: %w", err)
		}
		v.Value = string(value)
		vers[secretID] = append(vers[secretID], &v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate secret versions: %w", err)
	}
	return vers, nil
}

// importVault replaces the current vault contents with the data in the dump.
func (b *Backend) importVault(ctx context.Context, data []byte) error {
	if b.db == nil {
		return fmt.Errorf("database not initialized")
	}

	var dump storage.VaultDump
	if err := json.Unmarshal(data, &dump); err != nil {
		return fmt.Errorf("failed to parse vault data: %w", err)
	}

	if dump.SchemaVersion > schemaVersion {
		return fmt.Errorf("unsupported vault schema version: %d (expected %d)", dump.SchemaVersion, schemaVersion)
	}

	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Wipe existing data (cascading FKs remove children)
	for _, stmt := range []string{
		`DELETE FROM projects`,
		`DELETE FROM secret_versions`,
		`DELETE FROM secrets`,
		`DELETE FROM vault_metadata`,
	} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("failed to clear vault: %w", err)
		}
	}

	// Vault metadata
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO vault_metadata (id, version, salt, auth_hash, created_at, updated_at)
		VALUES (1, $1, $2, $3, $4, $5)
	`, dump.SchemaVersion, dump.Salt, dump.AuthHash, utc(dump.CreatedAt), utc(dump.UpdatedAt)); err != nil {
		return fmt.Errorf("failed to insert vault metadata: %w", err)
	}

	// Projects and their environments
	for _, p := range dump.Projects {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO projects (id, name, description, config, created_at, created_by, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		`, p.ID, p.Name, p.Description, p.Config, utc(p.CreatedAt), p.CreatedBy, utc(p.UpdatedAt)); err != nil {
			return fmt.Errorf("failed to insert project %s: %w", p.Name, err)
		}

		for _, e := range p.Environments {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO environments (id, project_id, name, type, protected, requires_mfa)
				VALUES ($1, $2, $3, $4, $5, $6)
			`, e.ID, p.ID, e.Name, e.Type, e.Protected, e.RequiresMFA); err != nil {
				return fmt.Errorf("failed to insert environment %s: %w", e.Name, err)
			}
		}

		// Secrets first (previous_id populated separately to respect FKs)
		for _, s := range p.Secrets {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO secrets (
					id, project_id, environment, key, value, type, tags, metadata,
					version, created_at, created_by, updated_at, updated_by,
					expires_at, rotate_at, owner, checksum, sync_status
				) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
			`, s.ID, p.ID, s.Environment, s.Key, []byte(s.Value), s.Type, s.Tags, s.Metadata,
				s.Version, utc(s.CreatedAt), s.CreatedBy, utc(s.UpdatedAt), s.UpdatedBy,
				utcPtr(s.ExpiresAt), utcPtr(s.RotateAt), s.Owner, s.Checksum, s.SyncStatus); err != nil {
				return fmt.Errorf("failed to insert secret %s/%s: %w", s.Environment, s.Key, err)
			}
		}

		// Then their versions
		for _, s := range p.Secrets {
			for _, v := range s.Versions {
				if _, err := tx.ExecContext(ctx, `
					INSERT INTO secret_versions (id, secret_id, value, version, created_at, created_by, checksum)
					VALUES ($1, $2, $3, $4, $5, $6, $7)
				`, v.ID, s.ID, []byte(v.Value), v.Version, utc(v.CreatedAt), v.CreatedBy, v.Checksum); err != nil {
					return fmt.Errorf("failed to insert version %d of %s: %w", v.Version, s.Key, err)
				}
			}
		}
	}

	// Link rotation history now that every secret exists.
	for _, p := range dump.Projects {
		for _, s := range p.Secrets {
			if s.PreviousID == nil {
				continue
			}
			if _, err := tx.ExecContext(ctx, `UPDATE secrets SET previous_id = $1 WHERE id = $2`,
				*s.PreviousID, s.ID); err != nil {
				return fmt.Errorf("failed to link previous_id for %s: %w", s.Key, err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit import: %w", err)
	}

	// The vault metadata (salt/auth hash) changed, so the current key is stale.
	b.key = nil
	return nil
}
