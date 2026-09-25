// Package storage provides storage backend abstraction
package storage

import "time"

// VaultDump represents a full serialized vault for cross-backend transfer.
//
// Secret values remain encrypted at rest; the dump preserves the vault's
// encryption salt and auth hash so the same master password keeps working
// after Import into another backend.
type VaultDump struct {
	SchemaVersion int            `json:"schema_version"`
	Salt          string         `json:"salt"`
	AuthHash      string         `json:"auth_hash"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	Projects      []*ProjectDump `json:"projects"`
}

// ProjectDump is a serialized project with its environments and secrets.
type ProjectDump struct {
	ID           string             `json:"id"`
	Name         string             `json:"name"`
	Description  string             `json:"description"`
	Config       string             `json:"config"`
	CreatedAt    time.Time          `json:"created_at"`
	CreatedBy    string             `json:"created_by"`
	UpdatedAt    time.Time          `json:"updated_at"`
	Environments []*EnvironmentDump `json:"environments"`
	Secrets      []*SecretDump      `json:"secrets"`
}

// EnvironmentDump is a serialized environment.
type EnvironmentDump struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Protected   bool   `json:"protected"`
	RequiresMFA bool   `json:"requires_mfa"`
}

// SecretDump is a serialized secret with its encrypted value and versions.
type SecretDump struct {
	ID           string         `json:"id"`
	Environment  string         `json:"environment"`
	Key          string         `json:"key"`
	Value        string         `json:"value"`
	Type         string         `json:"type"`
	Tags         string         `json:"tags"`
	Metadata     string         `json:"metadata"`
	Version      int            `json:"version"`
	PreviousID   *string        `json:"previous_id,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
	CreatedBy    string         `json:"created_by"`
	UpdatedAt    time.Time      `json:"updated_at"`
	UpdatedBy    string         `json:"updated_by"`
	ExpiresAt    *time.Time     `json:"expires_at,omitempty"`
	RotateAt     *time.Time     `json:"rotate_at,omitempty"`
	Owner        string         `json:"owner"`
	Checksum     string         `json:"checksum"`
	SyncStatus   string         `json:"sync_status"`
	LastSyncedAt *time.Time     `json:"last_synced_at,omitempty"`
	Versions     []*VersionDump `json:"versions"`
}

// VersionDump is a serialized secret version.
type VersionDump struct {
	ID        string    `json:"id"`
	Value     string    `json:"value"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
	Checksum  string    `json:"checksum"`
}
