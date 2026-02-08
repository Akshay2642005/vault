/*
package domain contains the core business logic and data structures of the application.
it defines the main entities, value objects, and interfaces that represent the core concepts of the domain.
this package is independent of any specific implementation details and can be used across different layers of the application.
*/

package domain

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

type SecretType string

const (
	SecretTypeGeneric     SecretType = "generic"
	SecretTypeAPIKey      SecretType = "api_key"
	SecretTypePassword    SecretType = "password"
	SecretTypeSSHKey      SecretType = "ssh_key"
	SecretTypeOAuthToken  SecretType = "oauth_token"
	SecretTypeCertificate SecretType = "certificate"
	SecretTypeDatabase    SecretType = "database_url"
)

type EnvironmentType string

const (
	EnvDevelopment EnvironmentType = "development"
	EnvStaging     EnvironmentType = "staging"
	EnvProduction  EnvironmentType = "production"
	EnvCustom      EnvironmentType = "custom"
)

type SyncStatus string

const (
	SyncStatusPending    SyncStatus = "pending"
	SyncStatusInSynced   SyncStatus = "synced"
	SyncStatusConfilct   SyncStatus = "conflict"
	SyncStatusFailed     SyncStatus = "failed"
	SyncStatusNotEnabled SyncStatus = "not_enabled"
)

type Secret struct {
	ID          string         `json:"id"`
	ProjectID   string         `json:"project_id"`
	Environment string         `json:"environment"`
	Key         string         `json:"key"`
	Value       string         `json:"value"`
	Type        SecretType     `json:"type"`
	Tags        []string       `json:"tags"`
	Metadata    map[string]any `json:"metadata"`

	Version    int     `json:"version"`
	PreviousID *string `json:"previous_id,omitempty"`

	CreatedAt time.Time  `json:"created_at"`
	CreatedBy string     `json:"created_by"`
	UpdatedAt time.Time  `json:"updated_at"`
	UpdatedBy string     `json:"updated_by"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	RotateAt  *time.Time `json:"rotate_at,omitempty"`

	Owner       string   `json:"owner"`
	Permissions []string `json:"permissions"`

	SyncStatus   SyncStatus `json:"sync_status"`
	LastSyncedAt *time.Time `json:"last_synced_at,omitempty"`
	Checksum     string     `json:"checksum"`
}

type Permission struct {
	Principal string   `json:"principal"`
	Action    []string `json:"action"`
}

type Project struct {
	ID           string        `json:"id"`
	Name         string        `json:"name"`
	Description  string        `json:"description"`
	Environments []Environment `json:"environment"`
	Config       ProjectConfig `json:"config"`

	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
	UpdatedAt time.Time `json:"updated_at"`

	Team []TeamMember `json:"team,omitempty"`
}

type Environment struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Type        EnvironmentType `json:"type"`
	Protected   bool            `json:"protected"`
	RequiresMFA bool            `json:"requires_mfa"`
}

type ProjectConfig struct {
	AutoRotate       bool           `json:"auto_rotate"`
	RotationInterval time.Duration  `json:"rotation_interval"`
	DefaultTags      []string       `json:"default_tags"`
	Metadata         map[string]any `json:"metadata"`
}

type TeamMember struct {
	UserID string   `json:"user_id"`
	Role   string   `json:"role"`
	Scopes []string `json:"scopes"`
}

type SecretVersion struct {
	ID        string    `json:"id"`
	SecretID  string    `json:"secret_id"`
	Value     string    `json:"value"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
	Checksum  string    `json:"checksum"`
}

type Store struct {
	Version  int       `json:"version"`
	Salt     string    `json:"salt"`
	AuthHash string    `json:"auth_hash"`
	Created  time.Time `json:"created"`
	Modified time.Time `json:"modified"`
}

func isLetter(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

func isDigit(r rune) bool {
	return r >= '0' && r <= '9'
}

func isValidIdentifier(s string) bool {
	if len(s) == 0 {
		return false
	}

	for i, r := range s {
		if i == 0 && !isLetter(r) && r != '_' {
			return false
		}
		if !isLetter(r) && !isDigit(r) && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

func ValidateProjectName(name string) error {
	name = strings.TrimSpace(name)
	if name == " " {
		return errors.New("project name cannot be empty")
	}

	if len(name) > 256 {
		return errors.New("project name cannot exceed 256 characters")
	}

	if !isValidIdentifier(name) {
		return errors.New("project name must contain only alphanumeric characters, dashes, and underscores")
	}
	return nil
}

func ValidateEnvironmentName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("environment name cannot be empty")
	}
	if len(name) > 64 {
		return errors.New("environment name cannot exceed 64 characters")
	}
	if !isValidIdentifier(name) {
		return errors.New("environment name must contain only alphanumeric characters, dashes, and underscores")
	}
	return nil
}

func ValidateSecretKey(key string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return errors.New("secret key cannot be empty")
	}
	if len(key) > 256 {
		return errors.New("secret key too long (max 256 characters)")
	}

	if strings.ContainsAny(key, "=\n\r\t") {
		return errors.New("secret key cannot contain =, newlines, tabs, or carriage returns")
	}
	return nil
}

func ValidateSecretValue(value string) error {
	if len(value) > 1024*1024 {
		return errors.New("secret value too long (max 1MB)")
	}
	return nil
}

func NewSecret(
	projectId, environment, key, value, createdBy string,
	secretType SecretType,
) (*Secret, error) {
	if err := ValidateSecretKey(key); err != nil {
		return nil, fmt.Errorf("invalid key: %w", err)
	}
	if err := ValidateSecretValue(value); err != nil {
		return nil, fmt.Errorf("invalid value: %w", err)
	}

	now := time.Now()

	return &Secret{
		ID:          GenerateID(),
		ProjectID:   projectId,
		Environment: environment,
		Key:         key,
		Value:       value,
		Type:        secretType,
		Version:     1,
		CreatedAt:   now,
		CreatedBy:   createdBy,
		UpdatedAt:   now,
		Owner:       createdBy,
		SyncStatus:  SyncStatusNotEnabled,
		Tags:        []string{},
		Metadata:    make(map[string]any),
	}, nil
}

func NewProject(
	name, description, createdBy string,
) (*Project, error) {
	if err := ValidateProjectName(name); err != nil {
		return nil, fmt.Errorf("invalid project name: %w", err)
	}

	now := time.Now()
	return &Project{
		ID:          GenerateID(),
		Name:        name,
		Description: description,
		Environments: []Environment{
			{
				ID:   GenerateID(),
				Name: "development",
				Type: EnvDevelopment,
			},
			{
				ID:   GenerateID(),
				Name: "staging",
				Type: EnvStaging,
			},
			{
				ID:          GenerateID(),
				Name:        "production",
				Type:        EnvProduction,
				Protected:   true,
				RequiresMFA: true,
			},
		},
		CreatedAt: now,
		CreatedBy: createdBy,
		UpdatedAt: now,
		Team:      []TeamMember{},
	}, nil
}

func (s *Secret) SecretPath() string {
	return fmt.Sprintf("%s%s%s", s.ProjectID, s.Environment, s.Key)
}

func (s *Secret) isExpired() bool {
	if s.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*s.ExpiresAt)
}

func (s *Secret) NeedsRotation() bool {
	if s.RotateAt == nil {
		return false
	}
	return time.Now().After(*s.RotateAt)
}

func (s *Secret) Clone() *Secret {
	clone := *s

	if s.Tags != nil {
		clone.Tags = make([]string, len(s.Tags))
		copy(clone.Tags, s.Tags)
	}

	if s.Metadata != nil {
		clone.Metadata = make(map[string]any)
		for k, v := range s.Metadata {
			clone.Metadata[k] = v
		}
	}

	if s.Permissions != nil {
		clone.Permissions = make([]string, len(s.Permissions))
		copy(clone.Permissions, s.Permissions)
	}

	return &clone
}
