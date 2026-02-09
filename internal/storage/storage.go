// Package storage provides storage backend abstraction
package storage

import (
	"context"
	"time"

	"vault/internal/domain"
)

type Backend interface {
	Initialize(ctx context.Context, config *Config) error
	Close() error
	Health(ctx context.Context) error

	CreateVault(ctx context.Context, password string) error
	UnlockVault(ctx context.Context, password string) ([]byte, error)
	IsInitialized(ctx context.Context) (bool, error)

	CreateSecret(ctx context.Context, secret *domain.Secret) error
	GetSecret(ctx context.Context, projectID, environment, key string) (*domain.Secret, error)
	GetSecretByID(ctx context.Context, id string) (*domain.Secret, error)
	UpdateSecret(ctx context.Context, secret *domain.Secret) error
	DeleteSecret(ctx context.Context, id string) error
	ListSecrets(ctx context.Context, projectID, environment string) ([]*domain.Secret, error)
	SearchSecrets(ctx context.Context, query string) ([]*domain.Secret, error)

	GetSecretVersion(ctx context.Context, secretID string, version int) (*domain.SecretVersion, error)
	ListSecretVersions(ctx context.Context, secretID string) ([]*domain.SecretVersion, error)
	CreateSecretVersion(ctx context.Context, version *domain.SecretVersion) error

	CreateProject(ctx context.Context, project *domain.Project) error
	GetProject(ctx context.Context, id string) (*domain.Project, error)
	GetProjectByName(ctx context.Context, name string) (*domain.Project, error)
	ListProjects(ctx context.Context) ([]*domain.Project, error)
	UpdateProject(ctx context.Context, project *domain.Project) error
	DeleteProject(ctx context.Context, id string) error

	CreateEnvironment(ctx context.Context, projectID string, env *domain.Environment) error
	GetEnvironment(ctx context.Context, projectID, envName string) (*domain.Environment, error)
	ListEnvironments(ctx context.Context, projectID string) ([]*domain.Environment, error)
	DeleteEnvironment(ctx context.Context, projectID, envID string) error

	BeginTx(ctx context.Context) (Transaction, error)

	Export(ctx context.Context) ([]byte, error)
	Import(ctx context.Context, data []byte) error
}

type Transaction interface {
	Commit() error
	Rollback() error
}

type Config struct {
	Type     string
	Path     string
	Host     string
	Port     int
	Database string
	User     string
	Password string
	SSLMode  string
	Options  map[string]any
}

type Filter struct {
	ProjectID   string
	Environment string
	Tags        []string
	Type        domain.SecretType
	Limit       int
	Offset      int
	SortBy      string
	SortOrder   string
}

type SyncMetadata struct {
	LastSyncTime time.Time
	RemoteURL    string
	SyncEnabled  bool
	Strategy     string
}

type Change struct {
	ID        string
	Type      ChangeType
	SecretID  string
	Data      []byte
	Timestamp time.Time
	Checksum  string
}

type ChangeType string

const (
	ChangeTypeCreate ChangeType = "create"
	ChangeTypeUpdate ChangeType = "update"
	ChangeTypeDelete ChangeType = "delete"
)

type Stats struct {
	TotalProjects     int
	TotalEnvironments int
	TotalSecrets      int
	TotalVersions     int
	StorageSize       int64
	LastBackup        *time.Time
}
