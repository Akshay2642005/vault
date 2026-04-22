package sqlite

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"vault/internal/crypto"
	"vault/internal/domain"
	"vault/internal/storage"
)

func TestListSecretMetadataSkipsDecryption(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	backend := newTestBackend(t, ctx)

	project, err := domain.NewProject("demo", "demo project", "test")
	if err != nil {
		t.Fatalf("NewProject() error = %v", err)
	}
	if err := backend.CreateProject(ctx, project); err != nil {
		t.Fatalf("CreateProject() error = %v", err)
	}

	secret, err := domain.NewSecret(project.ID, "development", "API_KEY", "super-secret", domain.SecretTypeAPIKey, "test")
	if err != nil {
		t.Fatalf("NewSecret() error = %v", err)
	}
	secret.Tags = []string{"critical", "api"}
	secret.Checksum = crypto.Hash([]byte(secret.Value))

	if err := backend.CreateSecret(ctx, secret); err != nil {
		t.Fatalf("CreateSecret() error = %v", err)
	}

	secrets, err := backend.ListSecretMetadata(ctx, project.ID, "development")
	if err != nil {
		t.Fatalf("ListSecretMetadata() error = %v", err)
	}
	if len(secrets) != 1 {
		t.Fatalf("ListSecretMetadata() len = %d, want 1", len(secrets))
	}
	if secrets[0].Value != "" {
		t.Fatalf("ListSecretMetadata() Value = %q, want empty", secrets[0].Value)
	}
	if secrets[0].Key != secret.Key {
		t.Fatalf("ListSecretMetadata() Key = %q, want %q", secrets[0].Key, secret.Key)
	}
	if len(secrets[0].Tags) != 2 {
		t.Fatalf("ListSecretMetadata() tags len = %d, want 2", len(secrets[0].Tags))
	}
}

func TestSearchSecretMetadataSkipsDecryption(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	backend := newTestBackend(t, ctx)

	project, err := domain.NewProject("searchdemo", "search project", "test")
	if err != nil {
		t.Fatalf("NewProject() error = %v", err)
	}
	if err := backend.CreateProject(ctx, project); err != nil {
		t.Fatalf("CreateProject() error = %v", err)
	}

	secret, err := domain.NewSecret(project.ID, "development", "DATABASE_URL", "postgres://secret", domain.SecretTypeDatabase, "test")
	if err != nil {
		t.Fatalf("NewSecret() error = %v", err)
	}
	secret.Tags = []string{"database"}
	secret.Checksum = crypto.Hash([]byte(secret.Value))

	if err := backend.CreateSecret(ctx, secret); err != nil {
		t.Fatalf("CreateSecret() error = %v", err)
	}

	results, err := backend.SearchSecretMetadata(ctx, "DATABASE")
	if err != nil {
		t.Fatalf("SearchSecretMetadata() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("SearchSecretMetadata() len = %d, want 1", len(results))
	}
	if results[0].Value != "" {
		t.Fatalf("SearchSecretMetadata() Value = %q, want empty", results[0].Value)
	}
}

func TestListProjectsLoadsEnvironmentsInBatch(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	backend := newTestBackend(t, ctx)

	projectOne, err := domain.NewProject("alpha", "", "test")
	if err != nil {
		t.Fatalf("NewProject(alpha) error = %v", err)
	}
	projectTwo, err := domain.NewProject("beta", "", "test")
	if err != nil {
		t.Fatalf("NewProject(beta) error = %v", err)
	}

	if err := backend.CreateProject(ctx, projectOne); err != nil {
		t.Fatalf("CreateProject(alpha) error = %v", err)
	}
	if err := backend.CreateProject(ctx, projectTwo); err != nil {
		t.Fatalf("CreateProject(beta) error = %v", err)
	}

	projects, err := backend.ListProjects(ctx)
	if err != nil {
		t.Fatalf("ListProjects() error = %v", err)
	}
	if len(projects) != 2 {
		t.Fatalf("ListProjects() len = %d, want 2", len(projects))
	}
	for _, project := range projects {
		if len(project.Environments) != 3 {
			t.Fatalf("project %q environments len = %d, want 3", project.Name, len(project.Environments))
		}
	}
}

func newTestBackend(t *testing.T, ctx context.Context) *Backend {
	t.Helper()

	cfg := &storage.Config{
		Type: "sqlite",
		Path: filepath.Join(t.TempDir(), "vault.db"),
	}

	backend, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		_ = backend.Close()
	})

	if err := backend.Initialize(ctx, cfg); err != nil {
		if strings.Contains(err.Error(), "requires cgo") {
			t.Skipf("sqlite backend unavailable in this test environment: %v", err)
		}
		t.Fatalf("Initialize() error = %v", err)
	}
	if err := backend.CreateVault(ctx, "password123"); err != nil {
		t.Fatalf("CreateVault() error = %v", err)
	}
	if _, err := backend.UnlockVault(ctx, "password123"); err != nil {
		t.Fatalf("UnlockVault() error = %v", err)
	}

	return backend
}
