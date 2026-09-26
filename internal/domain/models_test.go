package domain

import (
	"strings"
	"testing"
	"time"
)

func TestValidateProjectName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"simple", "myapp", false},
		{"with dashes", "my-app", false},
		{"with underscores", "my_app", false},
		{"leading underscore", "_app", false},
		{"alphanumeric", "app2", false},
		{"surrounding whitespace trimmed", "  a  ", false},
		{"exactly 256 chars", strings.Repeat("a", 256), false},
		{"empty", "", true},
		{"whitespace only", " ", true},
		{"starts with digit", "2app", true},
		{"contains space", "my app", true},
		{"contains dot", "my.app", true},
		{"too long", strings.Repeat("a", 257), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProjectName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateProjectName(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateEnvironmentName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"production", "production", false},
		{"custom", "my-env", false},
		{"trimmed", "  dev  ", false},
		{"exactly 64 chars", strings.Repeat("a", 64), false},
		{"empty", "", true},
		{"too long", strings.Repeat("a", 65), true},
		{"contains space", "my env", true},
		{"starts with digit", "1prod", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEnvironmentName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateEnvironmentName(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateSecretKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"plain", "API_KEY", false},
		{"with dots", "db.url", false},
		{"exactly 256 chars", strings.Repeat("a", 256), false},
		{"empty", "", true},
		{"too long", strings.Repeat("a", 257), true},
		{"contains equals", "A=B", true},
		{"contains newline", "A\nB", true},
		{"contains carriage return", "A\rB", true},
		{"contains tab", "A\tB", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSecretKey(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateSecretKey(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateSecretValue(t *testing.T) {
	t.Parallel()

	if err := ValidateSecretValue("anything"); err != nil {
		t.Fatalf("ValidateSecretValue() error = %v, want nil", err)
	}
	if err := ValidateSecretValue(strings.Repeat("a", 1024*1024)); err != nil {
		t.Fatalf("ValidateSecretValue(1MB) error = %v, want nil (limit is exclusive)", err)
	}
	if err := ValidateSecretValue(strings.Repeat("a", 1024*1024+1)); err == nil {
		t.Fatal("ValidateSecretValue(1MB+1) error = nil, want too-long error")
	}
}

func TestNewSecret(t *testing.T) {
	t.Parallel()

	secret, err := NewSecret("proj1", "development", "API_KEY", "value", SecretTypeAPIKey, "alice")
	if err != nil {
		t.Fatalf("NewSecret() error = %v", err)
	}
	if secret.ID == "" {
		t.Fatal("ID is empty")
	}
	if len(secret.ID) != 32 {
		t.Fatalf("ID length = %d, want 32 (16 random bytes hex-encoded)", len(secret.ID))
	}
	if secret.ProjectID != "proj1" || secret.Environment != "development" || secret.Key != "API_KEY" {
		t.Fatalf("identity = %s/%s/%s, want proj1/development/API_KEY", secret.ProjectID, secret.Environment, secret.Key)
	}
	if secret.Value != "value" || secret.Type != SecretTypeAPIKey {
		t.Fatalf("value/type = %q/%q, want %q/%q", secret.Value, secret.Type, "value", SecretTypeAPIKey)
	}
	if secret.Version != 1 {
		t.Fatalf("Version = %d, want 1", secret.Version)
	}
	if secret.CreatedBy != "alice" || secret.Owner != "alice" {
		t.Fatalf("CreatedBy/Owner = %q/%q, want alice/alice", secret.CreatedBy, secret.Owner)
	}
	if secret.SyncStatus != SyncStatusNotEnabled {
		t.Fatalf("SyncStatus = %q, want %q", secret.SyncStatus, SyncStatusNotEnabled)
	}
	if !secret.CreatedAt.Equal(secret.UpdatedAt) {
		t.Fatalf("CreatedAt %v != UpdatedAt %v (single clock read)", secret.CreatedAt, secret.UpdatedAt)
	}
	// Tags/Metadata must be non-nil so callers can append without nil checks.
	if secret.Tags == nil || secret.Metadata == nil {
		t.Fatal("Tags/Metadata must be initialized non-nil")
	}
	if len(secret.Tags) != 0 {
		t.Fatalf("Tags = %v, want empty", secret.Tags)
	}

	// Invalid inputs surface wrapped, distinguishable errors.
	if _, err := NewSecret("p", "development", "", "v", SecretTypeGeneric, "a"); err == nil || !strings.Contains(err.Error(), "invalid key:") {
		t.Fatalf("NewSecret(bad key) error = %v, want wrapped invalid key error", err)
	}
	if _, err := NewSecret("p", "development", "K", strings.Repeat("x", 1024*1024+1), SecretTypeGeneric, "a"); err == nil || !strings.Contains(err.Error(), "invalid value:") {
		t.Fatalf("NewSecret(bad value) error = %v, want wrapped invalid value error", err)
	}
}

func TestNewProject(t *testing.T) {
	t.Parallel()

	proj, err := NewProject("myapp", "test project", "bob")
	if err != nil {
		t.Fatalf("NewProject() error = %v", err)
	}
	if proj.ID == "" {
		t.Fatal("ID is empty")
	}
	if proj.Name != "myapp" || proj.Description != "test project" || proj.CreatedBy != "bob" {
		t.Fatalf("project fields wrong: %+v", proj)
	}
	if !proj.CreatedAt.Equal(proj.UpdatedAt) {
		t.Fatalf("CreatedAt %v != UpdatedAt %v", proj.CreatedAt, proj.UpdatedAt)
	}
	if proj.Team == nil {
		t.Fatal("Team must be initialized non-nil")
	}

	wantEnvs := []EnvironmentType{EnvDevelopment, EnvStaging, EnvProduction}
	if len(proj.Environments) != len(wantEnvs) {
		t.Fatalf("environment count = %d, want %d", len(proj.Environments), len(wantEnvs))
	}
	ids := map[string]bool{}
	for i, env := range proj.Environments {
		if env.Type != wantEnvs[i] {
			t.Fatalf("environments[%d].Type = %q, want %q", i, env.Type, wantEnvs[i])
		}
		if env.ID == "" || ids[env.ID] {
			t.Fatalf("environment %q has empty or duplicate ID", env.Name)
		}
		ids[env.ID] = true
	}
	// Only production is protected and MFA-gated.
	prod := proj.Environments[2]
	if !prod.Protected || !prod.RequiresMFA {
		t.Fatalf("production Protected/RequiresMFA = %v/%v, want true/true", prod.Protected, prod.RequiresMFA)
	}
	for _, env := range proj.Environments[:2] {
		if env.Protected || env.RequiresMFA {
			t.Fatalf("%s must not be protected/MFA", env.Name)
		}
	}

	if _, err := NewProject("bad name", "", "bob"); err == nil || !strings.Contains(err.Error(), "invalid project name:") {
		t.Fatalf("NewProject(bad name) error = %v, want wrapped invalid name error", err)
	}
}

func TestSecretPath(t *testing.T) {
	t.Parallel()

	s := &Secret{ProjectID: "proj1", Environment: "development", Key: "API_KEY"}
	if got := s.SecretPath(); got != "proj1developmentAPI_KEY" {
		t.Fatalf("SecretPath() = %q, want %q", got, "proj1developmentAPI_KEY")
	}
}

func TestSecretIsExpired(t *testing.T) {
	t.Parallel()

	s := &Secret{}
	if s.IsExpired() {
		t.Fatal("IsExpired() = true for nil ExpiresAt, want false")
	}
	past := time.Now().Add(-time.Hour)
	s.ExpiresAt = &past
	if !s.IsExpired() {
		t.Fatal("IsExpired() = false for past ExpiresAt, want true")
	}
	future := time.Now().Add(time.Hour)
	s.ExpiresAt = &future
	if s.IsExpired() {
		t.Fatal("IsExpired() = true for future ExpiresAt, want false")
	}
}

func TestSecretNeedsRotation(t *testing.T) {
	t.Parallel()

	s := &Secret{}
	if s.NeedsRotation() {
		t.Fatal("NeedsRotation() = true for nil RotateAt, want false")
	}
	past := time.Now().Add(-time.Hour)
	s.RotateAt = &past
	if !s.NeedsRotation() {
		t.Fatal("NeedsRotation() = false for past RotateAt, want true")
	}
	future := time.Now().Add(time.Hour)
	s.RotateAt = &future
	if s.NeedsRotation() {
		t.Fatal("NeedsRotation() = true for future RotateAt, want false")
	}
}

func TestSecretCloneIsDeepCopy(t *testing.T) {
	t.Parallel()

	orig := &Secret{
		Key:         "API_KEY",
		Tags:        []string{"a"},
		Metadata:    map[string]any{"k": "v"},
		Permissions: []string{"read"},
	}

	clone := orig.Clone()
	if clone == orig {
		t.Fatal("Clone() returned the same pointer")
	}
	if clone.Key != orig.Key {
		t.Fatalf("clone Key = %q, want %q", clone.Key, orig.Key)
	}

	// Mutating the clone must never reach the original.
	clone.Tags[0] = "mutated"
	clone.Metadata["k"] = "mutated"
	clone.Permissions[0] = "write"

	if orig.Tags[0] != "a" || orig.Metadata["k"] != "v" || orig.Permissions[0] != "read" {
		t.Fatalf("original mutated via clone: tags=%v meta=%v perms=%v", orig.Tags, orig.Metadata, orig.Permissions)
	}
}

func TestSecretCloneNilCollections(t *testing.T) {
	t.Parallel()

	orig := &Secret{Key: "API_KEY"}
	clone := orig.Clone()
	if clone.Tags != nil {
		t.Fatalf("clone Tags = %v, want nil", clone.Tags)
	}
	if clone.Metadata != nil {
		t.Fatalf("clone Metadata = %v, want nil", clone.Metadata)
	}
	if clone.Permissions != nil {
		t.Fatalf("clone Permissions = %v, want nil", clone.Permissions)
	}
}
