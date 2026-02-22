package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"vault/internal/config"
	"vault/internal/crypto"
	"vault/internal/domain"
	"vault/internal/storage"
	ft "vault/internal/utils/formatters"

	"github.com/spf13/cobra"
)

var (
	importFormat     string
	importOverwrite  bool
	importSkipErrors bool
)

// NewImportCmd creates the import command
func NewImportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import <project>/<environment> <file>",
		Short: "Import secrets from a file",
		Long: `Import secrets from a file in various formats.

Supported formats:
  - .env files (KEY=VALUE format)
  - JSON files (array of {key, value, ...})
  - YAML files (array of key/value mappings)

Format is auto-detected from file extension, or use --format flag.

Examples:
  vault import myapp/dev .env
  vault import myapp/prod secrets.json --format json
  vault import myapp/staging config.yaml
  vault import myapp/dev .env.example --overwrite --skip-errors`,
		Args: cobra.ExactArgs(2),
		RunE: runImport,
	}

	cmd.Flags().StringVar(&importFormat, "format", "", "Format: env, json, yaml (auto-detected if not specified)")
	cmd.Flags().BoolVar(&importOverwrite, "overwrite", false, "Overwrite existing secrets")
	cmd.Flags().BoolVar(&importSkipErrors, "skip-errors", false, "Skip invalid entries instead of failing")

	return cmd
}

func runImport(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Parse path
	path := args[0]
	filepath := args[1]

	parts := strings.Split(path, "/")
	if len(parts) != 2 {
		return fmt.Errorf("invalid path format. Expected: project/environment")
	}

	projectName := parts[0]
	environmentName := NormalizeEnvironment(parts[1])

	// Detect or use specified format
	var format ft.Format
	if importFormat != "" {
		format = ft.Format(importFormat)
	} else {
		format = ft.DetectFormat(filepath)
	}

	fmt.Printf("Importing secrets from %s (%s format)...\n", filepath, format)

	// Get storage configuration
	cfg := config.GetStorageConfig()

	// Create storage backend
	backend, err := storage.NewBackend(cfg)
	if err != nil {
		return fmt.Errorf("failed to create storage backend: %w", err)
	}
	defer backend.Close()

	// Unlock vault
	password, err := promptPassword()
	if err != nil {
		return err
	}

	if _, err := backend.UnlockVault(ctx, password); err != nil {
		return fmt.Errorf("failed to unlock vault: %w", err)
	}

	// Get or create project
	project, err := backend.GetProjectByName(ctx, projectName)
	if err != nil {
		return fmt.Errorf("project '%s' not found. Create it first with: vault project create %s", projectName, projectName)
	}

	// Verify environment exists
	found := false
	for _, env := range project.Environments {
		if env.Name == environmentName {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("environment '%s' not found in project '%s'", environmentName, projectName)
	}

	// Import secrets based on format
	opts := ft.ImportOptions{
		Format:      format,
		ProjectID:   project.ID,
		Environment: environmentName,
		Overwrite:   importOverwrite,
		SkipErrors:  importSkipErrors,
	}

	var secrets []domain.Secret
	switch format {
	case ft.FormatEnv:
		secrets, err = ft.ImportEnv(filepath, opts)
	case ft.FormatJSON:
		secrets, err = ft.ImportJSON(filepath, opts)
	case ft.FormatYAML:
		secrets, err = ft.ImportYAML(filepath, opts)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}

	if err != nil {
		return fmt.Errorf("import failed: %w", err)
	}

	// Store secrets
	created := 0
	updated := 0
	skipped := 0

	for _, secret := range secrets {
		// Check if secret already exists
		existing, err := backend.GetSecret(ctx, project.ID, environmentName, secret.Key)

		if err == nil {
			// Secret exists
			if !importOverwrite {
				skipped++
				if verbose {
					fmt.Printf("  ⊘ Skipped %s (already exists, use --overwrite to replace)\n", secret.Key)
				}
				continue
			}

			// Update existing
			existing.Value = secret.Value
			existing.Type = secret.Type
			existing.Tags = secret.Tags
			existing.Metadata = secret.Metadata
			existing.UpdatedAt = time.Now()
			existing.UpdatedBy = "import"
			existing.Checksum = crypto.Hash([]byte(secret.Value))

			if err := backend.UpdateSecret(ctx, existing); err != nil {
				if importSkipErrors {
					fmt.Printf("  ✗ Failed to update %s: %v\n", secret.Key, err)
					continue
				}
				return fmt.Errorf("failed to update secret %s: %w", secret.Key, err)
			}

			// Create version
			version := &domain.SecretVersion{
				ID:        domain.GenerateID(),
				SecretID:  existing.ID,
				Value:     secret.Value,
				Version:   existing.Version,
				CreatedAt: time.Now(),
				CreatedBy: "import",
				Checksum:  crypto.Hash([]byte(secret.Value)),
			}

			if err := backend.CreateSecretVersion(ctx, version); err != nil {
				// Version creation failure is not critical
				if verbose {
					fmt.Printf("  ⚠ Warning: Failed to create version for %s\n", secret.Key)
				}
			}

			updated++
			if verbose {
				fmt.Printf("  ✓ Updated %s\n", secret.Key)
			}
		} else {
			// Create new secret
			if err := backend.CreateSecret(ctx, &secret); err != nil {
				if importSkipErrors {
					fmt.Printf("  ✗ Failed to create %s: %v\n", secret.Key, err)
					continue
				}
				return fmt.Errorf("failed to create secret %s: %w", secret.Key, err)
			}

			created++
			if verbose {
				fmt.Printf("  ✓ Created %s\n", secret.Key)
			}
		}
	}

	// Summary
	fmt.Println("\nImport complete:")
	fmt.Printf("  Created: %d\n", created)
	if updated > 0 {
		fmt.Printf("  Updated: %d\n", updated)
	}
	if skipped > 0 {
		fmt.Printf("  Skipped: %d (use --overwrite to replace)\n", skipped)
	}
	fmt.Printf("  Total:   %d\n", created+updated+skipped)

	return nil
}
