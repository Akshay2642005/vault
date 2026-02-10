package cli

import (
	"context"
	"fmt"
	"strings"

	"vault/internal/config"
	"vault/internal/storage/sqlite"

	"github.com/spf13/cobra"
)

// NewListCmd creates the list command
func NewListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list [project]/[environment]",
		Short: "List secrets",
		Long: `List all secrets in a project and environment.

Examples:
  vault list                    # list all projects
  vault list myapp              # list environments in myapp
  vault list myapp/prod         # list secrets in myapp/prod`,
		Aliases: []string{"ls"},
		Args:    cobra.MaximumNArgs(1),
		RunE:    runList,
	}

	return cmd
}

func runList(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get storage configuration
	cfg := config.GetStorageConfig()

	// Create storage backend
	backend, err := sqlite.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to create storage backend: %w", err)
	}
	defer backend.Close()

	// Initialize backend
	if err := backend.Initialize(ctx, cfg); err != nil {
		return fmt.Errorf("failed to initialize backend: %w", err)
	}

	// Unlock vault
	password, err := promptPassword()
	if err != nil {
		return err
	}

	if _, err := backend.UnlockVault(ctx, password); err != nil {
		return fmt.Errorf("failed to unlock vault: %w", err)
	}

	// Parse arguments
	if len(args) == 0 {
		// List all projects
		return listProjects(ctx, backend)
	}

	parts := strings.Split(args[0], "/")
	if len(parts) == 1 {
		// List environments in project
		return listEnvironments(ctx, backend, parts[0])
	}

	if len(parts) == 2 {
		// Always use canonical environment name for lookup
		envName := NormalizeEnvironment(parts[1])
		return listSecrets(ctx, backend, parts[0], envName)
	}

	return fmt.Errorf("invalid argument format")
}

func listProjects(ctx context.Context, backend *sqlite.Backend) error {
	projects, err := backend.ListProjects(ctx)
	if err != nil {
		return fmt.Errorf("failed to list projects: %w", err)
	}

	if len(projects) == 0 {
		fmt.Println("No projects found.")
		return nil
	}

	fmt.Println("Projects:")
	for _, project := range projects {
		fmt.Printf("  %s", project.Name)
		if project.Description != "" {
			fmt.Printf(" - %s", project.Description)
		}
		fmt.Printf(" (%d environments)\n", len(project.Environments))
	}

	return nil
}

func listEnvironments(ctx context.Context, backend *sqlite.Backend, projectName string) error {
	project, err := backend.GetProjectByName(ctx, projectName)
	if err != nil {
		return fmt.Errorf("project not found: %w", err)
	}

	fmt.Printf("Environments in project '%s':\n", project.Name)
	for _, env := range project.Environments {
		fmt.Printf("  %s (%s)", env.Name, env.Type)
		if env.Protected {
			fmt.Print(" [protected]")
		}
		if env.RequiresMFA {
			fmt.Print(" [mfa required]")
		}
		fmt.Println()
	}

	return nil
}

func listSecrets(ctx context.Context, backend *sqlite.Backend, projectName, environmentName string) error {
	project, err := backend.GetProjectByName(ctx, projectName)
	if err != nil {
		return fmt.Errorf("project not found: %w", err)
	}

	// Only use canonical environment name
	secrets, err := backend.ListSecrets(ctx, project.ID, environmentName)
	if err != nil || len(secrets) == 0 {
		return fmt.Errorf("no secrets found in %s/%s", projectName, environmentName)
	}

	fmt.Printf("Secrets in %s/%s:\n\n", projectName, environmentName)
	fmt.Printf("%-30s %-15s %-10s %s\n", "KEY", "TYPE", "VERSION", "UPDATED")
	fmt.Println(strings.Repeat("-", 80))

	for _, secret := range secrets {
		updated := secret.UpdatedAt.Format("2006-01-02")
		fmt.Printf("%-30s %-15s v%-9d %s", secret.Key, secret.Type, secret.Version, updated)

		if secret.IsExpired() {
			fmt.Print(" ⚠ EXPIRED")
		} else if secret.NeedsRotation() {
			fmt.Print(" ⚠ NEEDS ROTATION")
		}

		fmt.Println()
	}

	fmt.Printf("\nTotal: %d secrets\n", len(secrets))

	return nil
}
