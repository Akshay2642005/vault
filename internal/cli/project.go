package cli

import (
	"context"
	"fmt"
	"strings"

	"vault/internal/config"
	"vault/internal/domain"
	"vault/internal/storage/sqlite"

	"github.com/spf13/cobra"
)

// NewDeleteCmd creates the delete command
func NewDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete <project>/<environment>/<key>",
		Short: "Delete a secret",
		Long: `Delete a secret from the vault.
This operation cannot be undone (but versions are preserved).`,
		Args: cobra.ExactArgs(1),
		RunE: runDelete,
	}

	return cmd
}

func runDelete(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Parse path
	path := args[0]
	parts := strings.Split(path, "/")
	if len(parts) != 3 {
		return fmt.Errorf("invalid path format. Expected: project/environment/key")
	}

	projectName := parts[0]
	environmentName := parts[1]
	secretKey := parts[2]

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

	// Get project
	project, err := backend.GetProjectByName(ctx, projectName)
	if err != nil {
		return fmt.Errorf("project not found: %w", err)
	}

	// Get secret to get ID
	secret, err := backend.GetSecret(ctx, project.ID, environmentName, secretKey)
	if err != nil {
		return fmt.Errorf("secret not found: %w", err)
	}

	// Delete secret
	if err := backend.DeleteSecret(ctx, secret.ID); err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	fmt.Printf("✓ Secret deleted: %s\n", path)

	return nil
}

// NewProjectCmd creates the project command
func NewProjectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "project",
		Short:   "Manage projects",
		Long:    `Create, list, and manage projects.`,
		Aliases: []string{"pr"},
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "create <name>",
		Short: "Create a new project",
		Args:  cobra.ExactArgs(1),
		RunE:  runProjectCreate,
	})

	cmd.AddCommand(&cobra.Command{
		Use:     "list",
		Short:   "List all projects",
		Aliases: []string{"ls"},
		RunE:    runProjectList,
	})

	cmd.AddCommand(&cobra.Command{
		Use:     "delete <name>",
		Short:   "Delete a project",
		Aliases: []string{"rm"},
		Args:    cobra.ExactArgs(1),
		RunE:    runProjectDelete,
	})

	return cmd
}

func runProjectCreate(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	projectName := args[0]

	// Get storage configuration
	cfg := config.GetStorageConfig()
	backend, err := sqlite.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to create storage backend: %w", err)
	}
	defer backend.Close()

	if err := backend.Initialize(ctx, cfg); err != nil {
		return fmt.Errorf("failed to initialize backend: %w", err)
	}

	// Prompt for password
	password, err := promptPassword()
	if err != nil {
		return err
	}

	if _, err := backend.UnlockVault(ctx, password); err != nil {
		return fmt.Errorf("failed to unlock vault: %w", err)
	}

	// Check if project exists
	_, err = backend.GetProjectByName(ctx, projectName)
	if err == nil {
		return fmt.Errorf("project '%s' already exists", projectName)
	}

	// Create project
	project, err := domain.NewProject(projectName, "", "system")
	if err != nil {
		return fmt.Errorf("failed to create project object: %w", err)
	}
	if err := backend.CreateProject(ctx, project); err != nil {
		return fmt.Errorf("failed to create project: %w", err)
	}

	fmt.Printf("✓ Project '%s' created successfully\n", projectName)
	return nil
}

func runProjectDelete(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	projectName := args[0]

	// Get storage configuration
	cfg := config.GetStorageConfig()
	backend, err := sqlite.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to create storage backend: %w", err)
	}
	defer backend.Close()

	if err := backend.Initialize(ctx, cfg); err != nil {
		return fmt.Errorf("failed to initialize backend: %w", err)
	}

	// Prompt for password
	password, err := promptPassword()
	if err != nil {
		return err
	}

	if _, err := backend.UnlockVault(ctx, password); err != nil {
		return fmt.Errorf("failed to unlock vault: %w", err)
	}

	// Check if project exists
	project, err := backend.GetProjectByName(ctx, projectName)
	if err != nil {
		return fmt.Errorf("project '%s' not found", projectName)
	}

	// Delete project
	if err := backend.DeleteProject(ctx, project.ID); err != nil {
		return fmt.Errorf("failed to delete project: %w", err)
	}

	fmt.Printf("✓ Project '%s' deleted successfully\n", projectName)
	return nil
}

func runProjectList(cmd *cobra.Command, args []string) error {
	// Reuse the listProjects function
	ctx := context.Background()
	cfg := config.GetStorageConfig()
	backend, err := sqlite.New(cfg)
	if err != nil {
		return err
	}
	defer backend.Close()

	if err := backend.Initialize(ctx, cfg); err != nil {
		return err
	}

	password, err := promptPassword()
	if err != nil {
		return err
	}

	if _, err := backend.UnlockVault(ctx, password); err != nil {
		return err
	}

	return listProjects(ctx, backend)
}

// NewVersionCmd creates the version command (for secret versions)
func NewVersionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version <project>/<environment>/<key>",
		Short: "Show secret version history",
		Args:  cobra.ExactArgs(1),
		RunE:  runVersion,
	}

	return cmd
}

func runVersion(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Parse path
	path := args[0]
	parts := strings.Split(path, "/")
	if len(parts) != 3 {
		return fmt.Errorf("invalid path format. Expected: project/environment/key")
	}

	projectName := parts[0]
	environmentName := parts[1]
	secretKey := parts[2]

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

	// Get project
	project, err := backend.GetProjectByName(ctx, projectName)
	if err != nil {
		return fmt.Errorf("project not found: %w", err)
	}

	// Get secret
	secret, err := backend.GetSecret(ctx, project.ID, environmentName, secretKey)
	if err != nil {
		return fmt.Errorf("secret not found: %w", err)
	}

	// Get versions
	versions, err := backend.ListSecretVersions(ctx, secret.ID)
	if err != nil {
		return fmt.Errorf("failed to get versions: %w", err)
	}

	fmt.Printf("Version history for %s:\n\n", path)
	fmt.Printf("%-10s %-20s %s\n", "VERSION", "CREATED", "CREATED BY")
	fmt.Println(strings.Repeat("-", 60))

	for _, v := range versions {
		created := v.CreatedAt.Format("2006-01-02 15:04:05")
		fmt.Printf("v%-9d %-20s %s\n", v.Version, created, v.CreatedBy)
	}

	fmt.Printf("\nTotal: %d versions\n", len(versions))

	return nil
}
