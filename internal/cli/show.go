package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"vault/internal/auth"
	"vault/internal/config"
	"vault/internal/domain"
	"vault/internal/storage"

	"github.com/spf13/cobra"
)

// NewShowCmd creates the show command
func NewShowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show [project]",
		Short: "Show a summary dashboard of the vault",
		Long: `Show a summary dashboard of the vault with project counts,
expiring secrets, and secrets that need rotation.

Examples:
  vault show              # global dashboard
  vault show myapp        # dashboard for a specific project`,
		Args: cobra.MaximumNArgs(1),
		RunE: runShow,
	}

	return cmd
}

func runShow(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Always use PRIMARY storage as the system of record
	cfg := config.GetPrimaryStorageConfig()

	// Create storage backend using factory
	backend, err := storage.NewBackend(cfg)
	if err != nil {
		return fmt.Errorf("failed to create storage backend: %w", err)
	}
	defer backend.Close()

	// Unlock vault
	password, err := auth.PromptPassword("Enter master password: ")
	if err != nil {
		return err
	}

	if _, err := backend.UnlockVault(ctx, password); err != nil {
		return fmt.Errorf("failed to unlock vault: %w", err)
	}

	projects, err := backend.ListProjects(ctx)
	if err != nil {
		return fmt.Errorf("failed to list projects: %w", err)
	}

	// Filter to a single project if specified
	if len(args) == 1 {
		project, err := backend.GetProjectByName(ctx, args[0])
		if err != nil {
			return fmt.Errorf("project not found: %w", err)
		}
		projects = []*domain.Project{project}
	}

	if len(projects) == 0 {
		fmt.Println("No projects in vault.")
		return nil
	}

	now := time.Now()
	expiringSoon := now.Add(7 * 24 * time.Hour)
	recentCutoff := now.Add(-24 * time.Hour)

	var totalEnvs, totalSecrets int
	var expiring, needsRotation, recentlyUpdated []string

	for _, project := range projects {
		projectEnvs, err := backend.ListEnvironments(ctx, project.ID)
		if err != nil {
			continue
		}
		totalEnvs += len(projectEnvs)

		for _, env := range projectEnvs {
			secrets, err := backend.ListSecretMetadata(ctx, project.ID, env.Name)
			if err != nil {
				continue
			}
			totalSecrets += len(secrets)

			for _, s := range secrets {
				if s.ExpiresAt != nil && !s.ExpiresAt.After(expiringSoon) {
					expiring = append(expiring, fmt.Sprintf("%s/%s/%s (expires %s)",
						project.Name, env.Name, s.Key, s.ExpiresAt.Format("2006-01-02")))
				}
				if s.NeedsRotation() {
					needsRotation = append(needsRotation, fmt.Sprintf("%s/%s/%s",
						project.Name, env.Name, s.Key))
				}
				if s.UpdatedAt.After(recentCutoff) {
					recentlyUpdated = append(recentlyUpdated, fmt.Sprintf("%s/%s/%s (v%d)",
						project.Name, env.Name, s.Key, s.Version))
				}
			}
		}
	}

	// Header
	fmt.Println("Vault Summary")
	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("Projects:      %d\n", len(projects))
	fmt.Printf("Environments:  %d\n", totalEnvs)
	fmt.Printf("Secrets:       %d\n", totalSecrets)
	fmt.Println(strings.Repeat("-", 60))

	// Expiring soon
	fmt.Printf("\n⚠ Expiring within 7 days (%d):\n", len(expiring))
	if len(expiring) == 0 {
		fmt.Println("  None")
	} else {
		for _, e := range expiring {
			fmt.Printf("  %s\n", e)
		}
	}

	// Needs rotation
	fmt.Printf("\n⟳ Needs rotation (%d):\n", len(needsRotation))
	if len(needsRotation) == 0 {
		fmt.Println("  None")
	} else {
		for _, r := range needsRotation {
			fmt.Printf("  %s\n", r)
		}
	}

	// Recently updated
	fmt.Printf("\nUpdated in the last 24h (%d):\n", len(recentlyUpdated))
	if len(recentlyUpdated) == 0 {
		fmt.Println("  None")
	} else {
		for _, r := range recentlyUpdated {
			fmt.Printf("  %s\n", r)
		}
	}

	return nil
}
