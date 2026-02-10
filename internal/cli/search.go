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

var (
	searchProjectName string
	searchAll         bool
	searchLimit       int
)

func NewSearchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "search <query>",
		Short: "Search for secrets",
		Long: `Search for secrets using full-text search.

Searches secret keys, tags, and optionally project/environment names.

Examples:
  vault search API          # Search in current context
  vault search database     # Find all database-related secrets
  vault search AWS --all    # Search across all projects
  vault search token --limit 10
  vault search token --project myapp
  vault find token -p myapp`,
		Aliases: []string{"find"},
		Args:    cobra.ExactArgs(1),
		RunE:    runSearch,
	}

	cmd.Flags().BoolVar(&searchAll, "all", false, "Search across all projects and environments")
	cmd.Flags().StringVarP(&searchProjectName, "project", "p", "", "Limit search to a specific project name")
	cmd.Flags().IntVar(&searchLimit, "limit", 50, "Maximum number of results")

	return cmd
}

func runSearch(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	query := args[0]

	fmt.Printf("Searching for secrets matching: %s\n\n", query)

	cfg := config.GetStorageConfig()
	backend, err := sqlite.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to create storage backend: %w", err)
	}

	defer backend.Close()

	if err := backend.Initialize(ctx, cfg); err != nil {
		return fmt.Errorf("failed to initialized backend: %w", err)
	}

	password, err := promptPassword()
	if err != nil {
		return err
	}

	if _, err := backend.UnlockVault(ctx, password); err != nil {
		return fmt.Errorf("failed to unlock vault: %w", err)
	}

	secrets, err := backend.SearchSecrets(ctx, query)
	if err != nil {
		fmt.Printf("No secrets found matching your query: %v\n", err)
		return nil
	}

	// If --project is specified, filter secrets by project name
	if searchProjectName != "" {
		project, err := backend.GetProjectByName(ctx, searchProjectName)
		if err != nil {
			return fmt.Errorf("project '%s' not found: %w", searchProjectName, err)
		}
		filtered := secrets[:0]
		for _, secret := range secrets {
			if secret.ProjectID == project.ID {
				filtered = append(filtered, secret)
			}
		}
		secrets = filtered
	}

	if len(secrets) > searchLimit {
		secrets = secrets[:searchLimit]
		fmt.Printf("Showing first %d results. Use --limit to see more.\n\n", searchLimit)
	}

	projectSecrets := make(map[string]map[string][]*domain.Secret)
	for _, secret := range secrets {
		if projectSecrets[secret.ProjectID] == nil {
			projectSecrets[secret.ProjectID] = make(map[string][]*domain.Secret)
		}
		projectSecrets[secret.ProjectID][secret.Environment] = append(
			projectSecrets[secret.ProjectID][secret.Environment],
			secret,
		)
	}

	totalCount := 0
	for projectID, envs := range projectSecrets {
		project, err := backend.GetProject(ctx, projectID)
		if err != nil {
			continue
		}
		fmt.Printf("Project: %s\n", project.Name)
		for envName, envSecrets := range envs {
			fmt.Printf("  Environment: %s\n", envName)
			for _, secret := range envSecrets {
				totalCount++
				fmt.Printf("    • %s", secret.Key)
				if secret.Type != domain.SecretTypeGeneric {
					fmt.Printf(" [%s]", secret.Type)
				}
				if len(secret.Tags) > 0 {
					fmt.Printf(" {%s}", strings.Join(secret.Tags, ", "))
				}
				fmt.Println()
			}
		}
		fmt.Println()
	}

	fmt.Printf("Found %d secret(s)\n", totalCount)

	return nil
}
