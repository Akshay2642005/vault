package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"vault/internal/config"
	"vault/internal/storage/sqlite"
)

var (
	showValue  bool
	jsonOutput bool
)

// NewGetCmd creates the get command
func NewGetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <project>/<environment>/<key>",
		Short: "Get a secret value",
		Long: `Retrieve a secret value from the vault.

Examples:
  vault get myapp/prod/API_KEY
  vault get myapp/dev/DB_PASSWORD --show
  vault get myapp/prod/AWS_KEY --json`,
		Args: cobra.ExactArgs(1),
		RunE: runGet,
	}

	cmd.Flags().BoolVar(&showValue, "show", false, "Show the secret value (default: masked)")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")

	return cmd
}

func runGet(cmd *cobra.Command, args []string) error {
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

	// Output
	if jsonOutput {
		// TODO: Output as JSON
		fmt.Printf(`{"key":"%s","value":"%s","type":"%s","version":%d}`+"\n",
			secret.Key, secret.Value, secret.Type, secret.Version)
	} else {
		fmt.Printf("Key:     %s\n", secret.Key)
		fmt.Printf("Type:    %s\n", secret.Type)
		fmt.Printf("Version: %d\n", secret.Version)
		fmt.Printf("Created: %s\n", secret.CreatedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("Updated: %s\n", secret.UpdatedAt.Format("2006-01-02 15:04:05"))

		if len(secret.Tags) > 0 {
			fmt.Printf("Tags:    %s\n", strings.Join(secret.Tags, ", "))
		}

		if showValue {
			fmt.Printf("\nValue:\n%s\n", secret.Value)
		} else {
			fmt.Println("\nValue: ********** (use --show to reveal)")
		}

		if secret.ExpiresAt != nil {
			fmt.Printf("\n⚠ Expires: %s\n", secret.ExpiresAt.Format("2006-01-02 15:04:05"))
		}

		if secret.RotateAt != nil {
			fmt.Printf("⚠ Rotate: %s\n", secret.RotateAt.Format("2006-01-02 15:04:05"))
		}
	}

	return nil
}
