package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
	"vault/internal/config"
	"vault/internal/crypto"
	"vault/internal/domain"
	"vault/internal/storage/sqlite"
)

var (
	secretType  string
	secretTags  []string
	expiresIn   string
	rotateAfter string
)

// NewSetCmd creates the set command
func NewSetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set <project>/<environment>/<key> [value]",
		Short: "Set a secret value",
		Long: `Set or update a secret value.
If no value is provided, you'll be prompted to enter it securely.

Examples:
  vault set myapp/prod/API_KEY secret123
  vault set myapp/dev/DB_PASSWORD    # prompts for value
  vault set myapp/prod/AWS_KEY --type api_key --tags aws,critical
  vault set myapp/prod/TEMP_TOKEN --expires-in 24h`,
		Args: cobra.RangeArgs(1, 2),
		RunE: runSet,
	}

	cmd.Flags().StringVar(&secretType, "type", "generic", "Secret type (generic, api_key, password, etc.)")
	cmd.Flags().StringSliceVar(&secretTags, "tags", []string{}, "Tags for the secret")
	cmd.Flags().StringVar(&expiresIn, "expires-in", "", "Expiration duration (e.g., 24h, 7d, 30d)")
	cmd.Flags().StringVar(&rotateAfter, "rotate-after", "", "Auto-rotation duration (e.g., 30d, 90d)")

	return cmd
}

func runSet(cmd *cobra.Command, args []string) error {
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

	// Validate secret key
	if err := domain.ValidateSecretKey(secretKey); err != nil {
		return err
	}

	// Get secret value
	var value string
	if len(args) == 2 {
		value = args[1]
	} else {
		// Prompt for value
		fmt.Print("Enter secret value: ")
		valueBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return fmt.Errorf("failed to read value: %w", err)
		}
		fmt.Println()
		value = string(valueBytes)
	}

	if value == "" {
		return fmt.Errorf("secret value cannot be empty")
	}

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

	// Get or create project
	project, err := backend.GetProjectByName(ctx, projectName)
	if err != nil {
		// Create project if it doesn't exist
		project, err = domain.NewProject(projectName, "", "system")
		if err != nil {
			return err
		}

		if err := backend.CreateProject(ctx, project); err != nil {
			return fmt.Errorf("failed to create project: %w", err)
		}
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

	// Check if secret exists
	existing, err := backend.GetSecret(ctx, project.ID, environmentName, secretKey)
	if err == nil {
		// Update existing secret
		existing.Value = value
		existing.Type = domain.SecretType(secretType)
		existing.Tags = secretTags
		existing.UpdatedAt = time.Now()
		existing.UpdatedBy = "system"
		existing.Checksum = crypto.Hash([]byte(value))

		// Parse expiration
		if expiresIn != "" {
			duration, err := parseDuration(expiresIn)
			if err != nil {
				return fmt.Errorf("invalid expires-in: %w", err)
			}
			expiryTime := time.Now().Add(duration)
			existing.ExpiresAt = &expiryTime
		}

		// Parse rotation
		if rotateAfter != "" {
			duration, err := parseDuration(rotateAfter)
			if err != nil {
				return fmt.Errorf("invalid rotate-after: %w", err)
			}
			rotateTime := time.Now().Add(duration)
			existing.RotateAt = &rotateTime
		}

		if err := backend.UpdateSecret(ctx, existing); err != nil {
			return fmt.Errorf("failed to update secret: %w", err)
		}

		// Create version
		version := &domain.SecretVersion{
			ID:        domain.GenerateID(),
			SecretID:  existing.ID,
			Value:     value,
			Version:   existing.Version,
			CreatedAt: time.Now(),
			CreatedBy: "system",
			Checksum:  crypto.Hash([]byte(value)),
		}

		if err := backend.CreateSecretVersion(ctx, version); err != nil {
			return fmt.Errorf("failed to create version: %w", err)
		}

		fmt.Printf("✓ Secret updated: %s\n", path)
		fmt.Printf("  Version: %d\n", existing.Version)
	} else {
		// Create new secret
		secret, err := domain.NewSecret(
			project.ID,
			environmentName,
			secretKey,
			value,
			domain.SecretType(secretType),
			"system",
		)
		if err != nil {
			return err
		}

		secret.Tags = secretTags
		secret.Checksum = crypto.Hash([]byte(value))

		// Parse expiration
		if expiresIn != "" {
			duration, err := parseDuration(expiresIn)
			if err != nil {
				return fmt.Errorf("invalid expires-in: %w", err)
			}
			expiryTime := time.Now().Add(duration)
			secret.ExpiresAt = &expiryTime
		}

		// Parse rotation
		if rotateAfter != "" {
			duration, err := parseDuration(rotateAfter)
			if err != nil {
				return fmt.Errorf("invalid rotate-after: %w", err)
			}
			rotateTime := time.Now().Add(duration)
			secret.RotateAt = &rotateTime
		}

		if err := backend.CreateSecret(ctx, secret); err != nil {
			return fmt.Errorf("failed to create secret: %w", err)
		}

		fmt.Printf("✓ Secret created: %s\n", path)
		fmt.Printf("  Type: %s\n", secret.Type)
		if len(secret.Tags) > 0 {
			fmt.Printf("  Tags: %s\n", strings.Join(secret.Tags, ", "))
		}
	}

	return nil
}

func promptPassword() (string, error) {
	fmt.Print("Enter master password: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}
	fmt.Println()
	return string(password), nil
}

func parseDuration(s string) (time.Duration, error) {
	// Simple duration parser supporting d (days) and h (hours)
	if before, ok := strings.CutSuffix(s, "d"); ok {
		days := before
		var d int
		_, err := fmt.Sscanf(days, "%d", &d)
		if err != nil {
			return 0, err
		}
		return time.Duration(d) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}
