package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"vault/internal/auth"
	"vault/internal/config"
	"vault/internal/crypto"
	"vault/internal/domain"
	"vault/internal/storage"

	"github.com/spf13/cobra"
)

var (
	rotateLength int
	rotateValue  string
	rotateTags   []string
	rotateType   string
)

// NewRotateCmd creates the rotate command
func NewRotateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rotate <project>/<environment>/<key>",
		Short: "Rotate a secret value",
		Long: `Rotate a secret by generating a new random value (or using a provided one)
and archiving the previous value in version history.

Examples:
  vault rotate myapp/prod/API_KEY
  vault rotate myapp/dev/DB_PASSWORD --length 16
  vault rotate myapp/prod/CREDENTIAL --value 'new-secret-value'`,
		Args: cobra.ExactArgs(1),
		RunE: runRotate,
	}

	cmd.Flags().IntVar(&rotateLength, "length", 32, "Length of the generated random value")
	cmd.Flags().StringVar(&rotateValue, "value", "", "Use a specific value instead of generating one")
	cmd.Flags().StringSliceVar(&rotateTags, "tags", nil, "Replace tags on the secret")
	cmd.Flags().StringVar(&rotateType, "type", "", "Secret type (generic, api_key, password, etc.)")

	return cmd
}

func runRotate(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Parse path
	path := args[0]
	parts := strings.Split(path, "/")
	if len(parts) != 3 {
		return fmt.Errorf("invalid path format. Expected: project/environment/key")
	}

	projectName := parts[0]
	environmentName := NormalizeEnvironment(parts[1])
	secretKey := parts[2]

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

	// Get project
	project, err := backend.GetProjectByName(ctx, projectName)
	if err != nil {
		return fmt.Errorf("project not found: %w", err)
	}

	// Get existing secret
	secret, err := backend.GetSecret(ctx, project.ID, environmentName, secretKey)
	if err != nil {
		return fmt.Errorf("secret not found: %w", err)
	}

	// Determine the new value
	var newValue string
	if rotateValue != "" {
		newValue = rotateValue
	} else {
		token, err := crypto.GenerateRandomToken(rotateLength)
		if err != nil {
			return fmt.Errorf("failed to generate random value: %w", err)
		}
		newValue = token
	}

	if err := domain.ValidateSecretValue(newValue); err != nil {
		return err
	}

	// Update the secret with the new value
	now := time.Now()
	secret.Value = newValue
	secret.UpdatedAt = now
	secret.UpdatedBy = "rotation"
	secret.Checksum = crypto.Hash([]byte(newValue))

	if rotateType != "" {
		secret.Type = domain.SecretType(rotateType)
	}
	if rotateTags != nil {
		secret.Tags = rotateTags
	}

	if err := backend.UpdateSecret(ctx, secret); err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}

	// Create version record for the new value
	version := &domain.SecretVersion{
		ID:        domain.GenerateID(),
		SecretID:  secret.ID,
		Value:     newValue,
		Version:   secret.Version + 1,
		CreatedAt: now,
		CreatedBy: "rotation",
		Checksum:  crypto.Hash([]byte(newValue)),
	}
	if err := backend.CreateSecretVersion(ctx, version); err != nil {
		return fmt.Errorf("failed to create version: %w", err)
	}

	fmt.Printf("✓ Secret rotated: %s\n", path)
	fmt.Printf("  New version: %d\n", secret.Version+1)
	fmt.Println("  Previous values preserved in version history.")

	return nil
}
