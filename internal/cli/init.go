package cli

import (
	"context"
	"fmt"

	"vault/internal/auth"
	"vault/internal/config"
	"vault/internal/storage"
	_ "vault/internal/storage/postgres"
	_ "vault/internal/storage/sqlite"

	"github.com/spf13/cobra"
)

// NewInitCmd creates the init command
func NewInitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize a new vault",
		Long: `Initialize a new encrypted vault.
This command creates a new vault and sets up the master password.
The password is used to derive an encryption key for all secrets.`,
		RunE: runInit,
	}

	return cmd
}

func runInit(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get storage configuration
	cfg := config.GetStorageConfig()

	// Create storage backend
	backend, err := storage.NewBackend(cfg)
	if err != nil {
		return fmt.Errorf("failed to create storage backend: %w", err)
	}
	defer backend.Close()

	// Check if already initialized
	initialized, err := backend.IsInitialized(ctx)
	if err != nil {
		return fmt.Errorf("failed to check initialization status: %w", err)
	}

	if initialized {
		return fmt.Errorf("vault is already initialized")
	}

	// Get master password using centralized auth package
	password, err := auth.PromptPassword("Enter master password: ")
	if err != nil {
		return err
	}
	if err := auth.ValidatePassword(password); err != nil {
		return err
	}
	if err := auth.ConfirmPassword(password); err != nil {
		return err
	}

	// Create vault
	if err := backend.CreateVault(ctx, password); err != nil {
		return fmt.Errorf("failed to create vault: %w", err)
	}

	fmt.Println("✓ Vault initialized successfully!")
	fmt.Printf("✓ Storage: %s\n", cfg.Path)
	fmt.Println("\nIMPORTANT: Store your master password securely!")
	fmt.Println("If you lose it, your secrets cannot be recovered.")

	return nil
}
