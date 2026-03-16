package cli

import (
	"context"
	"fmt"
	"os"

	"vault/internal/config"
	"vault/internal/storage"

	"github.com/spf13/cobra"
	"golang.org/x/term"
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

	// Always use PRIMARY storage as the system of record
	cfg := config.GetPrimaryStorageConfig()

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

	// Get master password
	fmt.Print("Enter master password: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	fmt.Println()

	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}

	// Confirm password
	fmt.Print("Confirm master password: ")
	confirm, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	fmt.Println()

	if string(password) != string(confirm) {
		return fmt.Errorf("passwords do not match")
	}

	// Create vault
	if err := backend.CreateVault(ctx, string(password)); err != nil {
		return fmt.Errorf("failed to create vault: %w", err)
	}

	fmt.Println("✓ Vault initialized successfully!")
	fmt.Printf("✓ Storage: %s\n", cfg.Path)
	fmt.Println("\nIMPORTANT: Store your master password securely!")
	fmt.Println("If you lose it, your secrets cannot be recovered.")

	return nil
}
