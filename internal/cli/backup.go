package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vault/internal/auth"
	"vault/internal/config"
	"vault/internal/storage"

	"github.com/spf13/cobra"
)

var (
	backupOutput string
	restoreForce bool
)

// NewBackupCmd creates the backup command
func NewBackupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Create a backup of the vault",
		Long: `Create a complete backup of the vault database.

The backup is a copy of the encrypted database file,
so it's safe to store but requires the master password to restore.

Examples:
  vault backup                           # Creates timestamped backup
  vault backup --output vault-backup.db  # Custom filename`,
		RunE: runBackup,
	}

	cmd.Flags().StringVarP(&backupOutput, "output", "o", "", "Backup output path. If a directory, a timestamped filename is generated inside it. If omitted, a timestamped filename is created in the current directory.")

	return cmd
}

func runBackup(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Always use PRIMARY storage as source of truth for backups/restores
	cfg := config.GetPrimaryStorageConfig()

	// Create storage backend
	backend, err := storage.NewBackend(cfg)
	if err != nil {
		return fmt.Errorf("failed to create storage backend: %w", err)
	}
	defer backend.Close()

	// Initialize backend is handled by factory, no need to call here

	// Verify vault exists
	initialized, err := backend.IsInitialized(ctx)
	if err != nil {
		return fmt.Errorf("failed to check vault: %w", err)
	}
	if !initialized {
		return fmt.Errorf("vault not initialized")
	}

	// Determine output path
	// - If --output is omitted: create "vault-backup-YYYYMMDD-HHMMSS.db" in current directory
	// - If --output is a directory (or ends with a path separator): create timestamped file inside that directory
	// - If --output is a file path: write exactly there
	timestamp := time.Now().Format("20060102-150405")
	defaultName := fmt.Sprintf("vault-backup-%s.db", timestamp)

	if backupOutput == "" {
		backupOutput = defaultName
	} else {
		outputIsDir := false

		// Treat trailing separator as explicit directory intent
		if strings.HasSuffix(backupOutput, string(os.PathSeparator)) || strings.HasSuffix(backupOutput, "/") || strings.HasSuffix(backupOutput, "\\") {
			outputIsDir = true
		} else if fi, err := os.Stat(backupOutput); err == nil && fi.IsDir() {
			outputIsDir = true
		} else if os.IsNotExist(err) {
			// If it doesn't exist but looks like a directory path, treat as directory intent.
			// (Heuristic: if it has no extension, assume directory.)
			if ext := filepath.Ext(backupOutput); ext == "" {
				outputIsDir = true
			}
		}

		if outputIsDir {
			if err := os.MkdirAll(backupOutput, 0o700); err != nil {
				return fmt.Errorf("failed to create backup directory: %w", err)
			}
			backupOutput = filepath.Join(backupOutput, defaultName)
		}
	}

	// Create parent directory if needed (for file path outputs)
	backupDir := filepath.Dir(backupOutput)
	if backupDir != "." && backupDir != "" {
		if err := os.MkdirAll(backupDir, 0o700); err != nil {
			return fmt.Errorf("failed to create backup directory: %w", err)
		}
	}

	// Read source database
	sourceData, err := os.ReadFile(cfg.Path)
	if err != nil {
		return fmt.Errorf("failed to read vault database: %w", err)
	}

	// Write backup
	if err := os.WriteFile(backupOutput, sourceData, 0o600); err != nil {
		return fmt.Errorf("failed to write backup: %w", err)
	}

	fileInfo, _ := os.Stat(backupOutput)
	size := float64(fileInfo.Size()) / 1024 // KB

	fmt.Printf("✓ Backup created: %s (%.2f KB)\n", backupOutput, size)
	fmt.Println("\nBackup is encrypted and requires your master password to restore.")
	fmt.Println("Store it securely!")

	return nil
}

// NewRestoreCmd creates the restore command
func NewRestoreCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "restore <backup-file>",
		Short: "Restore vault from a backup",
		Long: `Restore the vault from a backup file.

⚠ WARNING: This will replace your current vault!
Use --force to confirm the restore operation.

Examples:
  vault restore vault-backup-20240208.db --force`,
		Args: cobra.ExactArgs(1),
		RunE: runRestore,
	}

	cmd.Flags().BoolVar(&restoreForce, "force", false, "Force restore without confirmation (required)")
	cmd.MarkFlagRequired("force")

	return cmd
}

func runRestore(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	backupFile := args[0]

	// Verify backup file exists
	if _, err := os.Stat(backupFile); os.IsNotExist(err) {
		return fmt.Errorf("backup file not found: %s", backupFile)
	}

	// Always use PRIMARY storage as source of truth for backups/restores
	cfg := config.GetPrimaryStorageConfig()

	// Create storage backend
	backend, err := storage.NewBackend(cfg)
	if err != nil {
		return fmt.Errorf("failed to create storage backend: %w", err)
	}
	defer backend.Close()

	// Initialize backend is handled by factory, no need to call here

	// Check if current vault exists
	currentExists, err := backend.IsInitialized(ctx)
	if err != nil {
		return fmt.Errorf("failed to check current vault: %w", err)
	}

	if currentExists {
		fmt.Println("⚠ WARNING: This will replace your current vault!")
		fmt.Println("Current vault will be backed up to vault.db.pre-restore")

		if !restoreForce {
			return fmt.Errorf("use --force to confirm restore")
		}

		// Backup current vault
		currentData, err := os.ReadFile(cfg.Path)
		if err != nil {
			return fmt.Errorf("failed to read current vault: %w", err)
		}

		preRestoreBackup := cfg.Path + ".pre-restore"
		if err := os.WriteFile(preRestoreBackup, currentData, 0o600); err != nil {
			return fmt.Errorf("failed to backup current vault: %w", err)
		}

		fmt.Printf("✓ Current vault backed up to: %s\n\n", preRestoreBackup)
	}

	// Read backup file
	backupData, err := os.ReadFile(backupFile)
	if err != nil {
		return fmt.Errorf("failed to read backup file: %w", err)
	}

	// Write to vault location
	if err := os.WriteFile(cfg.Path, backupData, 0o600); err != nil {
		return fmt.Errorf("failed to restore vault: %w", err)
	}

	// Verify restored vault
	fmt.Println("Verifying restored vault...")

	password, err := auth.PromptPassword("Enter master password: ")
	if err != nil {
		return err
	}

	backend2, err := storage.NewBackend(cfg)
	if err != nil {
		return fmt.Errorf("failed to verify: %w", err)
	}
	defer backend2.Close()

	// Initialize backend is handled by factory, no need to call here

	if _, err := backend2.UnlockVault(ctx, password); err != nil {
		return fmt.Errorf("restored vault verification failed: %w\nYour original vault is at: %s.pre-restore", err, cfg.Path)
	}

	// Count projects
	projects, err := backend2.ListProjects(ctx)
	if err != nil {
		return fmt.Errorf("failed to list projects: %w", err)
	}

	fmt.Printf("\n✓ Vault restored successfully!\n")
	fmt.Printf("  Projects: %d\n", len(projects))

	if currentExists {
		fmt.Printf("\nYour previous vault is backed up at:\n  %s.pre-restore\n", cfg.Path)
	}

	return nil
}
