package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"vault/internal/config"
	"vault/internal/domain"
	"vault/internal/storage/sqlite"

	"github.com/spf13/cobra"
)

var (
	envShell string
	envExec  []string
)

// NewEnvCmd creates the env command
func NewEnvCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "env <project>/<environment>",
		Short: "Export secrets as environment variables",
		Long: `Export secrets as environment variables for use in shell.

This command outputs shell commands to set environment variables.
Eval the output in your shell to load the secrets.

Examples:
  # Bash/Zsh
  eval $(vault env myapp/dev)

  # Fish
  vault env myapp/dev --shell fish | source

  # Execute command with secrets
  vault env myapp/dev --exec -- npm start
  vault env myapp/prod --exec -- python app.py

  # PowerShell
  vault env myapp/dev --shell powershell | Invoke-Expression`,
		Args: cobra.ExactArgs(1),
		RunE: runEnv,
	}

	cmd.Flags().StringVar(&envShell, "shell", "bash", "Shell format: bash, zsh, fish, powershell")
	cmd.Flags().StringSliceVar(&envExec, "exec", []string{}, "Execute command with secrets loaded")

	return cmd
}

func runEnv(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Parse path
	path := args[0]
	parts := strings.Split(path, "/")
	if len(parts) != 2 {
		return fmt.Errorf("invalid path format. Expected: project/environment")
	}

	projectName := parts[0]
	environmentName := NormalizeEnvironment(parts[1])

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
		return fmt.Errorf("project '%s' not found", projectName)
	}

	// Get secrets
	secrets, err := backend.ListSecrets(ctx, project.ID, environmentName)
	if err != nil {
		return fmt.Errorf("failed to list secrets: %w", err)
	}

	if len(secrets) == 0 {
		return fmt.Errorf("no secrets found in %s/%s", projectName, environmentName)
	}

	// If --exec is provided, execute command with environment
	if len(envExec) > 0 {
		return executeWithEnv(secrets, envExec)
	}

	// Otherwise, output shell commands
	outputShellCommands(secrets, envShell)

	return nil
}

func outputShellCommands(secrets []*domain.Secret, shell string) {
	switch strings.ToLower(shell) {
	case "bash", "zsh", "sh":
		for _, secret := range secrets {
			// Escape single quotes in value
			value := strings.ReplaceAll(secret.Value, "'", "'\\''")
			fmt.Printf("export %s='%s'\n", secret.Key, value)
		}

	case "fish":
		for _, secret := range secrets {
			// Escape single quotes in value
			value := strings.ReplaceAll(secret.Value, "'", "\\'")
			fmt.Printf("set -x %s '%s'\n", secret.Key, value)
		}

	case "powershell", "pwsh":
		for _, secret := range secrets {
			// Escape special PowerShell characters
			value := strings.ReplaceAll(secret.Value, "'", "''")
			fmt.Printf("$env:%s = '%s'\n", secret.Key, value)
		}

	default:
		// Default to bash format
		for _, secret := range secrets {
			value := strings.ReplaceAll(secret.Value, "'", "'\\''")
			fmt.Printf("export %s='%s'\n", secret.Key, value)
		}
	}
}

func executeWithEnv(secrets []*domain.Secret, command []string) error {
	if len(command) == 0 {
		return fmt.Errorf("no command specified")
	}

	// Build environment variables
	env := os.Environ()
	for _, secret := range secrets {
		env = append(env, fmt.Sprintf("%s=%s", secret.Key, secret.Value))
	}

	// Execute command
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("command failed: %w", err)
	}

	return nil
}
