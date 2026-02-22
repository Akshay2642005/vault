package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"vault/internal/config"
	"vault/internal/storage"

	"github.com/spf13/cobra"
)

// NewRunCmd creates the run command
func NewRunCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run <project>/<environment> -- <command> [args...]",
		Short: "Run a shell command with secrets loaded as environment variables",
		Long: `Run a shell command with secrets from the specified project/environment loaded as environment variables.

Examples:
  vault run myapp/dev -- npm run dev
  vault run myapp/prod -- python app.py
  vault run myapp/staging -- bash -c "echo $DATABASE_URL"
  vault run myapp/dev -- powershell -Command "echo $env:DATABASE_URL"
`,
		Args:               cobra.MinimumNArgs(2),
		RunE:               runRun,
		DisableFlagParsing: true, // To allow "--" and arbitrary command args
	}

	return cmd
}

func runRun(cmd *cobra.Command, args []string) error {
	// Find the "--" separator
	sepIdx := -1
	for i, arg := range args {
		if arg == "--" {
			sepIdx = i
			break
		}
	}
	if sepIdx == -1 || sepIdx == 0 || sepIdx == len(args)-1 {
		return fmt.Errorf("usage: vault run <project>/<environment> -- <command> [args...]")
	}

	path := args[0]
	commandArgs := args[sepIdx+1:]
	if len(commandArgs) == 0 {
		return fmt.Errorf("no command specified after --")
	}

	parts := strings.Split(path, "/")
	if len(parts) != 2 {
		return fmt.Errorf("invalid path format. Expected: project/environment")
	}
	projectName := parts[0]
	environmentName := NormalizeEnvironment(parts[1])

	ctx := context.Background()

	// Get storage configuration
	cfg := config.GetStorageConfig()

	// Create storage backend using factory
	backend, err := storage.NewBackend(cfg)
	if err != nil {
		return fmt.Errorf("failed to create storage backend: %w", err)
	}
	defer backend.Close()

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

	// Build environment variables
	env := os.Environ()
	for _, secret := range secrets {
		env = append(env, fmt.Sprintf("%s=%s", secret.Key, secret.Value))
	}

	// Detect shell if the command is a shell built-in or a string
	shell, shellFlag := detectShellForRun()

	var execCmd *exec.Cmd
	if len(commandArgs) == 1 {
		// Single string: treat as a shell command
		execCmd = exec.Command(shell, shellFlag, commandArgs[0])
	} else {
		// Multiple args: try to exec directly, fallback to shell if not found
		execCmd = exec.Command(commandArgs[0], commandArgs[1:]...)
		// If not found, fallback to shell
		if _, err := exec.LookPath(commandArgs[0]); err != nil {
			joined := strings.Join(commandArgs, " ")
			execCmd = exec.Command(shell, shellFlag, joined)
		}
	}

	execCmd.Env = env
	execCmd.Stdin = os.Stdin
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr

	// Forward signals to the subprocess
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	go func() {
		sig := <-sigCh
		if execCmd.Process != nil {
			_ = execCmd.Process.Signal(sig)
		}
	}()

	if err := execCmd.Run(); err != nil {
		// On Windows, Ctrl+C returns exit status 255; on Unix, it's often 130 (128+SIGINT)
		// Suppress error message if process was killed by Ctrl+C/SIGINT
		// if exitErr, ok := err.(*exec.ExitError); ok {
		// ws := exitErr.ProcessState
		// exitCode := ws.ExitCode()
		// if true {
		// User interrupted, exit silently
		return nil
		// }
		// }
		// return fmt.Errorf("command failed: %w", err)
	}

	return nil
}

// detectShellForRun returns the shell and the flag to run a command string
func detectShellForRun() (shell string, flag string) {
	// Unix-like systems
	if sh := os.Getenv("SHELL"); sh != "" {
		if strings.Contains(sh, "zsh") {
			return "zsh", "-c"
		}
		if strings.Contains(sh, "fish") {
			return "fish", "-c"
		}
		if strings.Contains(sh, "bash") {
			return "bash", "-c"
		}
		return "sh", "-c"
	}
	// Windows
	if comspec := os.Getenv("COMSPEC"); comspec != "" {
		if strings.Contains(strings.ToLower(comspec), "powershell") {
			return "powershell", "-Command"
		}
		return "cmd", "/C"
	}
	// PowerShell Core (cross-platform)
	if pwsh := os.Getenv("PSModulePath"); pwsh != "" {
		return "powershell", "-Command"
	}
	// Default fallback
	return "sh", "-c"
}
