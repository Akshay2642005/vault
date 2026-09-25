package cli

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"vault/internal/auth"
	"vault/internal/config"
	"vault/internal/domain"
	"vault/internal/storage"

	"github.com/spf13/cobra"
)

// NewDiffCmd creates the diff command
func NewDiffCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diff <project>/<environment1> <environment2>",
		Short: "Compare secrets between two environments",
		Long: `Compare secrets between two environments of the same project.
Identical secrets show '=', differing secrets show '~', and secrets
present in only one environment show '+' or '-'.

Examples:
  vault diff myapp/dev staging
  vault diff myapp/dev prod
  vault diff myapp/production myapp/development`,
		Args: cobra.RangeArgs(2, 2),
		RunE: runDiff,
	}

	return cmd
}

func runDiff(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Parse the two environment references
	projName, env1Name, env2Name, err := parseDiffPaths(args[0], args[1])
	if err != nil {
		return err
	}

	env1Name = NormalizeEnvironment(env1Name)
	env2Name = NormalizeEnvironment(env2Name)

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
	project, err := backend.GetProjectByName(ctx, projName)
	if err != nil {
		return fmt.Errorf("project not found: %w", err)
	}

	// Verify both environments exist
	if _, err := backend.GetEnvironment(ctx, project.ID, env1Name); err != nil {
		return fmt.Errorf("environment '%s' not found in project '%s'", env1Name, projName)
	}
	if _, err := backend.GetEnvironment(ctx, project.ID, env2Name); err != nil {
		return fmt.Errorf("environment '%s' not found in project '%s'", env2Name, projName)
	}

	// Fetch secret metadata for both environments
	secrets1, err := backend.ListSecretMetadata(ctx, project.ID, env1Name)
	if err != nil {
		return fmt.Errorf("failed to list secrets in %s/%s: %w", projName, env1Name, err)
	}
	secrets2, err := backend.ListSecretMetadata(ctx, project.ID, env2Name)
	if err != nil {
		return fmt.Errorf("failed to list secrets in %s/%s: %w", projName, env2Name, err)
	}

	// Build maps keyed by secret key
	index1 := make(map[string]*domain.Secret, len(secrets1))
	for _, s := range secrets1 {
		index1[s.Key] = s
	}

	index2 := make(map[string]*domain.Secret, len(secrets2))
	for _, s := range secrets2 {
		index2[s.Key] = s
	}

	// Collect all keys
	keys := make(map[string]struct{})
	for k := range index1 {
		keys[k] = struct{}{}
	}
	for k := range index2 {
		keys[k] = struct{}{}
	}

	if len(keys) == 0 {
		fmt.Printf("No secrets in either environment.\n")
		return nil
	}

	// Compare and display
	var identical, differing int
	var onlyEnv1, onlyEnv2 []string

	for key := range keys {
		s1, in1 := index1[key]
		s2, in2 := index2[key]

		switch {
		case in1 && in2:
			if s1.Checksum == s2.Checksum {
				identical++
				fmt.Printf("=  %s\n", key)
			} else {
				differing++
				fmt.Printf("~  %s  (v%d -> v%d)\n", key, s1.Version, s2.Version)
			}
		case in1 && !in2:
			onlyEnv1 = append(onlyEnv1, key)
		case !in1 && in2:
			onlyEnv2 = append(onlyEnv2, key)
		}
	}

	sort.Strings(onlyEnv1)
	sort.Strings(onlyEnv2)
	for _, key := range onlyEnv1 {
		fmt.Printf("-  %s  (only in %s)\n", key, env1Name)
	}
	for _, key := range onlyEnv2 {
		fmt.Printf("+  %s  (only in %s)\n", key, env2Name)
	}

	fmt.Printf("\nSummary: %d identical, %d differ, %d only in %s, %d only in %s\n",
		identical, differing, len(onlyEnv1), env1Name, len(onlyEnv2), env2Name)

	return nil
}

// parseDiffPaths handles both "project/env1 env2" and "project/env1 project/env2" forms.
func parseDiffPaths(arg1, arg2 string) (project, env1, env2 string, err error) {
	parts1 := strings.Split(arg1, "/")
	parts2 := strings.Split(arg2, "/")

	switch {
	case len(parts1) == 2 && len(parts2) == 1:
		return parts1[0], parts1[1], parts2[0], nil
	case len(parts1) == 2 && len(parts2) == 2:
		if parts1[0] != parts2[0] {
			return "", "", "", fmt.Errorf("both environments must belong to the same project")
		}
		return parts1[0], parts1[1], parts2[1], nil
	default:
		return "", "", "", fmt.Errorf("invalid arguments. Expected: vault diff <project>/<environment1> <environment2>")
	}
}
