package cli

import (
	"context"
	"fmt"
	"strings"

	"vault/internal/config"
	"vault/internal/storage/sqlite"
	ft "vault/internal/utils/formatters"

	"github.com/spf13/cobra"
)

var (
	exportFormat      string
	exportMask        bool
	exportIncludeMeta bool
	exportOutput      string
)

// NewExportCmd creates the export command
func NewExportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export <project>/<environment>",
		Short: "Export secrets to a file",
		Long: `Export secrets to a file in various formats.

Supported formats:
  - .env files (KEY=VALUE format)
  - JSON files (array of secret objects)
  - YAML files (array of secret mappings)

Examples:
  vault export myapp/dev --output .env
  vault export myapp/prod --format json --output secrets.json
  vault export myapp/staging --format yaml --mask --output config.yaml
  vault export myapp/dev --include-meta --output backup.json`,
		Args: cobra.ExactArgs(1),
		RunE: runExport,
	}

	cmd.Flags().StringVarP(&exportOutput, "output", "o", "", "Output file (required)")
	cmd.Flags().StringVar(&exportFormat, "format", "", "Format: env, json, yaml (auto-detected from output if not specified)")
	cmd.Flags().BoolVar(&exportMask, "mask", false, "Mask secret values (replace with ********)")
	cmd.Flags().BoolVar(&exportIncludeMeta, "include-meta", false, "Include metadata (type, tags, etc.) - JSON/YAML only")

	cmd.MarkFlagRequired("output")

	return cmd
}

func runExport(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Parse path
	path := args[0]
	parts := strings.Split(path, "/")
	if len(parts) != 2 {
		return fmt.Errorf("invalid path format. Expected: project/environment")
	}

	projectName := parts[0]
	environmentName := NormalizeEnvironment(parts[1])

	// Detect or use specified format
	var format ft.Format
	if exportFormat != "" {
		format = ft.Format(exportFormat)
	} else {
		format = ft.DetectFormat(exportOutput)
	}

	fmt.Printf("Exporting secrets from %s/%s to %s (%s format)...\n",
		projectName, environmentName, exportOutput, format)

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

	// Export options
	opts := ft.ExportOptions{
		Format:      format,
		ProjectID:   project.ID,
		Environment: environmentName,
		IncludeMeta: exportIncludeMeta,
		MaskValues:  exportMask,
	}

	// Export based on format
	switch format {
	case ft.FormatEnv:
		err = ft.ExportEnv(exportOutput, secrets, opts)
	case ft.FormatJSON:
		err = ft.ExportJSON(exportOutput, secrets, opts)
	case ft.FormatYAML:
		err = ft.ExportYAML(exportOutput, secrets, opts)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}

	if err != nil {
		return fmt.Errorf("export failed: %w", err)
	}

	fmt.Printf("\n✓ Exported %d secrets to %s\n", len(secrets), exportOutput)

	if exportMask {
		fmt.Println("  Note: Values are masked (********)")
	} else {
		fmt.Println("  ⚠ Warning: File contains unencrypted secrets!")
		fmt.Println("  Protect this file and delete it when no longer needed.")
	}

	return nil
}
