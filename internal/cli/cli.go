// Package cli provides the command-line interface
package cli

import (
	"fmt"
	"os"

	"vault/internal/config"

	"github.com/spf13/cobra"
)

var (
	cfgFile string
	verbose bool
)

// NewRootCmd creates the root command
func NewRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "vault",
		Short: "Vault - Modern secrets management",
		Long: `Vault is a modern secrets management system built for developers.
It provides secure storage, synchronization, and management of secrets
across multiple backends with powerful Lua-based configuration.`,
		Version: config.Version,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Initialize configuration
			if err := config.Init(cfgFile); err != nil {
				fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
				os.Exit(1)
			}
		},
	}

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.config/vault/config.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")

	// Add subcommands
	rootCmd.AddCommand(NewInitCmd())
	rootCmd.AddCommand(NewSetCmd())
	rootCmd.AddCommand(NewGetCmd())
	rootCmd.AddCommand(NewListCmd())
	rootCmd.AddCommand(NewDeleteCmd())
	rootCmd.AddCommand(NewProjectCmd())
	rootCmd.AddCommand(NewVersionCmd())
	rootCmd.AddCommand(NewImportCmd())
	rootCmd.AddCommand(NewExportCmd())
	rootCmd.AddCommand(NewCompletionCmd())
	rootCmd.AddCommand(NewSearchCmd())
	rootCmd.AddCommand(NewBackupCmd())
	rootCmd.AddCommand(NewRestoreCmd())
	rootCmd.AddCommand(NewRunCmd())
	rootCmd.AddCommand(NewSyncCmd())

	return rootCmd
}

// Execute runs the root command
func Execute() {
	if err := NewRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
