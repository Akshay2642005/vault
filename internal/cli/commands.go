package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func NewDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete <project>/<environment>/<key>",
		Short: "Delete a secret",
		Long: `Delete a secret from the vault.
    This operation cannot be undone (but versions are preserved).`,
		Args: cobra.ExactArgs(1),
		RunE: runDelete,
	}

	return cmd
}

func runDelete(cmd *cobra.Command, args []string) error {
	// _ := context.Background()
	//
	// path := args[0]
	// parts := strings.Split(path, "/")
	//
	// if len(parts) != 3 {
	// 	return fmt.Errorf("invalid path format. Expected: project/environment/key")
	// }
	//
	// _projectName := parts[0]
	// _environmentName := parts[1]
	// _secretKey := parts[2]
	//
	return nil
}
