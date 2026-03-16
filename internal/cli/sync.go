package cli

import (
	"context"
	"fmt"
	"strings"

	"vault/internal/auth"
	synccli "vault/internal/cli/sync"
	"vault/internal/config"
	"vault/internal/storage"
	"vault/internal/storage/roles"
	syncengine "vault/internal/sync/engine"

	"github.com/spf13/cobra"
)

var (
	syncFlagDirection    string
	syncFlagStrategy     string
	syncFlagDryRun       bool
	syncFlagSince        string
	syncFlagApprove      bool
	syncFlagDeleteRemote bool
)

// NewSyncCmd creates the sync command.
//
// This command syncs PRIMARY (SQLite) with an optional SYNC target (Postgres).
// If storage.sync.postgres isn't configured, sync is disabled.
func NewSyncCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Sync primary SQLite vault with configured Postgres sync target",
		Long: `Sync your primary SQLite vault with the configured Postgres sync target.

Storage roles:
- PRIMARY: SQLite (system of record)
- SYNC:    optional Postgres target (if not configured, sync is disabled)

Subcommands:
- enable: initialize the configured Postgres sync target using the same master password

Directions:
- push: local -> remote
- pull: remote -> local
- both: bidirectional reconciliation

Conflict strategies:
- fail (default): detect conflict and abort
- prefer-local: local wins
- prefer-remote: remote wins
- prefer-latest: chooses the newest by UpdatedAt (cannot resolve exact ties)

Approval:
- By default, applying changes requires explicit confirmation.
- Use --approve to skip the interactive prompt.`,
	}

	cmd.AddCommand(NewSyncEnableCmd())
	cmd.AddCommand(NewSyncRunCmd())

	return cmd
}

// NewSyncRunCmd runs a sync operation (default subcommand behavior moved here to keep `sync` extensible).
func NewSyncRunCmd() *cobra.Command {
	runCmd := &cobra.Command{
		Use:   "run [project/environment]",
		Short: "Run sync (PRIMARY SQLite <-> configured Postgres sync target)",
		Args:  cobra.MaximumNArgs(1),
		RunE:  runSync,
	}

	runCmd.Flags().StringVar(&syncFlagDirection, "direction", "both", "Sync direction: push, pull, both")
	runCmd.Flags().StringVar(&syncFlagStrategy, "conflict", "fail", "Conflict strategy: fail, prefer-local, prefer-remote, prefer-latest")
	runCmd.Flags().BoolVar(&syncFlagDryRun, "dry-run", false, "Print planned operations without applying changes")
	runCmd.Flags().StringVar(&syncFlagSince, "since", "", "Only consider changes since RFC3339 time (e.g. 2026-03-01T00:00:00Z). Optional.")
	runCmd.Flags().BoolVar(&syncFlagApprove, "approve", false, "Approve the sync plan and apply changes without prompting")
	runCmd.Flags().BoolVar(&syncFlagDeleteRemote, "delete-remote", false, "DANGEROUS: When pushing, delete remote secrets that are missing locally (delete-by-absence). Requires interactive confirmation and cannot be used with --approve.")

	return runCmd
}

// NewSyncEnableCmd initializes the configured Postgres sync target vault using the SAME master password
// as the primary SQLite vault.
func NewSyncEnableCmd() *cobra.Command {
	enableCmd := &cobra.Command{
		Use:   "enable",
		Short: "Initialize the configured Postgres sync target (same master password as primary)",
		Long: `Initialize the configured Postgres sync target vault.

This uses the same master password as your primary SQLite vault.
If the sync target is already initialized, this command does nothing.`,
		RunE: runSyncEnable,
	}

	return enableCmd
}

func runSyncEnable(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	primaryCfg := config.GetPrimaryStorageConfig()
	if err := roles.ValidatePrimary(primaryCfg); err != nil {
		return err
	}

	remoteCfg := config.GetSyncStorageConfig()
	if remoteCfg == nil {
		return fmt.Errorf("sync is disabled: configure storage.sync.postgres in config.yaml before enabling")
	}
	if err := roles.ValidateSyncTarget(remoteCfg); err != nil {
		return err
	}

	local, err := storage.NewBackend(primaryCfg)
	if err != nil {
		return fmt.Errorf("failed to open primary backend: %w", err)
	}
	defer local.Close()

	remote, err := storage.NewBackend(remoteCfg)
	if err != nil {
		return fmt.Errorf("failed to open sync backend: %w", err)
	}
	defer remote.Close()

	password, err := auth.PromptPassword("Enter master password (same as primary): ")
	if err != nil {
		return err
	}

	// Verify the master password against the local (primary) vault
	if _, err := local.UnlockVault(ctx, password); err != nil {
		return fmt.Errorf("failed to unlock primary vault: %w", err)
	}

	// If remote already initialized, verify it uses the same password and finish.
	initialized, err := remote.IsInitialized(ctx)
	if err != nil {
		return fmt.Errorf("failed to check sync target initialization: %w", err)
	}
	if initialized {
		if _, err := remote.UnlockVault(ctx, password); err != nil {
			return fmt.Errorf("sync target is initialized but could not be unlocked with the provided password: %w", err)
		}
		fmt.Println("✓ Sync target already enabled (already initialized and unlocked successfully).")
		return nil
	}

	// Initialize remote vault with same password
	if err := remote.CreateVault(ctx, password); err != nil {
		return fmt.Errorf("failed to initialize sync target vault: %w", err)
	}

	// Verify unlock immediately
	if _, err := remote.UnlockVault(ctx, password); err != nil {
		return fmt.Errorf("sync target vault initialized but unlock verification failed: %w", err)
	}

	fmt.Println("✓ Sync target enabled (initialized successfully).")
	return nil
}

func runSync(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	primaryCfg := config.GetPrimaryStorageConfig()
	if err := roles.ValidatePrimary(primaryCfg); err != nil {
		return err
	}

	remoteCfg := config.GetSyncStorageConfig()
	if remoteCfg == nil {
		return fmt.Errorf("sync is disabled: configure storage.sync.postgres in config.yaml")
	}
	if err := roles.ValidateSyncTarget(remoteCfg); err != nil {
		return err
	}

	scope, err := synccli.ParseScope(args)
	if err != nil {
		return err
	}

	dir, err := synccli.ParseDirection(syncFlagDirection)
	if err != nil {
		return err
	}

	strategy, err := synccli.ParseConflictStrategy(syncFlagStrategy)
	if err != nil {
		return err
	}

	since, err := synccli.ParseSince(syncFlagSince)
	if err != nil {
		return err
	}

	local, err := storage.NewBackend(primaryCfg)
	if err != nil {
		return fmt.Errorf("failed to open primary backend: %w", err)
	}
	defer local.Close()

	remote, err := storage.NewBackend(remoteCfg)
	if err != nil {
		return fmt.Errorf("failed to open sync backend: %w", err)
	}
	defer remote.Close()

	password, err := auth.PromptPassword("Enter master password: ")
	if err != nil {
		return err
	}

	if _, err := local.UnlockVault(ctx, password); err != nil {
		return fmt.Errorf("failed to unlock primary vault: %w", err)
	}

	// Provide a clearer message if the sync target isn't initialized yet.
	remoteInitialized, err := remote.IsInitialized(ctx)
	if err != nil {
		return fmt.Errorf("failed to check sync target initialization: %w", err)
	}
	if !remoteInitialized {
		return fmt.Errorf("sync target vault is not initialized. Run: vault sync enable")
	}

	if _, err := remote.UnlockVault(ctx, password); err != nil {
		return fmt.Errorf("failed to unlock sync target vault: %w", err)
	}

	engine := syncengine.New(local, remote, syncengine.Options{
		Direction:           dir,
		Strategy:            strategy,
		Scope:               scope,
		Since:               since,
		DeleteRemoteMissing: syncFlagDeleteRemote,
	})

	plan, err := engine.SyncPlan(ctx)
	if err != nil {
		// Still print the plan if partially built (conflicts, etc.)
		// but only if it's non-empty.
		if len(plan.Pull) > 0 || len(plan.Push) > 0 || len(plan.Conflicts) > 0 {
			synccli.RenderPlan(plan)
		}
		return err
	}

	// Plain output (no pager / Bubble Tea)
	planText := synccli.FormatPlan(plan, synccli.FormatOptions{MaxPerSection: 0})
	fmt.Print(planText)

	if syncFlagDryRun {
		synccli.RenderResult(syncengine.Result{Plan: plan, Applied: false})
		return nil
	}

	// Hard safety rule:
	// --delete-remote is destructive and must NEVER be allowed with --approve.
	if syncFlagDeleteRemote && syncFlagApprove {
		return fmt.Errorf("refusing to run: --delete-remote cannot be used with --approve (interactive confirmation required)")
	}

	// Require explicit approval before applying changes unless --approve is set.
	// If --delete-remote is enabled, we *always* require interactive confirmation.
	if syncFlagDeleteRemote {
		if err := synccli.ConfirmApplyPlan(plan); err != nil {
			return fmt.Errorf("sync aborted: %w", err)
		}
	} else if !syncFlagApprove {
		if err := synccli.ConfirmApplyPlan(plan); err != nil {
			return fmt.Errorf("sync aborted: %w (re-run with --approve to skip prompt)", err)
		}
	}

	// NOTE: The actual delete-by-absence behavior is implemented in the sync engine.
	// This flag only controls CLI safety/UX gating here.
	res, err := engine.Sync(ctx, false)
	if err != nil {
		return err
	}

	synccli.RenderResult(res)
	return nil
}

func parseSyncScope(args []string) (syncengine.Scope, error) {
	if len(args) == 0 {
		return syncengine.Scope{}, nil
	}

	parts := strings.Split(args[0], "/")
	if len(parts) != 2 {
		return syncengine.Scope{}, fmt.Errorf("invalid scope. Expected: project/environment")
	}

	return syncengine.Scope{
		ProjectName:     parts[0],
		EnvironmentName: NormalizeEnvironment(parts[1]),
	}, nil
}

func parseSyncDirection(v string) (syncengine.Direction, error) {
	switch syncengine.Direction(v) {
	case syncengine.DirectionPush, syncengine.DirectionPull, syncengine.DirectionBoth:
		return syncengine.Direction(v), nil
	default:
		return "", fmt.Errorf("invalid --direction %q (expected push, pull, both)", v)
	}
}

func parseConflictStrategy(v string) (syncengine.ConflictStrategy, error) {
	switch syncengine.ConflictStrategy(v) {
	case syncengine.ConflictFail,
		syncengine.ConflictPreferLocal,
		syncengine.ConflictPreferRemote,
		syncengine.ConflictPreferLatest:
		return syncengine.ConflictStrategy(v), nil
	default:
		return "", fmt.Errorf("invalid --conflict %q (expected fail, prefer-local, prefer-remote, prefer-latest)", v)
	}
}

func renderSyncPlan(plan syncengine.Plan) {
	// Keep CLI output simple and consistent with other commands.
	fmt.Printf("Planned PULL operations (remote -> local): %d\n", len(plan.Pull))
	for _, op := range plan.Pull {
		fmt.Printf("  - %s %s/%s/%s\n", op.Kind, op.ProjectName, op.Environment, op.Key)
	}

	fmt.Printf("\nPlanned PUSH operations (local -> remote): %d\n", len(plan.Push))
	for _, op := range plan.Push {
		fmt.Printf("  - %s %s/%s/%s\n", op.Kind, op.ProjectName, op.Environment, op.Key)
	}

	if len(plan.Conflicts) > 0 {
		fmt.Printf("\nConflicts detected: %d\n", len(plan.Conflicts))
		for _, c := range plan.Conflicts {
			fmt.Printf("  - %s/%s/%s (%s)\n", c.ProjectName, c.Environment, c.Key, c.Reason)
		}
	}
}
