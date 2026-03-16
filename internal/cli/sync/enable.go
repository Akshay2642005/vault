package sync

import (
	"context"
	"fmt"

	"vault/internal/storage"
)

// EnsureSyncTargetEnabled ensures the sync target vault (remote backend) is initialized and unlocked.
//
// Intended behavior:
// - If the sync target is not initialized, return a helpful error telling the user to run `vault sync enable`.
// - If it is initialized, attempt to unlock it with the provided master password.
// - Returns nil on success.
func EnsureSyncTargetEnabled(ctx context.Context, remote storage.Backend, masterPassword string) error {
	initialized, err := remote.IsInitialized(ctx)
	if err != nil {
		return fmt.Errorf("failed to check sync target initialization status: %w", err)
	}
	if !initialized {
		return fmt.Errorf("sync target vault is not initialized. Run `vault sync enable` to initialize it with your master password")
	}

	if _, err := remote.UnlockVault(ctx, masterPassword); err != nil {
		return fmt.Errorf("failed to unlock sync target vault: %w", err)
	}

	return nil
}

// EnableSyncTarget initializes the sync target vault (remote backend) using the provided master password.
//
// Rules:
// - Uses the same master password as primary (as per your requirement).
// - If already initialized, it will just attempt to unlock and return success.
// - Returns a user-friendly error if initialization or unlock fails.
func EnableSyncTarget(ctx context.Context, remote storage.Backend, masterPassword string) error {
	initialized, err := remote.IsInitialized(ctx)
	if err != nil {
		return fmt.Errorf("failed to check sync target initialization status: %w", err)
	}

	// If already initialized, just verify we can unlock with the password.
	if initialized {
		if _, err := remote.UnlockVault(ctx, masterPassword); err != nil {
			return fmt.Errorf("sync target vault is already initialized but failed to unlock with the provided master password: %w", err)
		}
		return nil
	}

	// Initialize remote vault metadata with the same password.
	if err := remote.CreateVault(ctx, masterPassword); err != nil {
		return fmt.Errorf("failed to initialize sync target vault: %w", err)
	}

	// Verify unlock works immediately after init.
	if _, err := remote.UnlockVault(ctx, masterPassword); err != nil {
		return fmt.Errorf("sync target vault initialized but failed to unlock (verification): %w", err)
	}

	return nil
}
