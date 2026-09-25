package sqlite

import (
	"context"
	"fmt"

	"vault/internal/domain"
)

// RecordSyncRun persists an observability record for a sync execution.
func (b *Backend) RecordSyncRun(ctx context.Context, run *domain.SyncRun) error {
	_, err := b.db.ExecContext(ctx, `
		INSERT INTO sync_runs (id, started_at, finished_at, direction, strategy, scope, status, dry_run, pushed, pulled, conflicts, error)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, run.ID, run.StartedAt, run.FinishedAt, run.Direction, run.Strategy, run.Scope,
		run.Status, run.DryRun, run.Pushed, run.Pulled, run.Conflicts, run.Error)
	if err != nil {
		return fmt.Errorf("failed to record sync run: %w", err)
	}
	return nil
}

// ListSyncRuns returns the limit most recent sync runs, newest first.
func (b *Backend) ListSyncRuns(ctx context.Context, limit int) ([]*domain.SyncRun, error) {
	if limit <= 0 {
		limit = 10
	}
	if limit > 500 {
		limit = 500
	}

	rows, err := b.db.QueryContext(ctx, `
		SELECT id, started_at, finished_at, direction, strategy, COALESCE(scope, ''), status,
		       dry_run, pushed, pulled, conflicts, COALESCE(error, '')
		FROM sync_runs
		ORDER BY started_at DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query sync runs: %w", err)
	}
	defer rows.Close()

	var runs []*domain.SyncRun
	for rows.Next() {
		var r domain.SyncRun
		if err := rows.Scan(&r.ID, &r.StartedAt, &r.FinishedAt, &r.Direction, &r.Strategy,
			&r.Scope, &r.Status, &r.DryRun, &r.Pushed, &r.Pulled, &r.Conflicts, &r.Error); err != nil {
			return nil, fmt.Errorf("failed to scan sync run: %w", err)
		}
		runs = append(runs, &r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate sync runs: %w", err)
	}
	return runs, nil
}
