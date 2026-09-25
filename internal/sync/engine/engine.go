package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"vault/internal/domain"
	"vault/internal/storage"
)

// Engine reconciles secrets between a PRIMARY backend (SQLite) and an optional SYNC backend (Postgres).
//
// Design goals (as requested):
//   - Primary is SQLite and is the system-of-record.
//   - Postgres is only used as sync/backup target (remote).
//   - Sync is optional: callers can decide not to construct an Engine if remote isn't configured.
//   - Conflict detection and resolution supported via strategies.
//
// Important note about current repo state:
//   - There is no persisted change-log / vector clock table in storage backends yet.
//   - Therefore, this engine implements a pragmatic reconciliation based on snapshots:
//     identity = (project name, environment name, secret key)
//     equality = checksum match (preferred), otherwise value+metadata compare (best effort)
//     change   = UpdatedAt later than LastSyncedAt (never-synced secrets count as changed)
//   - Deletions are tracked via secret_tombstones: a deliberate deletion on one side
//     is never resurrected by the other, and can optionally propagate with the
//     DeleteRemoteMissing / DeleteLocalMissing options.
//
// With a future change-log, we can replace Snapshot reconciliation with a proper CRDT / vector-clock protocol.
type Engine struct {
	local  storage.Backend // primary (sqlite)
	remote storage.Backend // sync target (postgres)

	opts Options
}

type Options struct {
	Direction Direction

	// Strategy determines how to resolve conflicts.
	Strategy ConflictStrategy

	// Scope optionally restricts reconciliation.
	Scope Scope

	// Since optionally ignores secrets updated before this time.
	Since *time.Time

	// DeleteRemoteMissing causes the planner to emit delete operations on the remote
	// for secrets that exist on the remote but not on the local side — whether
	// because the local side has a tombstone for them (deliberately deleted) or
	// never had them at all (delete by absence).
	//
	// A local tombstone ALWAYS prevents pulling the secret back; this flag only
	// controls whether the surviving remote copy is actively removed. Delete-by-
	// absence is inherently risky (missing local secrets could be due to scoping
	// or partial sync), so callers should gate this behind explicit confirmation.
	DeleteRemoteMissing bool

	// DeleteLocalMissing causes the planner to emit delete operations on the
	// local side for secrets that exist locally but were deleted on the remote
	// (the remote carries a tombstone for the identity).
	//
	// A remote tombstone ALWAYS prevents pushing the secret back; this flag only
	// controls whether the surviving local copy is actively removed. It mirrors
	// DeleteRemoteMissing and is equally risky; callers should gate it behind
	// explicit user confirmation.
	DeleteLocalMissing bool

	// Clock allows deterministic tests.
	Clock func() time.Time
}

type Direction string

const (
	DirectionPush Direction = "push" // local -> remote
	DirectionPull Direction = "pull" // remote -> local
	DirectionBoth Direction = "both" // reconcile both ways
)

type ConflictStrategy string

const (
	// ConflictFail aborts when a conflict is detected.
	ConflictFail ConflictStrategy = "fail"

	// ConflictPreferLocal chooses local snapshot in conflicts.
	ConflictPreferLocal ConflictStrategy = "prefer-local"

	// ConflictPreferRemote chooses remote snapshot in conflicts.
	ConflictPreferRemote ConflictStrategy = "prefer-remote"

	// ConflictPreferLatest chooses whichever has later UpdatedAt; if tied, fails.
	ConflictPreferLatest ConflictStrategy = "prefer-latest"
)

type Scope struct {
	// If ProjectName is empty, all projects on either side are considered.
	ProjectName string

	// If EnvironmentName is empty, all environments for a project are considered.
	EnvironmentName string
}

func New(local storage.Backend, remote storage.Backend, opts Options) *Engine {
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.Direction == "" {
		opts.Direction = DirectionBoth
	}
	if opts.Strategy == "" {
		opts.Strategy = ConflictFail
	}
	return &Engine{local: local, remote: remote, opts: opts}
}

// Result captures the outcome of a sync.
type Result struct {
	Plan Plan

	Applied bool

	OperationsApplied int
	ConflictsDetected int
}

type Plan struct {
	Push []Operation // local -> remote
	Pull []Operation // remote -> local

	Conflicts []Conflict
}

type OperationKind string

const (
	OpUpsertRemote OperationKind = "upsert-remote"
	OpUpsertLocal  OperationKind = "upsert-local"

	// OpDeleteRemote deletes a secret from the remote by identity (project/env/key).
	//
	// NOTE: This engine only emits OpDeleteRemote when Options.DeleteRemoteMissing is true.
	OpDeleteRemote OperationKind = "delete-remote"

	// OpDeleteLocal deletes a secret from the local side by identity
	// (project/env/key), prompted by a tombstone on the remote.
	//
	// NOTE: This engine only emits OpDeleteLocal when Options.DeleteLocalMissing is true.
	OpDeleteLocal OperationKind = "delete-local"
)

type Operation struct {
	Kind OperationKind

	ProjectName string
	Environment string
	Key         string

	// Payload for upsert operations.
	Secret *SecretSnapshot
}

type Conflict struct {
	ProjectName string
	Environment string
	Key         string

	Local  *SecretSnapshot
	Remote *SecretSnapshot

	Reason string
}

type SecretSnapshot struct {
	// Identity
	ProjectName  string
	Environment  string
	Key          string
	SecretType   domain.SecretType
	Tags         []string
	Metadata     map[string]any
	ExpiresAt    *time.Time
	RotateAt     *time.Time
	Owner        string
	Permissions  []string
	Version      int
	PreviousID   *string
	Checksum     string
	UpdatedAt    time.Time
	UpdatedBy    string
	CreatedAt    time.Time
	CreatedBy    string
	LastSyncedAt *time.Time
	SyncStatus   domain.SyncStatus

	// Value is plaintext here because backends decrypt on read after UnlockVault.
	Value string
}

// SyncPlans builds a reconciliation plan but does not apply it.
func (e *Engine) SyncPlan(ctx context.Context) (Plan, error) {
	localIdx, err := e.snapshotIndex(ctx, e.local, sideLocal, e.opts.Scope, e.opts.Since)
	if err != nil {
		return Plan{}, err
	}
	remoteIdx, err := e.snapshotIndex(ctx, e.remote, sideRemote, e.opts.Scope, e.opts.Since)
	if err != nil {
		return Plan{}, err
	}

	localTombs, err := e.tombstoneIndex(ctx, e.local, sideLocal, e.opts.Scope, e.opts.Since)
	if err != nil {
		return Plan{}, err
	}
	remoteTombs, err := e.tombstoneIndex(ctx, e.remote, sideRemote, e.opts.Scope, e.opts.Since)
	if err != nil {
		return Plan{}, err
	}

	plan := Plan{
		Push:      make([]Operation, 0),
		Pull:      make([]Operation, 0),
		Conflicts: make([]Conflict, 0),
	}

	seen := map[identity]struct{}{}
	for id := range localIdx {
		seen[id] = struct{}{}
	}
	for id := range remoteIdx {
		seen[id] = struct{}{}
	}

	for id := range seen {
		ls := localIdx[id]
		rs := remoteIdx[id]

		switch {
		case ls != nil && rs == nil:
			// Local-only secret.
			//
			// If the remote side has a tombstone for this identity, the secret
			// was deliberately deleted remotely: never push it back. Optionally
			// mirror the deletion to the local copy with DeleteLocalMissing.
			if _, deletedRemotely := remoteTombs[id]; deletedRemotely {
				if e.opts.DeleteLocalMissing {
					plan.Pull = append(plan.Pull, Operation{
						Kind:        OpDeleteLocal,
						ProjectName: id.project,
						Environment: id.env,
						Key:         id.key,
					})
				}
				continue
			}
			plan.Push = append(plan.Push, Operation{
				Kind:        OpUpsertRemote,
				ProjectName: id.project,
				Environment: id.env,
				Key:         id.key,
				Secret:      ls,
			})

		case ls == nil && rs != nil:
			// Remote-only secret.
			//
			// If the local side has a tombstone, the secret was deliberately
			// deleted locally: never pull it back. Optionally mirror the
			// deletion to the remote with DeleteRemoteMissing.
			if _, deletedLocally := localTombs[id]; deletedLocally {
				if e.opts.DeleteRemoteMissing {
					plan.Push = append(plan.Push, Operation{
						Kind:        OpDeleteRemote,
						ProjectName: id.project,
						Environment: id.env,
						Key:         id.key,
					})
				}
				continue
			}

			// No local tombstone: the local side simply lacks this secret.
			//
			// If DeleteRemoteMissing is enabled, interpret remote-only as "should be deleted remotely"
			// during a push (delete-by-absence). Otherwise, default to pulling it locally.
			if e.opts.DeleteRemoteMissing {
				plan.Push = append(plan.Push, Operation{
					Kind:        OpDeleteRemote,
					ProjectName: id.project,
					Environment: id.env,
					Key:         id.key,
				})
			} else {
				plan.Pull = append(plan.Pull, Operation{
					Kind:        OpUpsertLocal,
					ProjectName: id.project,
					Environment: id.env,
					Key:         id.key,
					Secret:      rs,
				})
			}

		case ls != nil && rs != nil:
			if equivalent(ls, rs) {
				continue
			}

			// A side "changed since the last sync" when its UpdatedAt is after
			// its LastSyncedAt — or it has never been synced at all. Genuine
			// conflicts only exist when BOTH sides changed since their last
			// sync; a single-sided change is a normal push/pull.
			lChanged := changedSince(ls)
			rChanged := changedSince(rs)

			switch {
			case lChanged && !rChanged:
				// Only the local side changed since the last sync: push.
				plan.Push = append(plan.Push, Operation{
					Kind:        OpUpsertRemote,
					ProjectName: id.project,
					Environment: id.env,
					Key:         id.key,
					Secret:      ls,
				})
				continue

			case !lChanged && rChanged:
				// Only the remote side changed since the last sync: pull.
				plan.Pull = append(plan.Pull, Operation{
					Kind:        OpUpsertLocal,
					ProjectName: id.project,
					Environment: id.env,
					Key:         id.key,
					Secret:      rs,
				})
				continue

			case lChanged && rChanged:
				plan.Conflicts = append(plan.Conflicts, Conflict{
					ProjectName: id.project,
					Environment: id.env,
					Key:         id.key,
					Local:       ls,
					Remote:      rs,
					Reason:      "both sides changed since the last sync",
				})
				continue
			}

			// Neither side changed since its last sync, yet the snapshots
			// differ (e.g. an out-of-band write that bypassed sync). Fall back
			// to recency; equal timestamps are treated as a conflict.
			if ls.UpdatedAt.After(rs.UpdatedAt) {
				plan.Push = append(plan.Push, Operation{
					Kind:        OpUpsertRemote,
					ProjectName: id.project,
					Environment: id.env,
					Key:         id.key,
					Secret:      ls,
				})
				continue
			}
			if rs.UpdatedAt.After(ls.UpdatedAt) {
				plan.Pull = append(plan.Pull, Operation{
					Kind:        OpUpsertLocal,
					ProjectName: id.project,
					Environment: id.env,
					Key:         id.key,
					Secret:      rs,
				})
				continue
			}

			// Same timestamp but diverging data => conflict.
			plan.Conflicts = append(plan.Conflicts, Conflict{
				ProjectName: id.project,
				Environment: id.env,
				Key:         id.key,
				Local:       ls,
				Remote:      rs,
				Reason:      "local and remote differ but neither has changed since the last sync (equal UpdatedAt)",
			})
		}
	}

	// Apply conflict strategy by transforming conflicts into ops when possible.
	if len(plan.Conflicts) > 0 {
		if err := e.applyConflictStrategy(&plan); err != nil {
			return plan, err
		}
	}

	return plan, nil
}

// Sync applies reconciliation operations. If dryRun is true, it only returns the plan.
func (e *Engine) Sync(ctx context.Context, dryRun bool) (Result, error) {
	plan, err := e.SyncPlan(ctx)
	if err != nil {
		return Result{Plan: plan}, err
	}

	res := Result{
		Plan:              plan,
		Applied:           false,
		OperationsApplied: 0,
		ConflictsDetected: len(plan.Conflicts),
	}

	if dryRun {
		return res, nil
	}

	ops := e.opsByDirection(plan)

	for _, op := range ops {
		if err := e.applyOp(ctx, op); err != nil {
			return res, err
		}
		res.OperationsApplied++
	}

	res.Applied = true
	return res, nil
}

func (e *Engine) opsByDirection(plan Plan) []Operation {
	switch e.opts.Direction {
	case DirectionPush:
		return append([]Operation{}, plan.Push...)
	case DirectionPull:
		return append([]Operation{}, plan.Pull...)
	case DirectionBoth:
		// Prefer pulling first (remote -> local), then pushing (local -> remote).
		// This minimizes chance of overwriting remote-only changes before local sees them.
		out := make([]Operation, 0, len(plan.Pull)+len(plan.Push))
		out = append(out, plan.Pull...)
		out = append(out, plan.Push...)
		return out
	default:
		return append([]Operation{}, plan.Pull...)
	}
}

func (e *Engine) applyConflictStrategy(plan *Plan) error {
	switch e.opts.Strategy {
	case ConflictFail:
		return fmt.Errorf("sync conflicts detected (%d)", len(plan.Conflicts))

	case ConflictPreferLocal:
		for _, c := range plan.Conflicts {
			plan.Push = append(plan.Push, Operation{
				Kind:        OpUpsertRemote,
				ProjectName: c.ProjectName,
				Environment: c.Environment,
				Key:         c.Key,
				Secret:      c.Local,
			})
		}
		plan.Conflicts = nil
		return nil

	case ConflictPreferRemote:
		for _, c := range plan.Conflicts {
			plan.Pull = append(plan.Pull, Operation{
				Kind:        OpUpsertLocal,
				ProjectName: c.ProjectName,
				Environment: c.Environment,
				Key:         c.Key,
				Secret:      c.Remote,
			})
		}
		plan.Conflicts = nil
		return nil

	case ConflictPreferLatest:
		// Conflicts are now genuine (both sides changed since the last sync),
		// so recency can resolve them — except when UpdatedAt ties exactly.
		for _, c := range plan.Conflicts {
			switch {
			case c.Local != nil && (c.Remote == nil || c.Local.UpdatedAt.After(c.Remote.UpdatedAt)):
				plan.Push = append(plan.Push, Operation{
					Kind:        OpUpsertRemote,
					ProjectName: c.ProjectName,
					Environment: c.Environment,
					Key:         c.Key,
					Secret:      c.Local,
				})
			case c.Remote != nil && (c.Local == nil || c.Remote.UpdatedAt.After(c.Local.UpdatedAt)):
				plan.Pull = append(plan.Pull, Operation{
					Kind:        OpUpsertLocal,
					ProjectName: c.ProjectName,
					Environment: c.Environment,
					Key:         c.Key,
					Secret:      c.Remote,
				})
			default:
				return fmt.Errorf("conflict on %s/%s/%s has equal UpdatedAt; --conflict prefer-latest cannot resolve it", c.ProjectName, c.Environment, c.Key)
			}
		}
		plan.Conflicts = nil
		return nil

	default:
		return fmt.Errorf("unknown conflict strategy: %s", e.opts.Strategy)
	}
}

func (e *Engine) applyOp(ctx context.Context, op Operation) error {
	switch op.Kind {
	case OpUpsertRemote:
		return upsert(ctx, e.local, e.remote, op.ProjectName, op.Environment, op.Key, op.Secret, e.opts.Clock)

	case OpUpsertLocal:
		return upsert(ctx, e.remote, e.local, op.ProjectName, op.Environment, op.Key, op.Secret, e.opts.Clock)

	case OpDeleteRemote:
		// Delete-by-identity on remote. The remote DeleteSecret records a
		// tombstone, so a later pull cannot resurrect the secret.
		return deleteByIdentity(ctx, e.remote, op.ProjectName, op.Environment, op.Key)

	case OpDeleteLocal:
		// Delete-by-identity on local, prompted by a tombstone on the remote.
		// The local DeleteSecret records a tombstone, so the remote cannot
		// resurrect the secret on a later push.
		return deleteByIdentity(ctx, e.local, op.ProjectName, op.Environment, op.Key)
	default:
		return fmt.Errorf("unknown operation: %s", op.Kind)
	}
}

type side string

const (
	sideLocal  side = "local"
	sideRemote side = "remote"
)

type identity struct {
	project string // project name (not ID) to allow mapping across different DBs
	env     string
	key     string
}

func (e *Engine) snapshotIndex(ctx context.Context, b storage.Backend, _ side, scope Scope, since *time.Time) (map[identity]*SecretSnapshot, error) {
	projects, err := b.ListProjects(ctx)
	if err != nil {
		return nil, err
	}

	projIDsByName := map[string]string{}
	for _, p := range projects {
		projIDsByName[p.Name] = p.ID
	}

	projectNames := make([]string, 0)
	if scope.ProjectName != "" {
		projectNames = append(projectNames, scope.ProjectName)
	} else {
		for name := range projIDsByName {
			projectNames = append(projectNames, name)
		}
	}

	idx := make(map[identity]*SecretSnapshot, 128)

	for _, pname := range projectNames {
		pid := projIDsByName[pname]
		if pid == "" {
			continue
		}

		envs := make([]string, 0)
		if scope.EnvironmentName != "" {
			envs = append(envs, scope.EnvironmentName)
		} else {
			list, err := b.ListEnvironments(ctx, pid)
			if err != nil {
				return nil, fmt.Errorf("failed to list environments for project %q: %w", pname, err)
			}
			for _, e := range list {
				envs = append(envs, e.Name)
			}
		}

		for _, env := range envs {
			secrets, err := b.ListSecrets(ctx, pid, env)
			if err != nil {
				// Environment might not exist on this side; skip.
				continue
			}
			for _, s := range secrets {
				if since != nil && s.UpdatedAt.Before(*since) {
					continue
				}

				id := identity{project: pname, env: s.Environment, key: s.Key}
				idx[id] = toSnapshot(pname, s)
			}
		}
	}

	return idx, nil
}

// tombstoneIndex builds the set of identities that have deletion records on the
// given backend, honoring the same scope and `since` filtering as snapshotIndex.
func (e *Engine) tombstoneIndex(ctx context.Context, b storage.Backend, _ side, scope Scope, since *time.Time) (map[identity]struct{}, error) {
	projects, err := b.ListProjects(ctx)
	if err != nil {
		return nil, err
	}

	projIDsByName := map[string]string{}
	for _, p := range projects {
		projIDsByName[p.Name] = p.ID
	}

	projectNames := make([]string, 0)
	if scope.ProjectName != "" {
		projectNames = append(projectNames, scope.ProjectName)
	} else {
		for name := range projIDsByName {
			projectNames = append(projectNames, name)
		}
	}

	idx := make(map[identity]struct{}, 64)

	for _, pname := range projectNames {
		pid := projIDsByName[pname]
		if pid == "" {
			continue
		}

		envs := make([]string, 0)
		if scope.EnvironmentName != "" {
			envs = append(envs, scope.EnvironmentName)
		} else {
			list, err := b.ListEnvironments(ctx, pid)
			if err != nil {
				return nil, fmt.Errorf("failed to list environments for project %q: %w", pname, err)
			}
			for _, ev := range list {
				envs = append(envs, ev.Name)
			}
		}

		for _, env := range envs {
			tombs, err := b.ListTombstones(ctx, pid, env)
			if err != nil {
				// Environment likely absent on this side; nothing to delete.
				continue
			}
			for _, t := range tombs {
				if since != nil && t.DeletedAt.Before(*since) {
					continue
				}
				idx[identity{project: pname, env: env, key: t.Key}] = struct{}{}
			}
		}
	}

	return idx, nil
}

func toSnapshot(projectName string, s *domain.Secret) *SecretSnapshot {
	// Make defensive copies of maps/slices for safety.
	tags := make([]string, len(s.Tags))
	copy(tags, s.Tags)

	meta := make(map[string]any, len(s.Metadata))
	for k, v := range s.Metadata {
		meta[k] = v
	}

	var perms []string
	if len(s.Permissions) > 0 {
		perms = make([]string, len(s.Permissions))
		copy(perms, s.Permissions)
	}

	return &SecretSnapshot{
		ProjectName:  projectName,
		Environment:  s.Environment,
		Key:          s.Key,
		SecretType:   s.Type,
		Tags:         tags,
		Metadata:     meta,
		ExpiresAt:    s.ExpiresAt,
		RotateAt:     s.RotateAt,
		Owner:        s.Owner,
		Permissions:  perms,
		Version:      s.Version,
		PreviousID:   s.PreviousID,
		Checksum:     s.Checksum,
		UpdatedAt:    s.UpdatedAt,
		UpdatedBy:    s.UpdatedBy,
		CreatedAt:    s.CreatedAt,
		CreatedBy:    s.CreatedBy,
		LastSyncedAt: s.LastSyncedAt,
		SyncStatus:   s.SyncStatus,
		Value:        s.Value,
	}
}

func equivalent(a, b *SecretSnapshot) bool {
	if a == nil || b == nil {
		return false
	}

	// Prefer checksum if both populated.
	if a.Checksum != "" && b.Checksum != "" && a.Checksum == b.Checksum {
		return true
	}

	// Best-effort deep compare using stable JSON for tags/metadata + primary fields.
	if a.Value != b.Value {
		return false
	}
	if a.SecretType != b.SecretType {
		return false
	}
	if !stringSliceEqual(a.Tags, b.Tags) {
		return false
	}
	if !jsonEqual(a.Metadata, b.Metadata) {
		return false
	}
	// ExpiresAt/RotateAt differences matter.
	if !timePtrEqual(a.ExpiresAt, b.ExpiresAt) {
		return false
	}
	if !timePtrEqual(a.RotateAt, b.RotateAt) {
		return false
	}

	return true
}

func upsert(ctx context.Context, src storage.Backend, dst storage.Backend, projectName, env, key string, snap *SecretSnapshot, now func() time.Time) error {
	if snap == nil {
		return fmt.Errorf("upsert missing snapshot for %s/%s/%s", projectName, env, key)
	}

	t := now()

	// Ensure project exists on destination (auto-create if missing).
	dstProj, err := dst.GetProjectByName(ctx, projectName)
	if err != nil {
		project, err2 := domain.NewProject(projectName, "", "sync")
		if err2 != nil {
			return fmt.Errorf("failed to construct destination project %q: %w", projectName, err2)
		}
		if err := dst.CreateProject(ctx, project); err != nil {
			return fmt.Errorf("failed to create destination project %q: %w", projectName, err)
		}

		dstProj, err = dst.GetProjectByName(ctx, projectName)
		if err != nil {
			return fmt.Errorf("destination project %q creation succeeded but lookup failed: %w", projectName, err)
		}
	}

	// Ensure environment exists on destination (auto-create if missing).
	if _, err := dst.GetEnvironment(ctx, dstProj.ID, env); err != nil {
		envType := domain.EnvCustom
		protected := false
		requiresMFA := false

		switch env {
		case "development":
			envType = domain.EnvDevelopment
		case "staging":
			envType = domain.EnvStaging
		case "production":
			envType = domain.EnvProduction
			protected = true
			requiresMFA = true
		}

		newEnv := &domain.Environment{
			ID:          domain.GenerateID(),
			ProjectID:   dstProj.ID,
			Name:        env,
			Type:        envType,
			Protected:   protected,
			RequiresMFA: requiresMFA,
		}

		if err := dst.CreateEnvironment(ctx, dstProj.ID, newEnv); err != nil {
			return fmt.Errorf("failed to create destination environment %q in project %q: %w", env, projectName, err)
		}
	}

	// Upsert secret: if exists => UpdateSecret; else => CreateSecret.
	existing, err := dst.GetSecret(ctx, dstProj.ID, env, key)
	if err != nil {
		// create new secret
		newSecret, err2 := domain.NewSecret(dstProj.ID, env, key, snap.Value, snap.SecretType, "sync")
		if err2 != nil {
			return fmt.Errorf("failed to construct destination secret: %w", err2)
		}

		// Override details from snapshot where applicable.
		newSecret.Type = snap.SecretType
		newSecret.Tags = cloneStrings(snap.Tags)
		newSecret.Metadata = cloneMap(snap.Metadata)
		newSecret.ExpiresAt = snap.ExpiresAt
		newSecret.RotateAt = snap.RotateAt
		newSecret.Owner = snap.Owner
		newSecret.Permissions = cloneStrings(snap.Permissions)

		// Preserve the source's temporal/version identity so the destination
		// mirror reports the same history as the source, not the sync time.
		newSecret.Version = snap.Version
		newSecret.PreviousID = snap.PreviousID
		newSecret.CreatedAt = snap.CreatedAt
		newSecret.CreatedBy = snap.CreatedBy
		newSecret.UpdatedAt = snap.UpdatedAt
		newSecret.UpdatedBy = snap.UpdatedBy

		// Keep checksum if present; otherwise backend-side secret creation computed it earlier in codebase.
		if snap.Checksum != "" {
			newSecret.Checksum = snap.Checksum
		}

		// Mark sync metadata.
		newSecret.SyncStatus = domain.SyncStatusInSync
		newSecret.LastSyncedAt = &t

		if err := dst.CreateSecret(ctx, newSecret); err != nil {
			return fmt.Errorf("failed to create destination secret %s/%s/%s: %w", projectName, env, key, err)
		}

		// Record sync bookkeeping on both sides. Destination was just marked
		// above; this also stamps the source so the next reconciliation knows
		// this change was already propagated.
		return finishUpsert(ctx, src, dst, projectName, env, key, t)
	}

	// update existing
	existing.Value = snap.Value
	existing.Type = snap.SecretType
	existing.Tags = cloneStrings(snap.Tags)
	existing.Metadata = cloneMap(snap.Metadata)
	existing.ExpiresAt = snap.ExpiresAt
	existing.RotateAt = snap.RotateAt
	existing.Owner = snap.Owner
	existing.Permissions = cloneStrings(snap.Permissions)

	// Preserve the source's last-edit metadata so version history and audit
	// fields reflect when the change actually happened, not when sync
	// propagated it.
	existing.UpdatedAt = snap.UpdatedAt
	existing.UpdatedBy = snap.UpdatedBy

	if snap.Checksum != "" {
		existing.Checksum = snap.Checksum
	}

	// Mark sync metadata.
	existing.SyncStatus = domain.SyncStatusInSync
	existing.LastSyncedAt = &t

	if err := dst.UpdateSecret(ctx, existing); err != nil {
		return fmt.Errorf("failed to update destination secret %s/%s/%s: %w", projectName, env, key, err)
	}

	// Record sync bookkeeping on both sides (see comment in create path).
	return finishUpsert(ctx, src, dst, projectName, env, key, t)
}

// finishUpsert records sync bookkeeping on both sides and clears any stale
// tombstones for the identity. A tombstone is only meaningful while the
// identity is absent; once a secret exists on both sides again, the deletion
// record describes an earlier era and must not re-trigger propagation.
func finishUpsert(ctx context.Context, src, dst storage.Backend, projectName, env, key string, t time.Time) error {
	if err := markSyncedBoth(ctx, src, dst, projectName, env, key, t); err != nil {
		return err
	}
	return clearTombstonesBoth(ctx, src, dst, projectName, env, key)
}

// markSyncedBoth stamps sync bookkeeping on both backends with the same
// timestamp. It only touches sync_status/last_synced_at — never the value,
// UpdatedAt, or version history — so the next reconciliation can correctly
// classify "changed since last sync".
func markSyncedBoth(ctx context.Context, a, b storage.Backend, projectName, env, key string, t time.Time) error {
	if err := markSideSynced(ctx, a, projectName, env, key, t); err != nil {
		return err
	}
	return markSideSynced(ctx, b, projectName, env, key, t)
}

func markSideSynced(ctx context.Context, backend storage.Backend, projectName, env, key string, t time.Time) error {
	proj, err := backend.GetProjectByName(ctx, projectName)
	if err != nil {
		return nil // nothing to mark on this side
	}
	s, err := backend.GetSecret(ctx, proj.ID, env, key)
	if err != nil {
		return nil // secret absent on this side; nothing to mark
	}
	return backend.MarkSynced(ctx, s.ID, t)
}

func clearTombstonesBoth(ctx context.Context, a, b storage.Backend, projectName, env, key string) error {
	if err := clearSideTombstone(ctx, a, projectName, env, key); err != nil {
		return err
	}
	return clearSideTombstone(ctx, b, projectName, env, key)
}

func clearSideTombstone(ctx context.Context, backend storage.Backend, projectName, env, key string) error {
	proj, err := backend.GetProjectByName(ctx, projectName)
	if err != nil {
		return nil // nothing to clear on this side
	}
	return backend.DeleteTombstone(ctx, proj.ID, env, key)
}

// changedSince reports whether the snapshot was modified after its last sync.
// A secret that has never been synced is considered changed.
func changedSince(s *SecretSnapshot) bool {
	if s == nil {
		return false
	}
	if s.LastSyncedAt == nil {
		return true
	}
	return s.UpdatedAt.After(*s.LastSyncedAt)
}

func cloneStrings(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func cloneMap(in map[string]any) map[string]any {
	if in == nil {
		return make(map[string]any)
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func jsonEqual(a, b map[string]any) bool {
	// Using JSON marshal as a best-effort stable compare. Maps in Go are randomized,
	// but encoding/json sorts keys deterministically.
	aj, err := json.Marshal(a)
	if err != nil {
		return false
	}
	bj, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return string(aj) == string(bj)
}

func timePtrEqual(a, b *time.Time) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	default:
		return a.Equal(*b)
	}
}

func deleteByIdentity(ctx context.Context, b storage.Backend, projectName, env, key string) error {
	// Map project name -> project id on destination
	p, err := b.GetProjectByName(ctx, projectName)
	if err != nil {
		// If project doesn't exist, there's nothing to delete.
		return nil
	}

	// If env doesn't exist, nothing to delete.
	if _, err := b.GetEnvironment(ctx, p.ID, env); err != nil {
		return nil
	}

	// Get secret by identity; if missing, nothing to delete.
	s, err := b.GetSecret(ctx, p.ID, env, key)
	if err != nil {
		return nil
	}

	return b.DeleteSecret(ctx, s.ID)
}
