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
//     recency  = UpdatedAt timestamp
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
	// for secrets that exist on the remote but do not exist on the local side.
	//
	// This is a "delete by absence" behavior (no tombstones) and is inherently risky:
	// a missing local secret could be due to scoping, partial sync, or other reasons.
	//
	// Callers should gate this behind an explicit user confirmation (and preferably scope it).
	DeleteRemoteMissing bool

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

	// OpDeleteLocal is reserved for future use (would require explicit tombstones/change log).
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

			// If one is strictly newer by UpdatedAt, treat as normal update.
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
				Reason:      "local and remote differ but UpdatedAt timestamps are equal",
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
		// In our snapshot logic, conflicts only occur when UpdatedAt ties.
		// So prefer-latest cannot resolve these; require user to pick side.
		return fmt.Errorf("conflicts have equal UpdatedAt; --conflict prefer-latest cannot resolve (%d conflicts)", len(plan.Conflicts))

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
		// Delete-by-identity on remote.
		return deleteByIdentity(ctx, e.remote, op.ProjectName, op.Environment, op.Key)

	case OpDeleteLocal:
		// Reserved for future use (would require explicit tombstones/change log).
		return fmt.Errorf("delete-local is not implemented (requires tombstones/change log)")
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

		// Keep checksum if present; otherwise backend-side secret creation computed it earlier in codebase.
		if snap.Checksum != "" {
			newSecret.Checksum = snap.Checksum
		}

		// Mark sync metadata.
		t := now()
		newSecret.SyncStatus = domain.SyncStatusInSynced
		newSecret.LastSyncedAt = &t

		if err := dst.CreateSecret(ctx, newSecret); err != nil {
			return fmt.Errorf("failed to create destination secret %s/%s/%s: %w", projectName, env, key, err)
		}
		return nil
	}

	// update existing
	existing.Value = snap.Value
	existing.Type = snap.SecretType
	existing.Tags = cloneStrings(snap.Tags)
	existing.Metadata = cloneMap(snap.Metadata)
	existing.ExpiresAt = snap.ExpiresAt
	existing.RotateAt = snap.RotateAt

	// Set update metadata to indicate sync origin.
	existing.UpdatedAt = now()
	existing.UpdatedBy = "sync"

	if snap.Checksum != "" {
		existing.Checksum = snap.Checksum
	}

	// Mark sync metadata.
	t := now()
	existing.SyncStatus = domain.SyncStatusInSynced
	existing.LastSyncedAt = &t

	if err := dst.UpdateSecret(ctx, existing); err != nil {
		return fmt.Errorf("failed to update destination secret %s/%s/%s: %w", projectName, env, key, err)
	}
	_ = src // reserved for future: could read src again to confirm checksum after apply
	return nil
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
