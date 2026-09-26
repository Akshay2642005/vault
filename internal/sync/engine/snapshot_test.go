package engine

// Stage A4: unit coverage for the pure snapshot-comparison helpers and the
// backend-facing bookkeeping helpers (mark-side-synced, clear-side-tombstone,
// delete-by-identity, upsert preconditions). The sync matrix in engine_test.go
// exercises these paths end to end; here each branch is hit directly so a
// regression names the exact helper that broke.

import (
	"context"
	"strings"
	"testing"
	"time"

	"vault/internal/crypto"
	"vault/internal/domain"
)

func TestNewDefaults(t *testing.T) {
	t.Parallel()

	e := New(nil, nil, Options{})
	if e.opts.Clock == nil {
		t.Error("New() left Clock nil, want time.Now default")
	}
	if e.opts.Direction != DirectionBoth {
		t.Errorf("New() Direction = %q, want %q", e.opts.Direction, DirectionBoth)
	}
	if e.opts.Strategy != ConflictFail {
		t.Errorf("New() Strategy = %q, want %q", e.opts.Strategy, ConflictFail)
	}

	// Explicit options are preserved verbatim.
	fixed := fixedClock(time.Unix(1000, 0))
	e2 := New(nil, nil, Options{
		Clock:     fixed,
		Direction: DirectionPush,
		Strategy:  ConflictPreferLocal,
	})
	if e2.opts.Clock == nil || e2.opts.Clock().Unix() != 1000 {
		t.Error("New() replaced an explicit Clock")
	}
	if e2.opts.Direction != DirectionPush || e2.opts.Strategy != ConflictPreferLocal {
		t.Errorf("New() overwrote explicit options: %+v", e2.opts)
	}
}

func TestEquivalent(t *testing.T) {
	t.Parallel()

	exp := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	rot := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	otherExp := exp.Add(time.Hour)

	base := func() *SecretSnapshot {
		return &SecretSnapshot{
			Value:      "v1",
			SecretType: domain.SecretTypeAPIKey,
			Tags:       []string{"a", "b"},
			Metadata:   map[string]any{"k": "v"},
			ExpiresAt:  &exp,
			RotateAt:   &rot,
		}
	}

	tests := []struct {
		name string
		a, b *SecretSnapshot
		want bool
	}{
		{"nil left", nil, base(), false},
		{"nil right", base(), nil, false},
		{"identical", base(), base(), true},
		{
			"matching checksums win over differing values",
			func() *SecretSnapshot { s := base(); s.Checksum = "same"; return s }(),
			func() *SecretSnapshot { s := base(); s.Value = "different"; s.Checksum = "same"; return s }(),
			true,
		},
		{
			"checksum on one side only is ignored",
			func() *SecretSnapshot { s := base(); s.Checksum = "only-left"; return s }(),
			base(),
			true,
		},
		{
			"differing checksums fall through to field compare",
			func() *SecretSnapshot { s := base(); s.Checksum = "left"; return s }(),
			func() *SecretSnapshot { s := base(); s.Checksum = "right"; return s }(),
			true,
		},
		{
			"value differs",
			base(),
			func() *SecretSnapshot { s := base(); s.Value = "v2"; return s }(),
			false,
		},
		{
			"secret type differs",
			base(),
			func() *SecretSnapshot { s := base(); s.SecretType = domain.SecretTypeDatabase; return s }(),
			false,
		},
		{
			"tags length differs",
			base(),
			func() *SecretSnapshot { s := base(); s.Tags = []string{"a"}; return s }(),
			false,
		},
		{
			"tags element differs",
			base(),
			func() *SecretSnapshot { s := base(); s.Tags = []string{"a", "c"}; return s }(),
			false,
		},
		{
			"metadata differs",
			base(),
			func() *SecretSnapshot { s := base(); s.Metadata = map[string]any{"k": "other"}; return s }(),
			false,
		},
		{
			"expires differs",
			base(),
			func() *SecretSnapshot { s := base(); s.ExpiresAt = &otherExp; return s }(),
			false,
		},
		{
			"expires nil versus set",
			base(),
			func() *SecretSnapshot { s := base(); s.ExpiresAt = nil; return s }(),
			false,
		},
		{
			"rotate differs",
			base(),
			func() *SecretSnapshot { s := base(); s.RotateAt = nil; return s }(),
			false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := equivalent(tc.a, tc.b); got != tc.want {
				t.Errorf("equivalent() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestStringSliceEqual(t *testing.T) {
	t.Parallel()

	if !stringSliceEqual(nil, nil) {
		t.Error("stringSliceEqual(nil, nil) = false, want true")
	}
	if !stringSliceEqual([]string{}, []string{}) {
		t.Error("stringSliceEqual(empty, empty) = false, want true")
	}
	if !stringSliceEqual([]string{"a", "b"}, []string{"a", "b"}) {
		t.Error("stringSliceEqual(equal) = false, want true")
	}
	if stringSliceEqual([]string{"a"}, []string{"a", "b"}) {
		t.Error("stringSliceEqual(longer right) = true, want false")
	}
	if stringSliceEqual([]string{"a", "b"}, []string{"a"}) {
		t.Error("stringSliceEqual(longer left) = true, want false")
	}
	if stringSliceEqual([]string{"a", "b"}, []string{"a", "c"}) {
		t.Error("stringSliceEqual(differing element) = true, want false")
	}
}

func TestJSONEqual(t *testing.T) {
	t.Parallel()

	if !jsonEqual(map[string]any{"a": 1, "b": "x"}, map[string]any{"b": "x", "a": 1}) {
		t.Error("jsonEqual(same content, different insertion order) = false, want true")
	}
	if jsonEqual(map[string]any{"a": 1}, map[string]any{"a": 2}) {
		t.Error("jsonEqual(different values) = true, want false")
	}
	// Marshalling failure on either side compares as unequal.
	badLeft := map[string]any{"ch": make(chan int)}
	if jsonEqual(badLeft, map[string]any{"ch": 1}) {
		t.Error("jsonEqual(unmarshalable left) = true, want false")
	}
	badRight := map[string]any{"ch": 1}
	if jsonEqual(badRight, badLeft) {
		t.Error("jsonEqual(unmarshalable right) = true, want false")
	}
}

func TestTimePtrEqual(t *testing.T) {
	t.Parallel()

	a := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	sameTime := a.Add(0)
	different := a.Add(time.Hour)

	if !timePtrEqual(nil, nil) {
		t.Error("timePtrEqual(nil, nil) = false, want true")
	}
	if timePtrEqual(&a, nil) {
		t.Error("timePtrEqual(set, nil) = true, want false")
	}
	if timePtrEqual(nil, &a) {
		t.Error("timePtrEqual(nil, set) = true, want false")
	}
	if !timePtrEqual(&a, &sameTime) {
		t.Error("timePtrEqual(equal instants) = false, want true")
	}
	if timePtrEqual(&a, &different) {
		t.Error("timePtrEqual(different instants) = true, want false")
	}
}

func TestCloneStringsAndMapAreDefensiveCopies(t *testing.T) {
	t.Parallel()

	// Empty input still yields a non-nil slice (safe to append to).
	if out := cloneStrings(nil); out == nil || len(out) != 0 {
		t.Errorf("cloneStrings(nil) = %#v, want non-nil empty", out)
	}

	src := []string{"a", "b"}
	out := cloneStrings(src)
	src[0] = "mutated"
	if out[0] != "a" {
		t.Errorf("cloneStrings aliasing: out[0] = %q after mutating source", out[0])
	}

	// nil map yields a usable empty map, not nil.
	if out := cloneMap(nil); out == nil || len(out) != 0 {
		t.Errorf("cloneMap(nil) = %#v, want non-nil empty", out)
	}

	m := map[string]any{"k": "v"}
	mout := cloneMap(m)
	m["k"] = "mutated"
	if mout["k"] != "v" {
		t.Errorf("cloneMap aliasing: out[k] = %v after mutating source", mout["k"])
	}
}

func TestChangedSince(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	synced := base.Add(-time.Hour)

	if changedSince(nil) {
		t.Error("changedSince(nil) = true, want false")
	}
	if !changedSince(&SecretSnapshot{UpdatedAt: base}) {
		t.Error("changedSince(never synced) = false, want true")
	}
	if !changedSince(&SecretSnapshot{UpdatedAt: base, LastSyncedAt: &synced}) {
		t.Error("changedSince(edited after sync) = false, want true")
	}
	if changedSince(&SecretSnapshot{UpdatedAt: synced, LastSyncedAt: &synced}) {
		t.Error("changedSince(edited at sync time) = true, want false")
	}
	older := base
	if changedSince(&SecretSnapshot{UpdatedAt: older.Add(-time.Hour), LastSyncedAt: &base}) {
		t.Error("changedSince(edited before sync) = true, want false")
	}
}

func TestToSnapshotCopiesFieldsDefensively(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	exp := now.Add(24 * time.Hour)
	secret := &domain.Secret{
		Environment: "development",
		Key:         "API_KEY",
		Type:        domain.SecretTypeAPIKey,
		Tags:        []string{"t1"},
		Metadata:    map[string]any{"m": "v"},
		Permissions: []string{"read"},
		ExpiresAt:   &exp,
		Owner:       "owner",
		Version:     2,
		Checksum:    "sum",
		UpdatedAt:   now,
		UpdatedBy:   "user",
		CreatedAt:   now.Add(-time.Hour),
		CreatedBy:   "user",
		SyncStatus:  domain.SyncStatusInSync,
		Value:       "plain",
	}

	snap := toSnapshot("myapp", secret)

	if snap.ProjectName != "myapp" || snap.Environment != "development" ||
		snap.Key != "API_KEY" || snap.SecretType != domain.SecretTypeAPIKey ||
		snap.Owner != "owner" || snap.Version != 2 || snap.Checksum != "sum" ||
		snap.UpdatedAt != now || snap.UpdatedBy != "user" ||
		snap.CreatedAt != now.Add(-time.Hour) || snap.CreatedBy != "user" ||
		snap.SyncStatus != domain.SyncStatusInSync || snap.Value != "plain" {
		t.Errorf("toSnapshot() field mapping wrong: %+v", snap)
	}
	if snap.ExpiresAt == nil || !snap.ExpiresAt.Equal(exp) {
		t.Errorf("toSnapshot() ExpiresAt = %v, want %v", snap.ExpiresAt, exp)
	}
	if len(snap.Permissions) != 1 || snap.Permissions[0] != "read" {
		t.Errorf("toSnapshot() Permissions = %v, want [read]", snap.Permissions)
	}

	// Mutating the source after snapshotting must not leak into the snapshot.
	secret.Tags[0] = "mutated"
	secret.Metadata["m"] = "mutated"
	secret.Permissions[0] = "mutated"
	if snap.Tags[0] != "t1" || snap.Metadata["m"] != "v" || snap.Permissions[0] != "read" {
		t.Errorf("toSnapshot() aliased the source: tags=%v meta=%v perms=%v",
			snap.Tags, snap.Metadata, snap.Permissions)
	}

	// A secret without permissions keeps an empty (not populated) copy.
	secret.Permissions = nil
	snap2 := toSnapshot("myapp", secret)
	if len(snap2.Permissions) != 0 {
		t.Errorf("toSnapshot() Permissions = %v, want empty", snap2.Permissions)
	}
}

func TestMarkSideSyncedSkipsMissingProjectAndSecret(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	env := newTestEnv(t, ctx)
	stamp := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)

	// Missing project: nothing to mark, but not an error.
	if err := markSideSynced(ctx, env.local, "ghost", "development", "KEY", stamp); err != nil {
		t.Errorf("markSideSynced(missing project) error = %v, want nil", err)
	}

	// Project exists but the secret does not.
	seedSecret(t, ctx, env.local, "PRESENT", "v", stamp)
	if err := markSideSynced(ctx, env.local, "myapp", "development", "GONE", stamp); err != nil {
		t.Errorf("markSideSynced(missing secret) error = %v, want nil", err)
	}

	// Both present: sync bookkeeping lands on the secret.
	if err := markSideSynced(ctx, env.local, "myapp", "development", "PRESENT", stamp); err != nil {
		t.Fatalf("markSideSynced() error = %v", err)
	}
	got := getSecret(t, ctx, env.local, "PRESENT")
	if got.LastSyncedAt == nil || !got.LastSyncedAt.Equal(stamp) {
		t.Errorf("LastSyncedAt = %v, want %v", got.LastSyncedAt, stamp)
	}
	if got.SyncStatus != domain.SyncStatusInSync {
		t.Errorf("SyncStatus = %q, want %q", got.SyncStatus, domain.SyncStatusInSync)
	}
	// Value and version must be untouched by bookkeeping.
	if got.Value != "v" || got.Version != 1 {
		t.Errorf("secret mutated by markSideSynced: value=%q version=%d", got.Value, got.Version)
	}
}

func TestClearSideTombstoneSkipsMissingProject(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	env := newTestEnv(t, ctx)

	// Missing project: nothing to clear, but not an error.
	if err := clearSideTombstone(ctx, env.local, "ghost", "development", "KEY"); err != nil {
		t.Errorf("clearSideTombstone(missing project) error = %v, want nil", err)
	}

	// Project present, no tombstone stored: the delete is a no-op success.
	seedSecret(t, ctx, env.local, "KEY", "v", time.Now())
	if err := clearSideTombstone(ctx, env.local, "myapp", "development", "KEY"); err != nil {
		t.Errorf("clearSideTombstone(no tombstone) error = %v, want nil", err)
	}
}

func TestDeleteByIdentityBranches(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	env := newTestEnv(t, ctx)

	// Missing project → nothing to delete.
	if err := deleteByIdentity(ctx, env.remote, "ghost", "development", "KEY"); err != nil {
		t.Errorf("deleteByIdentity(missing project) error = %v, want nil", err)
	}

	seedSecret(t, ctx, env.remote, "KEY", "v", time.Now())

	// Missing environment → nothing to delete.
	if err := deleteByIdentity(ctx, env.remote, "myapp", "qa", "KEY"); err != nil {
		t.Errorf("deleteByIdentity(missing environment) error = %v, want nil", err)
	}

	// Missing secret → nothing to delete.
	if err := deleteByIdentity(ctx, env.remote, "myapp", "development", "GONE"); err != nil {
		t.Errorf("deleteByIdentity(missing secret) error = %v, want nil", err)
	}

	// Present → deleted.
	if err := deleteByIdentity(ctx, env.remote, "myapp", "development", "KEY"); err != nil {
		t.Fatalf("deleteByIdentity() error = %v", err)
	}
	if _, err := getSecretErr(t, ctx, env.remote, "KEY"); err == nil {
		t.Error("secret still present after deleteByIdentity")
	}
}

func TestUpsertRejectsNilSnapshot(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	env := newTestEnv(t, ctx)

	err := upsert(ctx, env.local, env.remote, "myapp", "development", "KEY", nil, fixedClock(time.Now()))
	if err == nil || err.Error() != "upsert missing snapshot for myapp/development/KEY" {
		t.Errorf("upsert(nil) error = %v, want missing snapshot", err)
	}
}

// TestUpsertCreatesProjectEnvironmentAndSecret covers the full auto-create
// path: missing destination project and environment are built from the
// snapshot, and the destination secret preserves the source's temporal and
// version identity.
func TestUpsertCreatesProjectEnvironmentAndSecret(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	env := newTestEnv(t, ctx)

	now := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	created := now.Add(-time.Hour)
	snap := &SecretSnapshot{
		ProjectName: "upsert-proj",
		Environment: "production",
		Key:         "API_KEY",
		SecretType:  domain.SecretTypeAPIKey,
		Tags:        []string{"tier"},
		Metadata:    map[string]any{"team": "platform"},
		Owner:       "owner",
		Version:     3,
		UpdatedAt:   now,
		UpdatedBy:   "user",
		CreatedAt:   created,
		CreatedBy:   "user",
		Checksum:    crypto.Hash([]byte("val")),
		Value:       "val",
	}

	if err := upsert(ctx, env.local, env.remote, "upsert-proj", "production", "API_KEY",
		snap, fixedClock(now)); err != nil {
		t.Fatalf("upsert() error = %v", err)
	}

	// The destination project carries a production environment with the
	// expected protection flags.
	proj, err := env.remote.GetProjectByName(ctx, "upsert-proj")
	if err != nil {
		t.Fatalf("GetProjectByName() error = %v", err)
	}
	prodEnv, err := env.remote.GetEnvironment(ctx, proj.ID, "production")
	if err != nil {
		t.Fatalf("GetEnvironment(production) error = %v", err)
	}
	if prodEnv.Type != domain.EnvProduction || !prodEnv.Protected || !prodEnv.RequiresMFA {
		t.Errorf("production env = %+v, want protected+mfa", prodEnv)
	}

	got := getSecretIn(t, ctx, env.remote, "upsert-proj", "production", "API_KEY")
	if got.Value != "val" || got.Version != 3 {
		t.Errorf("destination secret = value %q version %d, want val/3", got.Value, got.Version)
	}
	if !got.UpdatedAt.Equal(now) || !got.CreatedAt.Equal(created) {
		t.Errorf("temporal identity lost: updated=%v created=%v, want %v/%v",
			got.UpdatedAt, got.CreatedAt, now, created)
	}
	if got.LastSyncedAt == nil || !got.LastSyncedAt.Equal(now) {
		t.Errorf("LastSyncedAt = %v, want %v", got.LastSyncedAt, now)
	}
	if got.SyncStatus != domain.SyncStatusInSync {
		t.Errorf("SyncStatus = %q, want %q", got.SyncStatus, domain.SyncStatusInSync)
	}
	if len(got.Tags) != 1 || got.Tags[0] != "tier" {
		t.Errorf("Tags = %v, want [tier]", got.Tags)
	}
}

// TestUpsertRejectsInvalidKey proves snapshot application validates the
// identity it is about to construct (a key the domain forbids never reaches
// the destination backend).
func TestUpsertRejectsInvalidKey(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	env := newTestEnv(t, ctx)

	snap := &SecretSnapshot{
		ProjectName: "upsert-bad",
		Environment: "development",
		Key:         "bad=key",
		SecretType:  domain.SecretTypeGeneric,
		Metadata:    map[string]any{},
		Value:       "v",
	}

	err := upsert(ctx, env.local, env.remote, "upsert-bad", "development", "bad=key",
		snap, fixedClock(time.Now()))
	if err == nil || err.Error() == "" {
		t.Fatal("upsert(invalid key) error = nil, want construct failure")
	}
	if want := "failed to construct destination secret"; !strings.Contains(err.Error(), want) {
		t.Errorf("upsert(invalid key) error = %v, want it to contain %q", err, want)
	}
	if _, err := getSecretErrIn(t, ctx, env.remote, "upsert-bad", "development", "bad=key"); err == nil {
		t.Error("invalid-key secret was created on the destination")
	}
}
