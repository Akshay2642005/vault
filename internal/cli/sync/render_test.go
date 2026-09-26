package sync

import (
	"strings"
	"testing"

	syncengine "vault/internal/sync/engine"
)

func op(kind syncengine.OperationKind, project, env, key string) syncengine.Operation {
	return syncengine.Operation{Kind: kind, ProjectName: project, Environment: env, Key: key}
}

func TestFormatPlanEmpty(t *testing.T) {
	t.Parallel()

	got := FormatPlan(syncengine.Plan{}, FormatOptions{})
	want := "Sync plan\n" +
		"--------\n" +
		"Summary:\n" +
		"  Pull (remote -> local): 0\n" +
		"  Push (local -> remote): 0\n" +
		"  Conflicts:             0\n" +
		"\nNothing to do.\n"
	if got != want {
		t.Fatalf("FormatPlan(empty) =\n%q\nwant\n%q", got, want)
	}
}

func TestFormatPlanSectionsAndSummary(t *testing.T) {
	t.Parallel()

	plan := syncengine.Plan{
		Push: []syncengine.Operation{
			op(syncengine.OpUpsertRemote, "myapp", "development", "API_KEY"),
			op(syncengine.OpDeleteRemote, "myapp", "development", "OLD_KEY"),
		},
		Pull: []syncengine.Operation{
			op(syncengine.OpUpsertLocal, "beta", "production", "DB_URL"),
		},
		Conflicts: []syncengine.Conflict{
			{ProjectName: "myapp", Environment: "development", Key: "API_KEY", Reason: "changed on both sides"},
		},
		Detected: 1,
	}

	got := FormatPlan(plan, FormatOptions{})

	mustContain(t, got,
		"Pull (remote -> local): 1",
		"Push (local -> remote): 2",
		"Conflicts:             1",
		"PULL (remote -> local) (1)",
		"  beta/production (1)",
		"    - upsert-local DB_URL",
		"PUSH (local -> remote) (2)",
		"  myapp/development (2)",
		"    - delete-remote OLD_KEY",
		"    - upsert-remote API_KEY",
		"CONFLICTS (1)",
		"  - myapp/development/API_KEY",
		"      reason: changed on both sides",
	)

	// Key ordering within a group must be alphabetical.
	if strings.Index(got, "upsert-remote API_KEY") > strings.Index(got, "delete-remote OLD_KEY") {
		t.Fatal("ops within a group are not sorted by key")
	}
	// Pull section is rendered before push.
	if strings.Index(got, "PULL (remote -> local) (1)") > strings.Index(got, "PUSH (local -> remote) (2)") {
		t.Fatal("pull section must render before push section")
	}
}

func TestFormatPlanTruncatesPerSection(t *testing.T) {
	t.Parallel()

	plan := syncengine.Plan{
		Push: []syncengine.Operation{
			op(syncengine.OpUpsertRemote, "myapp", "development", "A"),
			op(syncengine.OpUpsertRemote, "myapp", "development", "B"),
			op(syncengine.OpUpsertRemote, "myapp", "development", "C"),
		},
	}

	got := FormatPlan(plan, FormatOptions{MaxPerSection: 2})
	mustContain(t, got,
		"PUSH (local -> remote) (3)",
		"    - upsert-remote A",
		"    - upsert-remote B",
		"... and 1 more",
	)
	if strings.Contains(got, "upsert-remote C") {
		t.Fatalf("truncated plan still shows the third op:\n%s", got)
	}

	// Zero means unlimited: every op is shown, no truncation notice.
	full := FormatPlan(plan, FormatOptions{MaxPerSection: 0})
	mustContain(t, full, "upsert-remote C")
	if strings.Contains(full, "... and") {
		t.Fatalf("unlimited plan contains truncation notice:\n%s", full)
	}

	// Negative is normalized to unlimited rather than hiding everything.
	neg := FormatPlan(plan, FormatOptions{MaxPerSection: -5})
	mustContain(t, neg, "upsert-remote C")
}

func TestFormatPlanGroupsSortedByProjectThenEnvironment(t *testing.T) {
	t.Parallel()

	plan := syncengine.Plan{
		Pull: []syncengine.Operation{
			op(syncengine.OpUpsertLocal, "beta", "production", "K1"),
			op(syncengine.OpUpsertLocal, "alpha", "staging", "K2"),
			op(syncengine.OpUpsertLocal, "alpha", "development", "K3"),
		},
	}

	got := FormatPlan(plan, FormatOptions{})
	iDev := strings.Index(got, "alpha/development (1)")
	iStg := strings.Index(got, "alpha/staging (1)")
	iProd := strings.Index(got, "beta/production (1)")
	if iDev < 0 || iStg < 0 || iProd < 0 {
		t.Fatalf("missing group header in output:\n%s", got)
	}
	if !(iDev < iStg && iStg < iProd) {
		t.Fatalf("groups not sorted dev < staging < beta/production:\n%s", got)
	}
}

func mustContain(t *testing.T, s string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(s, w) {
			t.Fatalf("output missing %q:\n%s", w, s)
		}
	}
}
