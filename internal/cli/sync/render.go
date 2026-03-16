package sync

import (
	"fmt"
	"sort"
	"strings"

	syncengine "vault/internal/sync/engine"
)

// RenderPlan prints a grouped, human-friendly sync plan with summaries.
//
// This file is formatting-focused: it produces plain text suitable for stdout, logs,
// or piping to external tools.
func RenderPlan(plan syncengine.Plan) {
	fmt.Print(FormatPlan(plan, FormatOptions{
		MaxPerSection: 25,
	}))
}

// FormatOptions controls plain-text formatting.
type FormatOptions struct {
	// MaxPerSection limits how many operations are printed across a section.
	// If 0, no limit is applied.
	MaxPerSection int
}

// FormatPlan returns the full plan as a single string. This is used both for plain printing
// and for piping into a pager UI.
func FormatPlan(plan syncengine.Plan, opts FormatOptions) string {
	maxPerSection := opts.MaxPerSection
	if maxPerSection < 0 {
		maxPerSection = 0
	}

	var b strings.Builder

	pullGroups := groupOps(plan.Pull)
	pushGroups := groupOps(plan.Push)

	totalPull := len(plan.Pull)
	totalPush := len(plan.Push)
	totalConflicts := len(plan.Conflicts)

	b.WriteString("Sync plan\n")
	b.WriteString("--------\n")
	b.WriteString("Summary:\n")
	fmt.Fprintf(&b, "  Pull (remote -> local): %d\n", totalPull)
	fmt.Fprintf(&b, "  Push (local -> remote): %d\n", totalPush)
	fmt.Fprintf(&b, "  Conflicts:             %d\n", totalConflicts)

	if totalPull == 0 && totalPush == 0 && totalConflicts == 0 {
		b.WriteString("\nNothing to do.\n")
		return b.String()
	}

	renderSectionTo(&b, "PULL (remote -> local)", pullGroups, maxPerSection)
	renderSectionTo(&b, "PUSH (local -> remote)", pushGroups, maxPerSection)

	if totalConflicts > 0 {
		fmt.Fprintf(&b, "\nCONFLICTS (%d)\n", totalConflicts)
		b.WriteString(strings.Repeat("-", 10+len(fmt.Sprintf("%d", totalConflicts))))
		b.WriteString("\n")

		conflicts := append([]syncengine.Conflict{}, plan.Conflicts...)
		sort.Slice(conflicts, func(i, j int) bool {
			if conflicts[i].ProjectName != conflicts[j].ProjectName {
				return conflicts[i].ProjectName < conflicts[j].ProjectName
			}
			if conflicts[i].Environment != conflicts[j].Environment {
				return conflicts[i].Environment < conflicts[j].Environment
			}
			return conflicts[i].Key < conflicts[j].Key
		})

		for _, c := range conflicts {
			fmt.Fprintf(&b, "  - %s/%s/%s\n", c.ProjectName, c.Environment, c.Key)
			fmt.Fprintf(&b, "      reason: %s\n", c.Reason)
		}
	}

	return b.String()
}

type groupKey struct {
	project string
	env     string
}

type groupedOps struct {
	key groupKey
	ops []syncengine.Operation
}

func groupOps(ops []syncengine.Operation) []groupedOps {
	m := make(map[groupKey][]syncengine.Operation, 16)
	for _, op := range ops {
		k := groupKey{project: op.ProjectName, env: op.Environment}
		m[k] = append(m[k], op)
	}

	out := make([]groupedOps, 0, len(m))
	for k, v := range m {
		sort.Slice(v, func(i, j int) bool {
			if v[i].Key != v[j].Key {
				return v[i].Key < v[j].Key
			}
			return string(v[i].Kind) < string(v[j].Kind)
		})
		out = append(out, groupedOps{key: k, ops: v})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].key.project != out[j].key.project {
			return out[i].key.project < out[j].key.project
		}
		return out[i].key.env < out[j].key.env
	})

	return out
}

func renderSectionTo(b *strings.Builder, title string, groups []groupedOps, maxPerSection int) {
	total := 0
	for _, g := range groups {
		total += len(g.ops)
	}

	fmt.Fprintf(b, "\n%s (%d)\n", title, total)
	b.WriteString(strings.Repeat("-", len(title)+2+len(fmt.Sprintf("%d", total))))
	b.WriteString("\n")

	if total == 0 {
		b.WriteString("  (none)\n")
		return
	}

	// If maxPerSection == 0 => no truncation.
	limit := maxPerSection
	if limit == 0 {
		limit = int(^uint(0) >> 1) // max int
	}

	shown := 0
	for _, g := range groups {
		if shown >= limit {
			break
		}

		fmt.Fprintf(b, "  %s/%s (%d)\n", g.key.project, g.key.env, len(g.ops))
		for _, op := range g.ops {
			if shown >= limit {
				break
			}
			fmt.Fprintf(b, "    - %s %s\n", op.Kind, op.Key)
			shown++
		}
	}

	if total > limit {
		fmt.Fprintf(b, "  ... and %d more\n", total-limit)
	}
}

// RenderResult prints a succinct completion line. The caller can print errors separately.
func RenderResult(res syncengine.Result) {
	if !res.Applied {
		fmt.Printf("\n(dry-run) Plan generated. No changes applied.\n")
		return
	}
	fmt.Printf("\n✓ Sync complete (applied %d operations, detected %d conflicts)\n", res.OperationsApplied, res.ConflictsDetected)
}
