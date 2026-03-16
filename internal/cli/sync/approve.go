package sync

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	syncengine "vault/internal/sync/engine"
)

// ConfirmApplyPlan prompts the user to approve applying a sync plan.
// It returns nil if the plan is approved, otherwise an error explaining why it wasn't applied.
//
// Intended UX:
// - If there are 0 operations and 0 conflicts: no prompt needed (returns nil).
// - If there are conflicts: require explicit confirmation (and recommend resolving).
// - Otherwise: ask for a simple y/N confirmation.
// - If stdin isn't interactive or an EOF occurs, default to "no".
//
// This helper is CLI-only; it does not mutate the plan or apply operations.
func ConfirmApplyPlan(plan syncengine.Plan) error {
	totalOps := len(plan.Pull) + len(plan.Push)
	totalConflicts := len(plan.Conflicts)

	// Nothing to apply => no need to ask.
	if totalOps == 0 && totalConflicts == 0 {
		return nil
	}

	// Conflicts present: do not silently proceed.
	if totalConflicts > 0 {
		// The engine may already fail depending on strategy, but in case a strategy
		// transforms conflicts into ops, we still keep this guard because sync is destructive.
		if err := promptYesNo(fmt.Sprintf(
			"Conflicts detected (%d). Applying may overwrite values. Continue?", totalConflicts,
		), false); err != nil {
			return err
		}
	}

	if err := promptYesNo(fmt.Sprintf("Apply sync plan (%d operations)?", totalOps), false); err != nil {
		return err
	}

	return nil
}

// promptYesNo asks a yes/no question on the controlling terminal (tty) when available,
// reads a single keypress, and echoes it so the user can see what was typed.
// defaultYes controls the default response when the user presses Enter.
// Returns nil if the user answered yes, otherwise returns an error.
//
// Accepted yes inputs: y, yes
// Accepted no inputs:  n, no, <empty>
func promptYesNo(question string, defaultYes bool) error {
	def := "y/N"
	if defaultYes {
		def = "Y/n"
	}

	reader := os.Stdin
	writer := os.Stderr

	var restore func()
	for _, ttyPath := range []string{"/dev/tty", "CON"} {
		if f, err := os.OpenFile(ttyPath, os.O_RDWR, 0); err == nil {
			reader = f
			writer = f
			if state, err := term.MakeRaw(int(f.Fd())); err == nil {
				restore = func() {
					_ = term.Restore(int(f.Fd()), state)
				}
			}
			defer f.Close()
			break
		}
	}
	if restore != nil {
		defer restore()
	}

	fmt.Fprintf(writer, "%s [%s]: ", question, def)

	in := bufio.NewReader(reader)
	b, err := in.ReadByte()
	if err != nil {
		// Treat EOF / read error as "no" for safety.
		return fmt.Errorf("not approved")
	}

	// If user pressed Enter immediately, use default.
	if b == '\r' || b == '\n' {
		fmt.Fprintln(writer)
		if defaultYes {
			return nil
		}
		return fmt.Errorf("not approved")
	}

	// Echo the keypress so it shows up in the terminal, then finish the prompt line.
	fmt.Fprintf(writer, "%c", b)
	fmt.Fprintln(writer)

	answer := strings.ToLower(strings.TrimSpace(string([]byte{b})))
	switch answer {
	case "y":
		return nil
	case "n":
		return fmt.Errorf("not approved")
	default:
		return fmt.Errorf("not approved (invalid input %q)", answer)
	}
}
