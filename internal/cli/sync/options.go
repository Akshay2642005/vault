package sync

import (
	"fmt"
	"strings"
	"time"

	syncengine "vault/internal/sync/engine"
)

// This file focuses on argument parsing and validation shared by sync CLI subcommands.

// ParseScope parses an optional argument of the form "project/environment".
// If args is empty, it returns an empty scope (meaning: all projects/envs).
func ParseScope(args []string) (syncengine.Scope, error) {
	if len(args) == 0 {
		return syncengine.Scope{}, nil
	}
	if len(args) > 1 {
		return syncengine.Scope{}, fmt.Errorf("too many arguments (expected at most 1: project/environment)")
	}

	parts := strings.Split(args[0], "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return syncengine.Scope{}, fmt.Errorf("invalid scope %q. Expected: project/environment", args[0])
	}

	return syncengine.Scope{
		ProjectName:     parts[0],
		EnvironmentName: normalizeEnvironment(parts[1]),
	}, nil
}

// ParseDirection validates direction string into engine enum.
func ParseDirection(v string) (syncengine.Direction, error) {
	d := syncengine.Direction(v)
	switch d {
	case syncengine.DirectionPush, syncengine.DirectionPull, syncengine.DirectionBoth:
		return d, nil
	default:
		return "", fmt.Errorf("invalid --direction %q (expected push, pull, both)", v)
	}
}

// ParseConflictStrategy validates conflict strategy string into engine enum.
func ParseConflictStrategy(v string) (syncengine.ConflictStrategy, error) {
	s := syncengine.ConflictStrategy(v)
	switch s {
	case syncengine.ConflictFail,
		syncengine.ConflictPreferLocal,
		syncengine.ConflictPreferRemote,
		syncengine.ConflictPreferLatest:
		return s, nil
	default:
		return "", fmt.Errorf("invalid --conflict %q (expected fail, prefer-local, prefer-remote, prefer-latest)", v)
	}
}

// ParseSince parses RFC3339 timestamp. Empty string returns nil, nil.
func ParseSince(v string) (*time.Time, error) {
	if strings.TrimSpace(v) == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return nil, fmt.Errorf("invalid --since %q (expected RFC3339): %w", v, err)
	}
	return &t, nil
}

// normalizeEnvironment maps common aliases to canonical environment names.
//
// This intentionally mirrors the repo behavior described in AGENTS.md without
// importing the main cli package to avoid circular dependencies.
//
// Aliases:
//   - dev   -> development
//   - stage -> staging
//   - prod  -> production
func normalizeEnvironment(input string) string {
	v := strings.TrimSpace(strings.ToLower(input))
	switch v {
	case "dev":
		return "development"
	case "stage":
		return "staging"
	case "prod":
		return "production"
	default:
		return v
	}
}
