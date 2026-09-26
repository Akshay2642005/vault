package sync

import (
	"testing"
	"time"

	syncengine "vault/internal/sync/engine"
)

func TestParseScope(t *testing.T) {
	t.Parallel()

	t.Run("no args means full scope", func(t *testing.T) {
		scope, err := ParseScope(nil)
		if err != nil {
			t.Fatalf("ParseScope(nil) error = %v", err)
		}
		if scope.ProjectName != "" || scope.EnvironmentName != "" {
			t.Fatalf("scope = %+v, want zero value", scope)
		}
	})

	t.Run("project/environment", func(t *testing.T) {
		scope, err := ParseScope([]string{"myapp/development"})
		if err != nil {
			t.Fatalf("ParseScope() error = %v", err)
		}
		if scope.ProjectName != "myapp" || scope.EnvironmentName != "development" {
			t.Fatalf("scope = %+v, want myapp/development", scope)
		}
	})

	aliases := map[string]string{
		"myapp/dev":   "development",
		"myapp/stage": "staging",
		"myapp/prod":  "production",
		"myapp/DEV":   "development", // case-insensitive
	}
	for input, wantEnv := range aliases {
		t.Run("alias "+input, func(t *testing.T) {
			scope, err := ParseScope([]string{input})
			if err != nil {
				t.Fatalf("ParseScope(%q) error = %v", input, err)
			}
			if scope.EnvironmentName != wantEnv {
				t.Fatalf("EnvironmentName = %q, want %q", scope.EnvironmentName, wantEnv)
			}
		})
	}

	invalid := []struct {
		name string
		args []string
	}{
		{"too many args", []string{"a/dev", "b"}},
		{"no slash", []string{"myapp"}},
		{"empty environment", []string{"myapp/"}},
		{"empty project", []string{"/dev"}},
		{"extra slash", []string{"a/b/c"}},
	}
	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseScope(tt.args); err == nil {
				t.Fatalf("ParseScope(%v) error = nil, want error", tt.args)
			}
		})
	}
}

func TestParseDirection(t *testing.T) {
	t.Parallel()

	valid := []syncengine.Direction{
		syncengine.DirectionPush,
		syncengine.DirectionPull,
		syncengine.DirectionBoth,
	}
	for _, d := range valid {
		got, err := ParseDirection(string(d))
		if err != nil {
			t.Fatalf("ParseDirection(%q) error = %v", d, err)
		}
		if got != d {
			t.Fatalf("ParseDirection(%q) = %q, want same", d, got)
		}
	}

	for _, bad := range []string{"", "up", "Push", "sideways"} {
		if _, err := ParseDirection(bad); err == nil {
			t.Fatalf("ParseDirection(%q) error = nil, want error", bad)
		}
	}
}

func TestParseConflictStrategy(t *testing.T) {
	t.Parallel()

	valid := []syncengine.ConflictStrategy{
		syncengine.ConflictFail,
		syncengine.ConflictPreferLocal,
		syncengine.ConflictPreferRemote,
		syncengine.ConflictPreferLatest,
	}
	for _, s := range valid {
		got, err := ParseConflictStrategy(string(s))
		if err != nil {
			t.Fatalf("ParseConflictStrategy(%q) error = %v", s, err)
		}
		if got != s {
			t.Fatalf("ParseConflictStrategy(%q) = %q, want same", s, got)
		}
	}

	for _, bad := range []string{"", "latest", "prefer-newest", "FAIL"} {
		if _, err := ParseConflictStrategy(bad); err == nil {
			t.Fatalf("ParseConflictStrategy(%q) error = nil, want error", bad)
		}
	}
}

func TestParseSince(t *testing.T) {
	t.Parallel()

	t.Run("empty means no filter", func(t *testing.T) {
		for _, in := range []string{"", "   "} {
			got, err := ParseSince(in)
			if err != nil {
				t.Fatalf("ParseSince(%q) error = %v", in, err)
			}
			if got != nil {
				t.Fatalf("ParseSince(%q) = %v, want nil", in, *got)
			}
		}
	})

	t.Run("rfc3339", func(t *testing.T) {
		got, err := ParseSince("2026-03-01T00:00:00Z")
		if err != nil {
			t.Fatalf("ParseSince() error = %v", err)
		}
		if got == nil {
			t.Fatal("ParseSince() = nil, want parsed time")
		}
		want := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
		if !got.Equal(want) {
			t.Fatalf("parsed time = %v, want %v", got, want)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, in := range []string{"not-a-time", "2026-03-01", "2026-03-01 00:00:00"} {
			if _, err := ParseSince(in); err == nil {
				t.Fatalf("ParseSince(%q) error = nil, want error", in)
			}
		}
	})
}

func TestNormalizeEnvironment(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   string
		want string
	}{
		{"dev", "development"},
		{"stage", "staging"},
		{"prod", "production"},
		{"DEV", "development"},
		{" Prod ", "production"},
		{"development", "development"},
		{"custom", "custom"},
	}
	for _, tt := range tests {
		if got := normalizeEnvironment(tt.in); got != tt.want {
			t.Fatalf("normalizeEnvironment(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
