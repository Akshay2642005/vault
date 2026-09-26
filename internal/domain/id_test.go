package domain

import (
	"encoding/hex"
	"testing"
)

func TestGenerateIDShape(t *testing.T) {
	t.Parallel()

	id := GenerateID()
	if len(id) != 32 {
		t.Fatalf("GenerateID() length = %d, want 32 (16 random bytes hex-encoded)", len(id))
	}
	if _, err := hex.DecodeString(id); err != nil {
		t.Fatalf("GenerateID() = %q, not valid hex: %v", id, err)
	}
}

func TestGenerateIDUnique(t *testing.T) {
	t.Parallel()

	const n = 1000
	seen := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		id := GenerateID()
		if seen[id] {
			t.Fatalf("GenerateID() collision at call %d: %s", i, id)
		}
		seen[id] = true
	}
}
