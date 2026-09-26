package auth

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// withReadPassword substitutes the password input primitive for the duration
// of a test. The real one requires an interactive terminal.
func withReadPassword(t *testing.T, fn func(fd int) ([]byte, error)) {
	t.Helper()
	orig := readPassword
	readPassword = fn
	t.Cleanup(func() { readPassword = orig })
}

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name    string
		pw      string
		wantErr string // exact message; "" means the password is accepted
	}{
		{"valid", "Str0ng!Pass", ""},
		{"exactly eight characters", "Ab1!xyzw", ""},
		{"empty", "", "password must be at least 8 characters"},
		{"too short", "Ab1!xy", "password must be at least 8 characters"},
		{"missing uppercase", "abcdefg1!", "password must contain at least an uppercase letter"},
		{"missing lowercase", "ABCDEFG1!", "password must contain at least a lowercase letter"},
		{"missing digit", "Abcdefgh!", "password must contain at least a digit"},
		{"missing special", "Abcdefgh1", "password must contain at least a special character"},
		{"missing two", "abcdefgh!", "password must contain at least an uppercase letter and a digit"},
		{"missing other two", "12345678!", "password must contain at least an uppercase letter and a lowercase letter"},
		{"missing three", "aaaaaaaa", "password must contain at least an uppercase letter, a digit and a special character"},
		{"missing all four", "        ", "password must contain at least an uppercase letter, a lowercase letter, a digit and a special character"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePassword(tc.pw)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidatePassword(%q) error = %v, want nil", tc.pw, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidatePassword(%q) = nil, want error %q", tc.pw, tc.wantErr)
			}
			if err.Error() != tc.wantErr {
				t.Errorf("ValidatePassword(%q) error = %q, want %q", tc.pw, err, tc.wantErr)
			}
		})
	}
}

func TestFormatMissing(t *testing.T) {
	tests := []struct {
		name  string
		items []string
		want  string
	}{
		{"one", []string{"a"}, "a"},
		{"two", []string{"a", "b"}, "a and b"},
		{"three", []string{"a", "b", "c"}, "a, b and c"},
		{"four", []string{"a", "b", "c", "d"}, "a, b, c and d"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatMissing(tc.items); got != tc.want {
				t.Errorf("formatMissing(%v) = %q, want %q", tc.items, got, tc.want)
			}
		})
	}
}

func TestPromptPasswordReturnsInput(t *testing.T) {
	withReadPassword(t, func(fd int) ([]byte, error) {
		if fd != int(os.Stdin.Fd()) {
			t.Errorf("readPassword(fd) = %d, want os.Stdin fd %d", fd, os.Stdin.Fd())
		}
		return []byte("S3cret!Pass"), nil
	})

	got, err := PromptPassword("Password: ")
	if err != nil {
		t.Fatalf("PromptPassword() error = %v", err)
	}
	if got != "S3cret!Pass" {
		t.Errorf("PromptPassword() = %q, want S3cret!Pass", got)
	}
}

func TestPromptPasswordWrapsReadError(t *testing.T) {
	withReadPassword(t, func(fd int) ([]byte, error) {
		return nil, errors.New("boom")
	})

	_, err := PromptPassword("Password: ")
	if err == nil {
		t.Fatal("PromptPassword() error = nil, want wrapped read error")
	}
	if !strings.Contains(err.Error(), "failed to read password") ||
		!strings.Contains(err.Error(), "boom") {
		t.Errorf("error = %q, want it to mention the wrapper and the cause", err)
	}
}

func TestPromptPasswordWithoutTerminalFailsFast(t *testing.T) {
	// No substitution: the real term.ReadPassword must fail the raw-mode
	// ioctl on a non-terminal instead of blocking for input.
	origStdin := os.Stdin
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open %s error = %v", os.DevNull, err)
	}
	os.Stdin = devNull
	t.Cleanup(func() {
		os.Stdin = origStdin
		devNull.Close()
	})

	if _, err := PromptPassword("Password: "); err == nil {
		t.Error("PromptPassword() without a terminal succeeded, want error")
	}
}

func TestConfirmPassword(t *testing.T) {
	t.Run("match", func(t *testing.T) {
		withReadPassword(t, func(fd int) ([]byte, error) {
			return []byte("S3cret!Pass"), nil
		})
		if err := ConfirmPassword("S3cret!Pass"); err != nil {
			t.Errorf("ConfirmPassword() error = %v, want nil", err)
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		withReadPassword(t, func(fd int) ([]byte, error) {
			return []byte("different"), nil
		})
		err := ConfirmPassword("S3cret!Pass")
		if err == nil || err.Error() != "passwords do not match" {
			t.Errorf("ConfirmPassword() error = %v, want passwords do not match", err)
		}
	})

	t.Run("prompt error propagates", func(t *testing.T) {
		withReadPassword(t, func(fd int) ([]byte, error) {
			return nil, errors.New("boom")
		})
		err := ConfirmPassword("S3cret!Pass")
		if err == nil || !strings.Contains(err.Error(), "failed to read password") {
			t.Errorf("ConfirmPassword() error = %v, want the prompt error", err)
		}
	})
}
