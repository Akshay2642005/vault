package auth

import (
	"fmt"
	"os"
	"unicode"

	"golang.org/x/term"
)

// readPassword is the input primitive behind PromptPassword. It is a package
// variable so tests can substitute a non-TTY source: the real implementation
// puts the terminal into raw mode and can only read from an interactive
// terminal, which the test runner does not provide.
var readPassword = term.ReadPassword

// PromptPassword securely prompts the user for a password with the given prompt message.
func PromptPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	password, err := readPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}
	return string(password), nil
}

// ValidatePassword checks password rules: minimum 8 characters, at least one
// uppercase letter, one lowercase letter, one digit, and one special character.
func ValidatePassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSpecial = true
		}
	}

	var missing []string
	if !hasUpper {
		missing = append(missing, "an uppercase letter")
	}
	if !hasLower {
		missing = append(missing, "a lowercase letter")
	}
	if !hasDigit {
		missing = append(missing, "a digit")
	}
	if !hasSpecial {
		missing = append(missing, "a special character")
	}

	if len(missing) > 0 {
		return fmt.Errorf("password must contain at least %s", formatMissing(missing))
	}

	return nil
}

func formatMissing(items []string) string {
	switch len(items) {
	case 1:
		return items[0]
	case 2:
		return items[0] + " and " + items[1]
	default:
		return items[0] + ", " + formatMissing(items[1:])
	}
}

// ConfirmPassword prompts for confirmation and checks if it matches the original password.
func ConfirmPassword(password string) error {
	confirm, err := PromptPassword("Confirm password: ")
	if err != nil {
		return err
	}
	if password != confirm {
		return fmt.Errorf("passwords do not match")
	}
	return nil
}
