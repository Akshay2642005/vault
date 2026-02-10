package auth

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

// PromptPassword securely prompts the user for a password with the given prompt message.
func PromptPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}
	return string(password), nil
}

// ValidatePassword checks password rules (minimum length, etc.).
func ValidatePassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	// Add more rules as needed (e.g., complexity, symbols, etc.)
	return nil
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
