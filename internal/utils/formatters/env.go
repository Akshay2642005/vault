package formatters

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"vault/internal/domain"
)

// ImportEnv imports secrets from a .env file
func ImportEnv(filepath string, opts ImportOptions) ([]domain.Secret, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var secrets []domain.Secret
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse KEY=VALUE
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			if opts.SkipErrors {
				continue
			}
			return nil, fmt.Errorf("invalid format at line %d: %s", lineNum, line)
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Remove quotes if present
		value = strings.Trim(value, "\"'")

		// Create secret
		secret, err := domain.NewSecret(
			opts.ProjectID,
			opts.Environment,
			key,
			value,
			domain.SecretTypeGeneric,
			"import",
		)
		if err != nil {
			if opts.SkipErrors {
				continue
			}
			return nil, fmt.Errorf("failed to create secret at line %d: %w", lineNum, err)
		}

		secrets = append(secrets, *secret)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	return secrets, nil
}

// ExportEnv exports secrets to a .env file
func ExportEnv(filepath string, secrets []*domain.Secret, opts ExportOptions) error {
	file, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	// Write header comment
	fmt.Fprintf(writer, "# Exported from Vault\n")
	fmt.Fprintf(writer, "# Project: %s, Environment: %s\n", opts.ProjectID, opts.Environment)
	fmt.Fprintf(writer, "# Warning: This file contains sensitive information\n\n")

	for _, secret := range secrets {
		value := secret.Value
		if opts.MaskValues {
			value = "********"
		}

		// Quote value if it contains spaces
		if strings.Contains(value, " ") {
			value = fmt.Sprintf("\"%s\"", value)
		}

		fmt.Fprintf(writer, "%s=%s\n", secret.Key, value)
	}

	return nil
}
