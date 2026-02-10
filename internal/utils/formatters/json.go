package formatters

import (
	"encoding/json"
	"fmt"
	"os"

	"vault/internal/domain"
)

// ImportJSON imports secrets from a JSON file
func ImportJSON(filepath string, opts ImportOptions) ([]domain.Secret, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var exports []SecretExport
	if err := json.Unmarshal(data, &exports); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	var secrets []domain.Secret
	for _, exp := range exports {
		secretType := domain.SecretTypeGeneric
		if exp.Type != "" {
			secretType = domain.SecretType(exp.Type)
		}

		secret, err := domain.NewSecret(
			opts.ProjectID,
			opts.Environment,
			exp.Key,
			exp.Value,
			secretType,
			"import",
		)
		if err != nil {
			if opts.SkipErrors {
				continue
			}
			return nil, fmt.Errorf("failed to create secret %s: %w", exp.Key, err)
		}

		secret.Tags = exp.Tags
		secret.Metadata = exp.Metadata

		secrets = append(secrets, *secret)
	}

	return secrets, nil
}

// ExportJSON exports secrets to a JSON file
func ExportJSON(filepath string, secrets []*domain.Secret, opts ExportOptions) error {
	var exports []SecretExport

	for _, secret := range secrets {
		exp := SecretExport{
			Key:   secret.Key,
			Value: secret.Value,
		}

		if opts.MaskValues {
			exp.Value = "********"
		}

		if opts.IncludeMeta {
			exp.Type = string(secret.Type)
			exp.Tags = secret.Tags
			exp.Metadata = secret.Metadata
		}

		exports = append(exports, exp)
	}

	data, err := json.MarshalIndent(exports, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if err := os.WriteFile(filepath, data, 0o600); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}
