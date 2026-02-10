package formatters

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"vault/internal/domain"

	"gopkg.in/yaml.v3"
)

func DetectFormat(filepath string) Format {
	lower := strings.ToLower(filepath)

	if strings.HasSuffix(lower, ".env") {
		return FormatEnv
	}
	if strings.HasSuffix(lower, ".json") {
		return FormatJSON
	}
	if strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml") {
		return FormatYAML
	}

	return FormatEnv // default
}

// ExportProject exports an entire project to a file
func ExportProject(filepath string, project *domain.Project, secrets map[string][]*domain.Secret, format Format) error {
	export := ProjectExport{
		Name:         project.Name,
		Description:  project.Description,
		Environments: make(map[string][]SecretExport),
	}

	for envName, envSecrets := range secrets {
		var exports []SecretExport
		for _, secret := range envSecrets {
			exports = append(exports, SecretExport{
				Key:      secret.Key,
				Value:    secret.Value,
				Type:     string(secret.Type),
				Tags:     secret.Tags,
				Metadata: secret.Metadata,
			})
		}
		export.Environments[envName] = exports
	}

	switch format {
	case FormatJSON:
		data, err := json.MarshalIndent(export, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		return os.WriteFile(filepath, data, 0o600)

	case FormatYAML:
		data, err := yaml.Marshal(export)
		if err != nil {
			return fmt.Errorf("failed to marshal YAML: %w", err)
		}
		return os.WriteFile(filepath, data, 0o600)

	default:
		return fmt.Errorf("unsupported format for project export: %s", format)
	}
}
