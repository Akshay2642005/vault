// Package importexport handles importing and exporting secrets in various formats
package formatters

// Format represents the import/export format
type Format string

const (
	FormatEnv  Format = "env"
	FormatJSON Format = "json"
	FormatYAML Format = "yaml"
)

// ImportOptions holds options for import operations
type ImportOptions struct {
	Format      Format
	ProjectID   string
	Environment string
	Overwrite   bool
	SkipErrors  bool
}

// ExportOptions holds options for export operations
type ExportOptions struct {
	Format      Format
	ProjectID   string
	Environment string
	IncludeMeta bool
	MaskValues  bool
}

// SecretExport represents a secret in export format
type SecretExport struct {
	Key         string                 `json:"key" yaml:"key"`
	Value       string                 `json:"value" yaml:"value"`
	Type        string                 `json:"type,omitempty" yaml:"type,omitempty"`
	Tags        []string               `json:"tags,omitempty" yaml:"tags,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	Description string                 `json:"description,omitempty" yaml:"description,omitempty"`
}

// ProjectExport represents a project in export format
type ProjectExport struct {
	Name         string                    `json:"name" yaml:"name"`
	Description  string                    `json:"description,omitempty" yaml:"description,omitempty"`
	Environments map[string][]SecretExport `json:"environments" yaml:"environments"`
}

// VaultExport represents a complete vault export
type VaultExport struct {
	Version  int             `json:"version" yaml:"version"`
	Projects []ProjectExport `json:"projects" yaml:"projects"`
}

// DetectFormat attempts to detect the file format from extension
