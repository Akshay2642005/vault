package cli

import (
	"strings"
)

// NormalizeEnvironment maps common environment aliases to canonical names.
// Supported aliases:
//   - "dev"   -> "development"
//   - "prod"  -> "production"
//   - "stage" -> "staging"
//
// All other values are returned unchanged.
func NormalizeEnvironment(env string) string {
	switch strings.ToLower(env) {
	case "dev":
		return "development"
	case "prod":
		return "production"
	case "stage":
		return "staging"
	default:
		return env
	}
}
