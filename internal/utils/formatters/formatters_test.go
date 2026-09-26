package formatters

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vault/internal/domain"
)

func TestDetectFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path string
		want Format
	}{
		{"secrets.env", FormatEnv},
		{"/tmp/a.ENV", FormatEnv},
		{"a.json", FormatJSON},
		{"A.JSON", FormatJSON},
		{"a.yaml", FormatYAML},
		{"a.yml", FormatYAML},
		{"a.YML", FormatYAML},
		{"no-extension", FormatEnv}, // default
		{"a.txt", FormatEnv},        // default
	}
	for _, tt := range tests {
		if got := DetectFormat(tt.path); got != tt.want {
			t.Fatalf("DetectFormat(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

func envOpts() ImportOptions {
	return ImportOptions{Format: FormatEnv, ProjectID: "proj1", Environment: "development"}
}

func TestImportEnv(t *testing.T) {
	t.Parallel()

	content := `# comment line

FOO=bar
DB_URL=postgres://user:pass@host:5432/db
QUOTED="hello world"
SINGLE='single quoted'
WITH_EQUALS=a=b`
	path := writeTemp(t, "in.env", content)

	secrets, err := ImportEnv(path, envOpts())
	if err != nil {
		t.Fatalf("ImportEnv() error = %v", err)
	}
	if len(secrets) != 5 {
		t.Fatalf("imported %d secrets, want 5 (comments/blank lines skipped)", len(secrets))
	}

	got := map[string]string{}
	for _, s := range secrets {
		got[s.Key] = s.Value
		if s.ProjectID != "proj1" || s.Environment != "development" {
			t.Fatalf("secret %q identity = %s/%s, want proj1/development", s.Key, s.ProjectID, s.Environment)
		}
		if s.Type != domain.SecretTypeGeneric {
			t.Fatalf("secret %q Type = %q, want generic", s.Key, s.Type)
		}
	}
	want := map[string]string{
		"FOO":         "bar",
		"DB_URL":      "postgres://user:pass@host:5432/db",
		"QUOTED":      "hello world",   // double quotes stripped
		"SINGLE":      "single quoted", // single quotes stripped
		"WITH_EQUALS": "a=b",           // only first = splits key from value
	}
	for k, w := range want {
		if got[k] != w {
			t.Fatalf("%s = %q, want %q", k, got[k], w)
		}
	}
}

func TestImportEnvInvalidLine(t *testing.T) {
	t.Parallel()

	path := writeTemp(t, "bad.env", "GOOD=1\nNOT_A_KV_LINE\n")

	_, err := ImportEnv(path, envOpts())
	if err == nil || !strings.Contains(err.Error(), "invalid format at line 2") {
		t.Fatalf("ImportEnv() error = %v, want invalid format at line 2", err)
	}

	// SkipErrors drops the bad line and keeps the rest.
	secrets, err := ImportEnv(path, ImportOptions{ProjectID: "p", Environment: "development", SkipErrors: true})
	if err != nil {
		t.Fatalf("ImportEnv(SkipErrors) error = %v", err)
	}
	if len(secrets) != 1 || secrets[0].Key != "GOOD" {
		t.Fatalf("SkipErrors imported %+v, want only GOOD", secrets)
	}
}

func TestImportEnvMissingFile(t *testing.T) {
	t.Parallel()

	if _, err := ImportEnv(filepath.Join(t.TempDir(), "nope.env"), envOpts()); err == nil {
		t.Fatal("ImportEnv(missing) error = nil, want open error")
	}
}

func TestImportEnvInvalidKey(t *testing.T) {
	t.Parallel()

	path := writeTemp(t, "badkey.env", "=novaluekey\n")

	if _, err := ImportEnv(path, envOpts()); err == nil {
		t.Fatal("ImportEnv(empty key) error = nil, want create-secret error")
	}
	secrets, err := ImportEnv(path, ImportOptions{ProjectID: "p", Environment: "development", SkipErrors: true})
	if err != nil {
		t.Fatalf("ImportEnv(SkipErrors) error = %v", err)
	}
	if len(secrets) != 0 {
		t.Fatalf("SkipErrors kept %d secrets, want 0", len(secrets))
	}
}

func testSecrets() []*domain.Secret {
	s1, _ := domain.NewSecret("proj1", "development", "API_KEY", "key-value", domain.SecretTypeAPIKey, "test")
	s1.Tags = []string{"prod"}
	s1.Metadata = map[string]any{"owner": "team"}
	s2, _ := domain.NewSecret("proj1", "development", "GREETING", "hello world", domain.SecretTypeGeneric, "test")
	return []*domain.Secret{s1, s2}
}

func TestExportImportEnvRoundTrip(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "out.env")
	if err := ExportEnv(path, testSecrets(), ExportOptions{ProjectID: "proj1", Environment: "development"}); err != nil {
		t.Fatalf("ExportEnv() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	content := string(data)
	mustContain(t, content,
		"# Exported from Vault",
		"API_KEY=key-value",
		"GREETING=\"hello world\"", // values with spaces are quoted
	)

	back, err := ImportEnv(path, envOpts())
	if err != nil {
		t.Fatalf("ImportEnv() error = %v", err)
	}
	if len(back) != 2 {
		t.Fatalf("round trip kept %d secrets, want 2", len(back))
	}
}

func TestExportEnvMaskValues(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "masked.env")
	if err := ExportEnv(path, testSecrets(), ExportOptions{MaskValues: true}); err != nil {
		t.Fatalf("ExportEnv() error = %v", err)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "key-value") {
		t.Fatal("masked export leaked the secret value")
	}
	mustContain(t, string(data), "API_KEY=********")
}

func TestJSONRoundTrip(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "out.json")
	opts := ExportOptions{ProjectID: "proj1", Environment: "development", IncludeMeta: true}
	if err := ExportJSON(path, testSecrets(), opts); err != nil {
		t.Fatalf("ExportJSON() error = %v", err)
	}

	back, err := ImportJSON(path, ImportOptions{ProjectID: "proj1", Environment: "development"})
	if err != nil {
		t.Fatalf("ImportJSON() error = %v", err)
	}
	if len(back) != 2 {
		t.Fatalf("round trip kept %d secrets, want 2", len(back))
	}
	got := map[string]domain.Secret{}
	for _, s := range back {
		got[s.Key] = s
	}
	api := got["API_KEY"]
	if api.Value != "key-value" || api.Type != domain.SecretTypeAPIKey {
		t.Fatalf("API_KEY = %q/%q, want key-value/api_key", api.Value, api.Type)
	}
	if len(api.Tags) != 1 || api.Tags[0] != "prod" {
		t.Fatalf("API_KEY Tags = %v, want [prod]", api.Tags)
	}
	if api.Metadata["owner"] != "team" {
		t.Fatalf("API_KEY Metadata = %v, want owner=team", api.Metadata)
	}
	if got["GREETING"].Value != "hello world" {
		t.Fatalf("GREETING = %q, want %q", got["GREETING"].Value, "hello world")
	}
}

func TestExportJSONMaskAndErrors(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "masked.json")
	if err := ExportJSON(path, testSecrets(), ExportOptions{MaskValues: true}); err != nil {
		t.Fatalf("ExportJSON() error = %v", err)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "key-value") {
		t.Fatal("masked JSON export leaked the secret value")
	}

	if _, err := ImportJSON(path+"-missing", ImportOptions{}); err == nil {
		t.Fatal("ImportJSON(missing) error = nil, want read error")
	}
	bad := writeTemp(t, "bad.json", "{not json")
	if _, err := ImportJSON(bad, ImportOptions{}); err == nil || !strings.Contains(err.Error(), "failed to parse JSON") {
		t.Fatalf("ImportJSON(bad) error = %v, want parse error", err)
	}
}

func TestYAMLRoundTrip(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "out.yaml")
	opts := ExportOptions{ProjectID: "proj1", Environment: "development", IncludeMeta: true}
	if err := ExportYAML(path, testSecrets(), opts); err != nil {
		t.Fatalf("ExportYAML() error = %v", err)
	}

	back, err := ImportYAML(path, ImportOptions{ProjectID: "proj1", Environment: "development"})
	if err != nil {
		t.Fatalf("ImportYAML() error = %v", err)
	}
	if len(back) != 2 {
		t.Fatalf("round trip kept %d secrets, want 2", len(back))
	}
	found := false
	for _, s := range back {
		if s.Key == "API_KEY" {
			found = true
			if s.Value != "key-value" || s.Type != domain.SecretTypeAPIKey {
				t.Fatalf("API_KEY = %q/%q, want key-value/api_key", s.Value, s.Type)
			}
		}
	}
	if !found {
		t.Fatal("API_KEY missing from YAML round trip")
	}
}

func TestImportYAMLErrors(t *testing.T) {
	t.Parallel()

	if _, err := ImportYAML(filepath.Join(t.TempDir(), "missing.yaml"), ImportOptions{}); err == nil {
		t.Fatal("ImportYAML(missing) error = nil, want read error")
	}
	bad := writeTemp(t, "bad.yaml", ":\n  - broken: [")
	if _, err := ImportYAML(bad, ImportOptions{}); err == nil || !strings.Contains(err.Error(), "failed to parse YAML") {
		t.Fatalf("ImportYAML(bad) error = %v, want parse error", err)
	}
}

func TestExportProjectJSONAndYAML(t *testing.T) {
	t.Parallel()

	proj, err := domain.NewProject("myapp", "demo", "tester")
	if err != nil {
		t.Fatalf("NewProject() error = %v", err)
	}
	secrets := map[string][]*domain.Secret{
		"development": testSecrets(),
		"production":  testSecrets(),
	}

	jsonPath := filepath.Join(t.TempDir(), "proj.json")
	if err := ExportProject(jsonPath, proj, secrets, FormatJSON); err != nil {
		t.Fatalf("ExportProject(JSON) error = %v", err)
	}
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	mustContain(t, string(data),
		`"name": "myapp"`,
		`"development"`,
		`"production"`,
		`"API_KEY"`,
	)

	yamlPath := filepath.Join(t.TempDir(), "proj.yaml")
	if err := ExportProject(yamlPath, proj, secrets, FormatYAML); err != nil {
		t.Fatalf("ExportProject(YAML) error = %v", err)
	}
	ydata, err := os.ReadFile(yamlPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	mustContain(t, string(ydata), "name: myapp", "development:", "key: API_KEY")

	// .env format is not supported for whole-project export.
	if err := ExportProject(filepath.Join(t.TempDir(), "proj.env"), proj, secrets, FormatEnv); err == nil {
		t.Fatal("ExportProject(env) error = nil, want unsupported format error")
	}
}

func mustContain(t *testing.T, s string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(s, w) {
			t.Fatalf("output missing %q:\n%s", w, s)
		}
	}
}
