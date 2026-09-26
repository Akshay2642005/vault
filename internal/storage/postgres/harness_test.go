package postgres

// Live-Postgres test harness (Stage B).
//
// SAFETY CONTRACT: every test that uses newTestBackend TRUNCATEs all vault
// data tables before it runs. The target database must therefore be
// disposable:
//
//   - Default (no env): the local docker-compose database
//     (localhost:5432, vault/vaultpass/vaultdb, sslmode=disable).
//   - VAULT_TEST_PG_DSN: opt-in to another database, as a postgres:// URL
//     (e.g. a scratch container on another port). Non-loopback hosts
//     additionally require VAULT_TEST_PG_ALLOW_REMOTE=1.
//   - *.supabase.com hosts are ALWAYS refused: that is the real sync
//     target, never a test fixture.
//
// Tests in this package must NOT call t.Parallel: they share one database.

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"vault/internal/crypto"
	"vault/internal/domain"
	"vault/internal/storage"
)

const testPassword = "password123"

// defaultTestDSN mirrors docker-compose.yml in the repository root.
const defaultTestDSN = "postgres://vault:vaultpass@localhost:5432/vaultdb?sslmode=disable"

// resetList are the data tables wiped between tests. schema_version is kept so
// the (already applied) migrations are not re-run on every case.
var resetList = []string{
	"vault_metadata",
	"projects",
	"environments",
	"secrets",
	"secret_versions",
	"secret_tombstones",
	"sync_runs",
}

// parseTestDSN resolves VAULT_TEST_PG_DSN into a backend config and enforces
// the safety rules. An empty dsn yields the docker-compose default. It is a
// pure function so the safety guards themselves are unit-testable without a
// running server.
func parseTestDSN(dsn string, allowRemote bool) (*storage.Config, error) {
	if strings.TrimSpace(dsn) == "" {
		cfg, err := parseTestDSN(defaultTestDSN, true)
		if err != nil {
			return nil, err
		}
		return cfg, nil
	}

	u, err := url.Parse(dsn)
	if err != nil {
		return nil, fmt.Errorf("VAULT_TEST_PG_DSN is not a valid URL: %w", err)
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return nil, fmt.Errorf("VAULT_TEST_PG_DSN scheme = %q, want postgres://", u.Scheme)
	}

	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("VAULT_TEST_PG_DSN has no host")
	}

	lower := strings.ToLower(host)
	if strings.Contains(lower, "supabase") {
		return nil, fmt.Errorf(
			"refusing to run destructive tests against %q: this suite TRUNCATEs vault tables and must never touch a real sync target",
			host)
	}
	if !isLoopback(host) && !allowRemote {
		return nil, fmt.Errorf(
			"VAULT_TEST_PG_DSN points at non-loopback host %q; set VAULT_TEST_PG_ALLOW_REMOTE=1 only if that database is disposable",
			host)
	}

	port := 5432
	if p := u.Port(); p != "" {
		port, err = strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("VAULT_TEST_PG_DSN has invalid port %q: %w", p, err)
		}
	}

	db := strings.TrimPrefix(u.Path, "/")
	if db == "" {
		return nil, fmt.Errorf("VAULT_TEST_PG_DSN has no database path (want postgres://user:pass@host:port/dbname)")
	}

	user, password := "", ""
	if u.User != nil {
		user = u.User.Username()
		password, _ = u.User.Password()
	}
	if user == "" {
		return nil, fmt.Errorf("VAULT_TEST_PG_DSN has no user (want postgres://user:pass@host:port/dbname)")
	}

	sslmode := u.Query().Get("sslmode")
	if sslmode == "" {
		sslmode = "disable"
	}

	return &storage.Config{
		Type:     "postgres",
		Host:     host,
		Port:     port,
		Database: db,
		User:     user,
		Password: password,
		SSLMode:  sslmode,
	}, nil
}

func isLoopback(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// dsnURL renders cfg as a postgres:// URL (used for the reachability probe).
func dsnURL(cfg *storage.Config) string {
	u := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(cfg.User, cfg.Password),
		Host:   fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Path:   "/" + cfg.Database,
	}
	q := url.Values{}
	q.Set("sslmode", cfg.SSLMode)
	u.RawQuery = q.Encode()
	return u.String()
}

// testConfig resolves the test database configuration and skips the test when
// the database is unreachable, so the suite stays green on machines without a
// running Postgres.
func testConfig(t *testing.T) *storage.Config {
	t.Helper()

	allowRemote := os.Getenv("VAULT_TEST_PG_ALLOW_REMOTE") == "1"
	cfg, err := parseTestDSN(os.Getenv("VAULT_TEST_PG_DSN"), allowRemote)
	if err != nil {
		t.Fatalf("invalid test database configuration: %v", err)
	}

	probe, err := sql.Open("postgres", dsnURL(cfg))
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer probe.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := probe.PingContext(ctx); err != nil {
		t.Skipf("postgres not reachable at %s:%d/%s (start `docker compose up -d` or set VAULT_TEST_PG_DSN): %v",
			cfg.Host, cfg.Port, cfg.Database, err)
	}

	return cfg
}

// resetVaultData wipes all vault data tables, keeping the migrated schema.
func resetVaultData(t *testing.T, b *Backend) {
	t.Helper()

	stmt := "TRUNCATE " + strings.Join(resetList, ", ") + " RESTART IDENTITY CASCADE"
	if _, err := b.db.ExecContext(context.Background(), stmt); err != nil {
		t.Fatalf("TRUNCATE error = %v (the test database must be disposable)", err)
	}
}

// newTestBackend returns an initialized backend on a freshly reset database.
// The vault is NOT created; use newUnlockedBackend for that.
func newTestBackend(t *testing.T) *Backend {
	t.Helper()

	cfg := testConfig(t)

	b, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	if err := b.Initialize(context.Background(), cfg); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	resetVaultData(t, b)
	return b
}

// newUnlockedBackend returns a backend whose vault exists and is unlocked with
// testPassword.
func newUnlockedBackend(t *testing.T) *Backend {
	t.Helper()

	b := newTestBackend(t)
	if err := b.CreateVault(context.Background(), testPassword); err != nil {
		t.Fatalf("CreateVault() error = %v", err)
	}
	return b
}

// mustProject returns the project with the given name, creating it (with its
// default development/staging/production environments) when absent.
func mustProject(t *testing.T, b *Backend, name string) *domain.Project {
	t.Helper()

	ctx := context.Background()
	proj, err := b.GetProjectByName(ctx, name)
	if err == nil {
		return proj
	}

	proj, err = domain.NewProject(name, "", "test")
	if err != nil {
		t.Fatalf("NewProject(%q) error = %v", name, err)
	}
	if err := b.CreateProject(ctx, proj); err != nil {
		t.Fatalf("CreateProject(%q) error = %v", name, err)
	}
	proj, err = b.GetProjectByName(ctx, name)
	if err != nil {
		t.Fatalf("GetProjectByName(%q) error = %v", name, err)
	}
	return proj
}

// seedProjectSecret creates project + secret in one step and returns the
// created secret (already persisted). updatedAt overrides the clock so tests
// can pin exact timestamps; Postgres stores microseconds, so pass
// microsecond-precision times to make round-trip assertions exact.
func seedProjectSecret(t *testing.T, b *Backend, project, env, key, value string, updatedAt time.Time) *domain.Secret {
	t.Helper()

	proj := mustProject(t, b, project)

	secret, err := domain.NewSecret(proj.ID, env, key, value, domain.SecretTypeGeneric, "test")
	if err != nil {
		t.Fatalf("NewSecret(%s/%s/%s) error = %v", project, env, key, err)
	}
	secret.UpdatedBy = "test"
	secret.Checksum = crypto.Hash([]byte(value))
	secret.UpdatedAt = updatedAt
	secret.CreatedAt = updatedAt

	if err := b.CreateSecret(context.Background(), secret); err != nil {
		t.Fatalf("CreateSecret(%s/%s/%s) error = %v", project, env, key, err)
	}
	return secret
}

// getSecret is the read-back counterpart of seedProjectSecret.
func getSecret(t *testing.T, b *Backend, projectID, env, key string) *domain.Secret {
	t.Helper()

	secret, err := b.GetSecret(context.Background(), projectID, env, key)
	if err != nil {
		t.Fatalf("GetSecret(%s/%s/%s) error = %v", projectID, env, key, err)
	}
	return secret
}

// us truncates to microsecond precision — the resolution of Postgres
// `timestamp without time zone` — so instants survive a round trip exactly.
func us(t time.Time) time.Time {
	return t.Truncate(time.Microsecond)
}
