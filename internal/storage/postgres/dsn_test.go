package postgres

// Unit tests for the harness safety guards. parseTestDSN is pure, so these
// run without a database — they are the rules that keep the destructive
// TRUNCATE suite away from the real sync target.

import (
	"strings"
	"testing"
)

func TestParseTestDSNDefaultsToDockerCompose(t *testing.T) {
	cfg, err := parseTestDSN("", false)
	if err != nil {
		t.Fatalf("parseTestDSN(\"\") error = %v", err)
	}
	if cfg.Host != "localhost" || cfg.Port != 5432 ||
		cfg.Database != "vaultdb" || cfg.User != "vault" || cfg.Password != "vaultpass" {
		t.Errorf("default config = %+v, want docker-compose defaults", cfg)
	}
	if cfg.SSLMode != "disable" {
		t.Errorf("SSLMode = %q, want disable", cfg.SSLMode)
	}
}

func TestParseTestDSNRefusesSupabaseHosts(t *testing.T) {
	dsns := []string{
		"postgres://user:pass@aws-1-ap-northeast-2.pooler.supabase.com:5432/postgres?sslmode=require",
		"postgres://user:pass@db.example.supabase.co:5432/postgres",
		"postgres://user:pass@SUPABASE.EXAMPLE.COM:5432/db",
	}
	for _, dsn := range dsns {
		if _, err := parseTestDSN(dsn, true); err == nil {
			t.Errorf("parseTestDSN(%q, allowRemote=true) succeeded, want refusal", dsn)
		} else if !strings.Contains(err.Error(), "sync target") {
			t.Errorf("parseTestDSN(%q) error = %v, want sync-target refusal", dsn, err)
		}
	}
}

func TestParseTestDSNRefusesNonLoopbackWithoutOptIn(t *testing.T) {
	const dsn = "postgres://vault:vaultpass@db.example.com:5433/vaultdb?sslmode=disable"

	if _, err := parseTestDSN(dsn, false); err == nil {
		t.Fatal("parseTestDSN(non-loopback, allowRemote=false) succeeded, want refusal")
	}

	cfg, err := parseTestDSN(dsn, true)
	if err != nil {
		t.Fatalf("parseTestDSN(non-loopback, allowRemote=true) error = %v", err)
	}
	if cfg.Host != "db.example.com" || cfg.Port != 5433 {
		t.Errorf("config = %+v, want db.example.com:5433", cfg)
	}
}

func TestParseTestDSNLoopbackVariants(t *testing.T) {
	for _, host := range []string{"localhost", "127.0.0.1", "::1"} {
		dsn := "postgres://vault:vaultpass@" + host + ":5433/vaultdb?sslmode=disable"
		if _, err := parseTestDSN(dsn, false); err != nil {
			t.Errorf("parseTestDSN(loopback %q) error = %v, want success without opt-in", host, err)
		}
	}
}

func TestParseTestDSNValidatesShape(t *testing.T) {
	cases := []struct {
		name, dsn, wantErr string
	}{
		{"bad scheme", "mysql://vault:vaultpass@localhost/vaultdb", "scheme"},
		{"no host", "postgres://vault:vaultpass@/vaultdb", "no host"},
		{"no database", "postgres://vault:vaultpass@localhost:5432", "no database path"},
		{"no user", "postgres://localhost:5432/vaultdb", "no user"},
		{"bad port", "postgres://vault:vaultpass@localhost:abc/vaultdb", "invalid port"},
	}
	for _, tc := range cases {
		_, err := parseTestDSN(tc.dsn, false)
		if err == nil {
			t.Errorf("%s: parseTestDSN(%q) succeeded, want error", tc.name, tc.dsn)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: error = %v, want it to contain %q", tc.name, err, tc.wantErr)
		}
	}
}

func TestParseTestDSNPreservesSSLOptIn(t *testing.T) {
	cfg, err := parseTestDSN("postgres://u:p@localhost:5432/db?sslmode=require", false)
	if err != nil {
		t.Fatalf("parseTestDSN() error = %v", err)
	}
	if cfg.SSLMode != "require" {
		t.Errorf("SSLMode = %q, want require", cfg.SSLMode)
	}
}
