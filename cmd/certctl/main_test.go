package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

// emptyEnv is a getenv that resolves every variable to "" (no overrides), so the
// binary falls back to its built-in single-node defaults.
func emptyEnv(string) string { return "" }

// envFunc builds a getenv backed by a map, for exercising configuration.
func envFunc(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// TestRun_VersionFlag encodes the acceptance criterion that the binary reports
// its version and exits cleanly (no error) for both --version and -version.
func TestRun_VersionFlag(t *testing.T) {
	for _, arg := range []string{"--version", "-version"} {
		var stdout, stderr bytes.Buffer
		if err := run(context.Background(), []string{arg}, emptyEnv, &stdout, &stderr); err != nil {
			t.Fatalf("run(%q) returned error: %v", arg, err)
		}
		out := stdout.String()
		if !strings.Contains(out, "certctl") {
			t.Errorf("run(%q) printed %q to stdout, want it to contain %q", arg, out, "certctl")
		}
		if strings.TrimSpace(out) == "" {
			t.Errorf("run(%q) printed nothing to stdout", arg)
		}
	}
}

// TestRun_ServeExternalWithoutDSNFailsFast: the serve path fails fast when
// external Postgres is selected without a DSN — no silent fallback (R4.5). The
// bundled default now actually serves an embedded single-node Postgres, so its
// full serve path is exercised by internal/server's bundled test and the
// assembled-server tests in internal/projections, not here.
func TestRun_ServeExternalWithoutDSNFailsFast(t *testing.T) {
	env := envFunc(map[string]string{"CERTCTL_POSTGRES_MODE": "external"}) // external, no DSN
	err := run(context.Background(), nil, env, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("serving with external Postgres and no DSN should fail fast")
	}
	low := strings.ToLower(err.Error())
	if !strings.Contains(low, "dsn") && !strings.Contains(low, "postgres") {
		t.Errorf("error %q should name the missing Postgres DSN", err)
	}
}

// TestRun_UnknownFlagIsError ensures bad input fails loudly rather than booting.
func TestRun_UnknownFlagIsError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"--no-such-flag"}, emptyEnv, &stdout, &stderr); err == nil {
		t.Fatal("run with an unknown flag returned nil, want an error")
	}
}

// TestRun_HelpExitsCleanly ensures -h/--help is treated as a clean exit, not an
// error (flag.ErrHelp must not propagate as a failure).
func TestRun_HelpExitsCleanly(t *testing.T) {
	for _, arg := range []string{"-h", "--help"} {
		var stdout, stderr bytes.Buffer
		if err := run(context.Background(), []string{arg}, emptyEnv, &stdout, &stderr); err != nil {
			t.Errorf("run(%q) returned error %v, want clean exit", arg, err)
		}
	}
}

// TestRun_CheckConfigDefault encodes that --check-config resolves and prints the
// effective configuration and exits cleanly. With no environment the binary
// reports its self-contained single-node defaults (bundled Postgres, embedded
// NATS).
func TestRun_CheckConfigDefault(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"--check-config"}, emptyEnv, &stdout, &stderr); err != nil {
		t.Fatalf("run(--check-config) returned error: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{"bundled", "embedded"} {
		if !strings.Contains(out, want) {
			t.Errorf("check-config output %q missing %q", out, want)
		}
	}
}

// TestRun_CheckConfigExternalTargets encodes the S7.4 acceptance that pointing
// at external Postgres/NATS is a supported, exercised configuration: the binary
// resolves the external targets from the environment and reports them, with the
// DSN password redacted.
func TestRun_CheckConfigExternalTargets(t *testing.T) {
	env := envFunc(map[string]string{
		"CERTCTL_POSTGRES_MODE": "external",
		"CERTCTL_POSTGRES_DSN":  "postgres://certctl:s3cretpw@db.example.com:5432/certctl?sslmode=require",
		"CERTCTL_NATS_MODE":     "external",
		"CERTCTL_NATS_URL":      "nats://nats.example.com:4222",
	})
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"--check-config"}, env, &stdout, &stderr); err != nil {
		t.Fatalf("run(--check-config, external) returned error: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{"external", "db.example.com", "nats.example.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("check-config output %q missing %q", out, want)
		}
	}
	if strings.Contains(out, "s3cretpw") {
		t.Errorf("check-config output leaked the DSN password: %q", out)
	}
}

// TestRun_InvalidConfigFailsFast encodes that an invalid configuration is
// rejected before the control plane boots — external Postgres with no DSN must
// be an error, not a silent fallback.
func TestRun_InvalidConfigFailsFast(t *testing.T) {
	env := envFunc(map[string]string{"CERTCTL_POSTGRES_MODE": "external"}) // no DSN
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"--check-config"}, env, &stdout, &stderr); err == nil {
		t.Fatal("run with external Postgres and no DSN returned nil, want a configuration error")
	}
}

// TestRun_CheckConfigShowsTelemetryOff encodes the S7.5 default: --check-config
// reports telemetry as disabled when the operator has not opted in.
func TestRun_CheckConfigShowsTelemetryOff(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"--check-config"}, emptyEnv, &stdout, &stderr); err != nil {
		t.Fatalf("run(--check-config): %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "telemetry") {
		t.Errorf("check-config output %q should report telemetry status", out)
	}
	if !strings.Contains(out, "telemetry.enabled: false") {
		t.Errorf("check-config output %q should show telemetry disabled by default", out)
	}
}
