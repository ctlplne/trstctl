package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultIsValid(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatalf("Default() must be valid, got: %v", err)
	}
}

func TestParseOverlaysDefaults(t *testing.T) {
	cfg, err := Parse([]byte(`{"postgres":{"mode":"external","dsn":"postgres://x"}}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Postgres.Mode != "external" || cfg.Postgres.DSN != "postgres://x" {
		t.Errorf("file values not applied: %+v", cfg.Postgres)
	}
	// Fields absent from the file keep their defaults.
	if cfg.Server.Addr != Default().Server.Addr {
		t.Errorf("Server.Addr should keep default, got %q", cfg.Server.Addr)
	}
	if cfg.Log.Format != "json" {
		t.Errorf("Log.Format should keep default json, got %q", cfg.Log.Format)
	}
}

// TestEnvOverridesFile pins the precedence: defaults < file < environment.
func TestEnvOverridesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trstctl.json")
	body := `{"server":{"addr":":1111"},"postgres":{"mode":"external","dsn":"file-dsn"}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"TRSTCTL_CONFIG_FILE":  path,
		"TRSTCTL_POSTGRES_DSN": "env-dsn",
		"TRSTCTL_LOG_LEVEL":    "debug",
	}
	cfg, err := Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Postgres.DSN != "env-dsn" {
		t.Errorf("env must override file dsn: got %q", cfg.Postgres.DSN)
	}
	if cfg.Server.Addr != ":1111" {
		t.Errorf("file must override default addr: got %q", cfg.Server.Addr)
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("env must override default log level: got %q", cfg.Log.Level)
	}
	if cfg.NATS.Mode != Default().NATS.Mode {
		t.Errorf("untouched NATS.Mode should be default: got %q", cfg.NATS.Mode)
	}
}

func TestValidateRejectsBadValues(t *testing.T) {
	cases := map[string]func(*Config){
		"postgres mode":          func(c *Config) { c.Postgres.Mode = "weird" },
		"external without dsn":   func(c *Config) { c.Postgres.Mode = "external"; c.Postgres.DSN = "" },
		"nats mode":              func(c *Config) { c.NATS.Mode = "weird" },
		"external without url":   func(c *Config) { c.NATS.Mode = "external"; c.NATS.URL = "" },
		"log level":              func(c *Config) { c.Log.Level = "loud" },
		"log format":             func(c *Config) { c.Log.Format = "binary" },
		"empty addr":             func(c *Config) { c.Server.Addr = "" },
		"negative nats replicas": func(c *Config) { c.NATS.Replicas = -1 },
		"too many nats replicas": func(c *Config) { c.NATS.Replicas = 6 },
		"bad nats sync interval": func(c *Config) { c.NATS.SyncInterval = "soon" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := Default()
			mutate(c)
			if err := c.Validate(); err == nil {
				t.Errorf("expected a validation error for %q", name)
			}
		})
	}
}

func TestExternalModesValidWithConnection(t *testing.T) {
	c := Default()
	c.Postgres.Mode = "external"
	c.Postgres.DSN = "postgres://u:p@host:5432/db"
	c.NATS.Mode = "external"
	c.NATS.URL = "nats://host:4222"
	if err := c.Validate(); err != nil {
		t.Fatalf("external config with connection strings should validate: %v", err)
	}
}

// TestTelemetryOffByDefault pins the privacy-first default: telemetry is
// disabled unless explicitly enabled (S7.5 acceptance).
func TestTelemetryOffByDefault(t *testing.T) {
	if Default().Telemetry.Enabled {
		t.Fatal("telemetry must be OFF by default")
	}
	// An empty environment keeps it off.
	cfg, err := Load(func(string) string { return "" })
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Telemetry.Enabled {
		t.Error("telemetry must stay off with no opt-in")
	}
}

// TestTelemetryOptInViaEnv: the operator opts in explicitly through the
// environment, and the endpoint/interval defaults are present.
func TestTelemetryOptInViaEnv(t *testing.T) {
	env := map[string]string{"TRSTCTL_TELEMETRY_ENABLED": "true"}
	cfg, err := Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Telemetry.Enabled {
		t.Error("TRSTCTL_TELEMETRY_ENABLED=true must enable telemetry")
	}
	if cfg.Telemetry.Endpoint == "" {
		t.Error("an enabled telemetry config must have a default endpoint")
	}
	if d, err := cfg.Telemetry.IntervalDuration(); err != nil || d <= 0 {
		t.Errorf("telemetry interval must default to a positive duration, got %v (%v)", d, err)
	}
}

// TestTelemetryValidation: when enabled, telemetry needs a valid https endpoint
// and a positive interval.
func TestTelemetryValidation(t *testing.T) {
	cases := map[string]func(*Config){
		"enabled without endpoint": func(c *Config) { c.Telemetry.Enabled = true; c.Telemetry.Endpoint = "" },
		"enabled non-https":        func(c *Config) { c.Telemetry.Enabled = true; c.Telemetry.Endpoint = "http://t.example/v1" },
		"enabled bad interval":     func(c *Config) { c.Telemetry.Enabled = true; c.Telemetry.Interval = "soon" },
		"enabled zero interval":    func(c *Config) { c.Telemetry.Enabled = true; c.Telemetry.Interval = "0s" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := Default()
			mutate(c)
			if err := c.Validate(); err == nil {
				t.Errorf("expected a validation error for %q", name)
			}
		})
	}

	// Disabled telemetry imposes no endpoint/interval requirements.
	c := Default()
	c.Telemetry.Enabled = false
	c.Telemetry.Endpoint = ""
	c.Telemetry.Interval = ""
	if err := c.Validate(); err != nil {
		t.Errorf("disabled telemetry must not require an endpoint: %v", err)
	}
}

// TestEmbeddedEventLogFsyncDefaultIsBounded pins RESIL-001: the default
// (embedded) event log is configured to fsync on a tight bounded cadence, NOT
// nats-server's ~2-minute default — so a single-node power loss bounds data loss
// to ~1s. The pre-fix tree left SyncInterval empty (the ~2-minute default applied),
// so this fails before the fix.
func TestEmbeddedEventLogFsyncDefaultIsBounded(t *testing.T) {
	d, err := Default().NATS.SyncIntervalDuration()
	if err != nil {
		t.Fatalf("default sync interval must parse: %v", err)
	}
	if d <= 0 {
		t.Fatalf("embedded event log must have a bounded fsync cadence by default, got %v (the unbounded nats-server ~2m default)", d)
	}
	if d > 5*time.Second {
		t.Errorf("default embedded fsync cadence %v is too loose for a single-node RPO target", d)
	}
	if DefaultEmbeddedSyncInterval <= 0 || DefaultEmbeddedSyncInterval > 5*time.Second {
		t.Errorf("DefaultEmbeddedSyncInterval = %v, want a small positive bound", DefaultEmbeddedSyncInterval)
	}
}

// TestEventStreamReplicasConfigurable pins SPINE-004: the event-stream replication
// factor is a config knob, surfaced through config + env, with a non-trivial default
// in external (clustered) mode.
func TestEventStreamReplicasConfigurable(t *testing.T) {
	if DefaultExternalReplicas < 3 {
		t.Errorf("DefaultExternalReplicas = %d, want >= 3 for HA", DefaultExternalReplicas)
	}
	// Config knob round-trips through the env overlay.
	env := map[string]string{
		"TRSTCTL_NATS_REPLICAS":      "5",
		"TRSTCTL_NATS_SYNC_INTERVAL": "250ms",
		"TRSTCTL_NATS_SYNC_ALWAYS":   "true",
	}
	cfg, err := Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.NATS.Replicas != 5 {
		t.Errorf("NATS.Replicas = %d, want 5 from env", cfg.NATS.Replicas)
	}
	if cfg.NATS.SyncInterval != "250ms" {
		t.Errorf("NATS.SyncInterval = %q, want 250ms from env", cfg.NATS.SyncInterval)
	}
	if !cfg.NATS.SyncAlways {
		t.Error("NATS.SyncAlways must be settable via env")
	}
}
