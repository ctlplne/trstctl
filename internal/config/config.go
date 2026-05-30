// Package config loads, merges, and validates certctl's configuration from a
// JSON file and the environment, with precedence defaults < file < environment.
// It includes the bundled-vs-external datastore switches for PostgreSQL and
// NATS and carries no business logic.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"time"
)

// Datastore mode values.
const (
	PostgresBundled  = "bundled"
	PostgresExternal = "external"
	NATSEmbedded     = "embedded"
	NATSExternal     = "external"
)

// Config is the top-level configuration.
type Config struct {
	Server    Server    `json:"server"`
	Postgres  Postgres  `json:"postgres"`
	NATS      NATS      `json:"nats"`
	Log       Log       `json:"log"`
	Lifecycle Lifecycle `json:"lifecycle"`
	Telemetry Telemetry `json:"telemetry"`
}

// Server holds the control-plane listen settings.
type Server struct {
	Addr string `json:"addr"`
}

// Postgres selects the bundled single-node datastore or an external cluster.
type Postgres struct {
	Mode    string `json:"mode"`     // bundled | external
	DSN     string `json:"dsn"`      // required when external
	DataDir string `json:"data_dir"` // used when bundled
}

// NATS selects the embedded file-backed JetStream or an external cluster.
type NATS struct {
	Mode     string `json:"mode"`      // embedded | external
	URL      string `json:"url"`       // required when external
	StoreDir string `json:"store_dir"` // used when embedded
}

// Log configures structured logging.
type Log struct {
	Level  string `json:"level"`  // debug | info | warn | error
	Format string `json:"format"` // json | text
}

// Lifecycle configures certificate-lifecycle automation (F6): how far ahead of
// expiry to renew, and how far ahead to raise an expiration alert. Thresholds
// are Go durations (for example "720h" for 30 days). ARI-driven renewal timing
// (S4.17) will later refine RenewBefore when the upstream CA supplies a window.
type Lifecycle struct {
	RenewBefore string `json:"renew_before"`
	AlertBefore string `json:"alert_before"`
}

// RenewBeforeDuration parses the renewal threshold.
func (l Lifecycle) RenewBeforeDuration() (time.Duration, error) {
	return time.ParseDuration(l.RenewBefore)
}

// AlertBeforeDuration parses the alert threshold.
func (l Lifecycle) AlertBeforeDuration() (time.Duration, error) {
	return time.ParseDuration(l.AlertBefore)
}

// Telemetry configures opt-in, off-by-default usage reporting (F-telemetry).
// When Enabled is false (the default) nothing is ever sent. When enabled, the
// reporter sends only coarse, anonymized, non-PII data to Endpoint every
// Interval.
type Telemetry struct {
	Enabled  bool   `json:"enabled"`
	Endpoint string `json:"endpoint"`
	Interval string `json:"interval"` // Go duration, e.g. "24h"
}

// IntervalDuration parses the telemetry reporting interval.
func (t Telemetry) IntervalDuration() (time.Duration, error) {
	return time.ParseDuration(t.Interval)
}

// Default returns the built-in configuration: a self-contained single-node
// deployment that needs no external services.
func Default() *Config {
	return &Config{
		Server:    Server{Addr: ":8443"},
		Postgres:  Postgres{Mode: PostgresBundled, DataDir: "data/postgres"},
		NATS:      NATS{Mode: NATSEmbedded, StoreDir: "data/nats"},
		Log:       Log{Level: "info", Format: "json"},
		Lifecycle: Lifecycle{RenewBefore: "720h", AlertBefore: "336h"}, // 30d renew, 14d alert
		// Telemetry is OFF by default (privacy-first; decided position). The
		// endpoint and interval are defaults that take effect only on opt-in.
		Telemetry: Telemetry{Enabled: false, Endpoint: "https://telemetry.certctl.io/v1/usage", Interval: "24h"},
	}
}

// Parse overlays a JSON document onto the defaults. Keys absent from the
// document keep their default values.
func Parse(data []byte) (*Config, error) {
	cfg := Default()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}

// Load builds the effective configuration from defaults, then the optional file
// named by CERTCTL_CONFIG_FILE, then environment overrides, and validates it.
// getenv is injected (pass os.Getenv) for testability.
func Load(getenv func(string) string) (*Config, error) {
	cfg := Default()
	if path := getenv("CERTCTL_CONFIG_FILE"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config file %q: %w", path, err)
		}
		parsed, err := Parse(data)
		if err != nil {
			return nil, err
		}
		cfg = parsed
	}
	cfg.applyEnv(getenv)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// applyEnv overlays CERTCTL_*-prefixed environment variables. Only non-empty
// variables take effect, so the environment can override but not blank out
// file or default values.
func (c *Config) applyEnv(getenv func(string) string) {
	setString(getenv, "CERTCTL_SERVER_ADDR", &c.Server.Addr)
	setString(getenv, "CERTCTL_POSTGRES_MODE", &c.Postgres.Mode)
	setString(getenv, "CERTCTL_POSTGRES_DSN", &c.Postgres.DSN)
	setString(getenv, "CERTCTL_POSTGRES_DATA_DIR", &c.Postgres.DataDir)
	setString(getenv, "CERTCTL_NATS_MODE", &c.NATS.Mode)
	setString(getenv, "CERTCTL_NATS_URL", &c.NATS.URL)
	setString(getenv, "CERTCTL_NATS_STORE_DIR", &c.NATS.StoreDir)
	setString(getenv, "CERTCTL_LOG_LEVEL", &c.Log.Level)
	setString(getenv, "CERTCTL_LOG_FORMAT", &c.Log.Format)
	setString(getenv, "CERTCTL_LIFECYCLE_RENEW_BEFORE", &c.Lifecycle.RenewBefore)
	setString(getenv, "CERTCTL_LIFECYCLE_ALERT_BEFORE", &c.Lifecycle.AlertBefore)
	setBool(getenv, "CERTCTL_TELEMETRY_ENABLED", &c.Telemetry.Enabled)
	setString(getenv, "CERTCTL_TELEMETRY_ENDPOINT", &c.Telemetry.Endpoint)
	setString(getenv, "CERTCTL_TELEMETRY_INTERVAL", &c.Telemetry.Interval)
}

func setString(getenv func(string) string, key string, dst *string) {
	if v := getenv(key); v != "" {
		*dst = v
	}
}

// setBool overlays a boolean environment variable. A malformed value is ignored
// (the prior value stands), so a typo can never silently turn telemetry on.
func setBool(getenv func(string) string, key string, dst *bool) {
	if v := getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			*dst = b
		}
	}
}

// Validate reports whether the configuration is internally consistent,
// reporting all problems together.
func (c *Config) Validate() error {
	var errs []error
	if c.Server.Addr == "" {
		errs = append(errs, errors.New("server.addr must not be empty"))
	}
	switch c.Postgres.Mode {
	case PostgresBundled:
		// no extra requirements
	case PostgresExternal:
		if c.Postgres.DSN == "" {
			errs = append(errs, errors.New("postgres.dsn is required when postgres.mode is external"))
		}
	default:
		errs = append(errs, fmt.Errorf("postgres.mode %q is invalid (want %q or %q)", c.Postgres.Mode, PostgresBundled, PostgresExternal))
	}
	switch c.NATS.Mode {
	case NATSEmbedded:
		// no extra requirements
	case NATSExternal:
		if c.NATS.URL == "" {
			errs = append(errs, errors.New("nats.url is required when nats.mode is external"))
		}
	default:
		errs = append(errs, fmt.Errorf("nats.mode %q is invalid (want %q or %q)", c.NATS.Mode, NATSEmbedded, NATSExternal))
	}
	if !validLevel(c.Log.Level) {
		errs = append(errs, fmt.Errorf("log.level %q is invalid (want debug, info, warn, or error)", c.Log.Level))
	}
	switch c.Log.Format {
	case "json", "text":
		// ok
	default:
		errs = append(errs, fmt.Errorf("log.format %q is invalid (want json or text)", c.Log.Format))
	}
	if d, err := c.Lifecycle.RenewBeforeDuration(); err != nil {
		errs = append(errs, fmt.Errorf("lifecycle.renew_before %q is invalid: %w", c.Lifecycle.RenewBefore, err))
	} else if d <= 0 {
		errs = append(errs, errors.New("lifecycle.renew_before must be positive"))
	}
	if d, err := c.Lifecycle.AlertBeforeDuration(); err != nil {
		errs = append(errs, fmt.Errorf("lifecycle.alert_before %q is invalid: %w", c.Lifecycle.AlertBefore, err))
	} else if d <= 0 {
		errs = append(errs, errors.New("lifecycle.alert_before must be positive"))
	}
	// Telemetry only constrains anything when the operator has opted in;
	// disabled telemetry needs no endpoint or interval.
	if c.Telemetry.Enabled {
		if c.Telemetry.Endpoint == "" {
			errs = append(errs, errors.New("telemetry.endpoint is required when telemetry is enabled"))
		} else if u, err := url.Parse(c.Telemetry.Endpoint); err != nil || u.Scheme != "https" || u.Host == "" {
			errs = append(errs, fmt.Errorf("telemetry.endpoint %q must be an absolute https URL", c.Telemetry.Endpoint))
		}
		if d, err := c.Telemetry.IntervalDuration(); err != nil {
			errs = append(errs, fmt.Errorf("telemetry.interval %q is invalid: %w", c.Telemetry.Interval, err))
		} else if d <= 0 {
			errs = append(errs, errors.New("telemetry.interval must be positive"))
		}
	}
	return errors.Join(errs...)
}

func validLevel(level string) bool {
	switch level {
	case "debug", "info", "warn", "error":
		return true
	default:
		return false
	}
}
