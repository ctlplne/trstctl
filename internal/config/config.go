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

// Control-plane TLS modes. The default is internal (TLS on with a self-signed
// certificate); plaintext (disabled) is an explicit, dev-only opt-in.
const (
	// TLSInternal serves TLS with a self-signed, internally-issued certificate —
	// the default, so the control plane is never plaintext out of the box. Clients
	// trust the certctl-generated CA (suitable for evaluation / internal use).
	TLSInternal = "internal"
	// TLSFile serves TLS with an operator-provided certificate and key (PEM).
	TLSFile = "file"
	// TLSDisabled serves plaintext HTTP. It is for local development only and is
	// loudly warned: credentials and sessions travel in the clear.
	TLSDisabled = "disabled"
)

// Config is the top-level configuration.
type Config struct {
	Server    Server    `json:"server"`
	Postgres  Postgres  `json:"postgres"`
	NATS      NATS      `json:"nats"`
	Log       Log       `json:"log"`
	Lifecycle Lifecycle `json:"lifecycle"`
	Telemetry Telemetry `json:"telemetry"`
	Audit     Audit     `json:"audit"`
	RateLimit RateLimit `json:"rate_limit"`
	Migrate   Migrate   `json:"migrate"`
	Secrets   Secrets   `json:"secrets"`
	Signer    Signer    `json:"signer"`
	CA        CA        `json:"ca"`
}

// Server holds the control-plane listen settings.
type Server struct {
	Addr string `json:"addr"`
	TLS  TLS    `json:"tls"`
}

// TLS configures the control plane's transport encryption (B4). Mode is one of
// internal (self-signed, the default), file (operator-provided cert+key), or
// disabled (plaintext, dev-only).
type TLS struct {
	Mode     string `json:"mode"`
	CertFile string `json:"cert_file"` // required when mode is file
	KeyFile  string `json:"key_file"`  // required when mode is file
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

// Audit configures the event-sourced audit trail's evidence export (F9 / B5).
// The event log itself (NATS JetStream) is the immutable source of truth and is
// retained indefinitely by default — Retention documents the operator's archival
// policy rather than pruning the spine. SigningKeyFile persists the export
// signing key so signed evidence bundles verify across restarts.
type Audit struct {
	SigningKeyFile string `json:"signing_key_file"` // PEM path; persisted so the export key does not rotate
	Retention      string `json:"retention"`        // Go duration; empty means indefinite (the default)
	ArchiveDir     string `json:"archive_dir"`      // optional directory for long-term signed-bundle archive
}

// RetentionDuration parses the retention window. An empty value means indefinite
// retention and returns a zero duration with no error.
func (a Audit) RetentionDuration() (time.Duration, error) {
	if a.Retention == "" {
		return 0, nil
	}
	return time.ParseDuration(a.Retention)
}

// RateLimit configures the PostgreSQL-backed per-tenant rate limiter (R2.3 /
// AN-7): each tenant may make Requests calls per Window (a token bucket admitting
// a burst of Requests, refilling steadily over Window). It sheds excess load with
// 429 + Retry-After so one noisy tenant cannot exhaust the control plane.
type RateLimit struct {
	Enabled  bool   `json:"enabled"`
	Requests int    `json:"requests"` // burst/budget per window, per tenant
	Window   string `json:"window"`   // Go duration, e.g. "1m"
}

// WindowDuration parses the rate-limit window.
func (r RateLimit) WindowDuration() (time.Duration, error) {
	return time.ParseDuration(r.Window)
}

// Migrate configures database schema migration at boot (R2.5). With Auto on
// (the default), the control plane applies any pending migrations on startup,
// serialized across instances by an advisory lock. With Auto off, a boot that
// finds pending migrations fails fast with guidance instead of migrating
// silently — the pre-migration backup gate: an operator inspects the plan
// (`certctl --migrate-status`), takes a backup, then applies them explicitly
// (`certctl --migrate`).
type Migrate struct {
	Auto bool `json:"auto"`
}

// Secrets configures credentials-at-rest (R3.1). KEKFile is the key-encryption
// key that wraps every stored CA/connector credential (envelope encryption). It
// is the root of trust for secrets at rest: back it up with the same care as the
// audit signing key, or front it with an HSM/KMS in production. If the file is
// absent it is created (random, 0600) on first boot.
type Secrets struct {
	KEKFile string `json:"kek_file"`
}

// Signer configures the out-of-process signing service (AN-4 / R3.2). In "child"
// mode the control plane supervises certctl-signer as a child process (single
// binary); in "external" mode it connects to a separately deployed signer over
// Socket (the Compose/topology isolation). KeyStoreDir is where the signer seals
// its keys at rest so a restart preserves the issuing CA rather than rotating it;
// the keys are sealed with the same KEK as credentials (Secrets.KEKFile).
type Signer struct {
	Mode        string `json:"mode"`          // "child" (default) or "external"
	Socket      string `json:"socket"`        // UDS path; required in external mode
	KeyStoreDir string `json:"key_store_dir"` // sealed key persistence directory
}

const (
	// SignerChild supervises certctl-signer as a child process (single binary).
	SignerChild = "child"
	// SignerExternal connects to a separately deployed signer over a socket.
	SignerExternal = "external"
)

// CA configures the assembled issuing CA. CertFile is where its self-signed
// certificate is persisted; reusing it (with the signer's persisted key) keeps
// the CA stable across restarts (R3.2 — no silent rotation).
type CA struct {
	CertFile string `json:"cert_file"`
}

// Default returns the built-in configuration: a self-contained single-node
// deployment that needs no external services.
func Default() *Config {
	return &Config{
		Server:    Server{Addr: ":8443", TLS: TLS{Mode: TLSInternal}},
		Postgres:  Postgres{Mode: PostgresBundled, DataDir: "data/postgres"},
		NATS:      NATS{Mode: NATSEmbedded, StoreDir: "data/nats"},
		Log:       Log{Level: "info", Format: "json"},
		Lifecycle: Lifecycle{RenewBefore: "720h", AlertBefore: "336h"}, // 30d renew, 14d alert
		// Telemetry is OFF by default (privacy-first; decided position). The
		// endpoint and interval are defaults that take effect only on opt-in.
		Telemetry: Telemetry{Enabled: false, Endpoint: "https://telemetry.certctl.io/v1/usage", Interval: "24h"},
		// The audit export key persists under the data directory so signed evidence
		// bundles verify across restarts; retention is indefinite by default.
		Audit: Audit{SigningKeyFile: "data/audit/signing-key.pem"},
		// Per-tenant rate limiting is on by default so the product ships with
		// backpressure; the budget is generous and tunable.
		RateLimit: RateLimit{Enabled: true, Requests: 600, Window: "1m"},
		// Automatic migration is on by default so first boot and the single-node
		// eval path apply the schema without extra steps; production deployments
		// can disable it to gate migrations behind an explicit, backed-up step.
		Migrate: Migrate{Auto: true},
		// The credential KEK persists under the data directory so sealed
		// credentials stay openable across restarts; created on first boot if absent.
		Secrets: Secrets{KEKFile: "data/secrets/kek.bin"},
		// The signer runs as a supervised child by default (single binary); its
		// keys are sealed under the data directory so a restart preserves the CA.
		Signer: Signer{Mode: SignerChild, KeyStoreDir: "data/signer/keys"},
		// The issuing CA certificate persists so it is stable across restarts.
		CA: CA{CertFile: "data/ca/issuing-ca.crt"},
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
	setString(getenv, "CERTCTL_SERVER_TLS_MODE", &c.Server.TLS.Mode)
	setString(getenv, "CERTCTL_SERVER_TLS_CERT_FILE", &c.Server.TLS.CertFile)
	setString(getenv, "CERTCTL_SERVER_TLS_KEY_FILE", &c.Server.TLS.KeyFile)
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
	setString(getenv, "CERTCTL_AUDIT_SIGNING_KEY_FILE", &c.Audit.SigningKeyFile)
	setString(getenv, "CERTCTL_AUDIT_RETENTION", &c.Audit.Retention)
	setString(getenv, "CERTCTL_AUDIT_ARCHIVE_DIR", &c.Audit.ArchiveDir)
	setBool(getenv, "CERTCTL_RATE_LIMIT_ENABLED", &c.RateLimit.Enabled)
	setInt(getenv, "CERTCTL_RATE_LIMIT_REQUESTS", &c.RateLimit.Requests)
	setString(getenv, "CERTCTL_RATE_LIMIT_WINDOW", &c.RateLimit.Window)
	setBool(getenv, "CERTCTL_MIGRATE_AUTO", &c.Migrate.Auto)
	setString(getenv, "CERTCTL_SECRETS_KEK_FILE", &c.Secrets.KEKFile)
	setString(getenv, "CERTCTL_SIGNER_MODE", &c.Signer.Mode)
	setString(getenv, "CERTCTL_SIGNER_SOCKET", &c.Signer.Socket)
	setString(getenv, "CERTCTL_SIGNER_KEY_STORE_DIR", &c.Signer.KeyStoreDir)
	setString(getenv, "CERTCTL_CA_CERT_FILE", &c.CA.CertFile)
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

// setInt overlays an integer environment variable. A malformed value is ignored
// (the prior value stands).
func setInt(getenv func(string) string, key string, dst *int) {
	if v := getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			*dst = n
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
	switch c.Server.TLS.Mode {
	case TLSInternal, TLSDisabled:
		// no extra requirements
	case TLSFile:
		if c.Server.TLS.CertFile == "" {
			errs = append(errs, errors.New("server.tls.cert_file is required when server.tls.mode is file"))
		}
		if c.Server.TLS.KeyFile == "" {
			errs = append(errs, errors.New("server.tls.key_file is required when server.tls.mode is file"))
		}
	default:
		errs = append(errs, fmt.Errorf("server.tls.mode %q is invalid (want %q, %q, or %q)", c.Server.TLS.Mode, TLSInternal, TLSFile, TLSDisabled))
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
	// Audit retention is optional (empty means indefinite); when set it must be a
	// valid, non-negative Go duration.
	if d, err := c.Audit.RetentionDuration(); err != nil {
		errs = append(errs, fmt.Errorf("audit.retention %q is invalid: %w", c.Audit.Retention, err))
	} else if d < 0 {
		errs = append(errs, errors.New("audit.retention must not be negative"))
	}
	// Rate limiting, when enabled, needs a positive per-tenant budget and a valid,
	// positive window.
	if c.RateLimit.Enabled {
		if c.RateLimit.Requests <= 0 {
			errs = append(errs, errors.New("rate_limit.requests must be positive when rate limiting is enabled"))
		}
		if d, err := c.RateLimit.WindowDuration(); err != nil {
			errs = append(errs, fmt.Errorf("rate_limit.window %q is invalid: %w", c.RateLimit.Window, err))
		} else if d <= 0 {
			errs = append(errs, errors.New("rate_limit.window must be positive"))
		}
	}
	// The signer runs as a supervised child or connects to an external service; an
	// external signer needs a socket to reach it.
	switch c.Signer.Mode {
	case SignerChild:
		// ok — single-binary supervises the child
	case SignerExternal:
		if c.Signer.Socket == "" {
			errs = append(errs, errors.New("signer.socket is required when signer.mode is external"))
		}
	default:
		errs = append(errs, fmt.Errorf("signer.mode %q is invalid (want %q or %q)", c.Signer.Mode, SignerChild, SignerExternal))
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
