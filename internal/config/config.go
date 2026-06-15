// Package config loads, merges, and validates trustctl's configuration from a
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
	"strings"
	"time"
)

// Datastore mode values.
const (
	PostgresBundled  = "bundled"
	PostgresExternal = "external"
	NATSEmbedded     = "embedded"
	NATSExternal     = "external"
)

// Event-stream durability/replication defaults (RESIL-001 / SPINE-004).
const (
	// DefaultEmbeddedSyncInterval is the embedded JetStream fsync cadence trustctl
	// applies when NATS.SyncInterval is unset (RESIL-001). nats-server's own default
	// is ~2 minutes; trustctl tightens it to one second so a single-node power loss
	// can lose at most ~1s of acked events instead of ~2 minutes, while avoiding the
	// throughput cost of fsync-on-every-append (NATS.SyncAlways, opt-in). It bounds
	// the single-node RPO for un-backed-up events; production still steers to an
	// external replicated cluster.
	DefaultEmbeddedSyncInterval = time.Second
	// DefaultExternalReplicas is the JetStream replication factor for the event
	// stream in external (clustered) mode when NATS.Replicas is unset (SPINE-004): a
	// three-way replicated source-of-truth log survives a single NATS node loss
	// without losing an acked event or going offline. Embedded single-node mode
	// always runs with one replica regardless.
	DefaultExternalReplicas = 3
)

// Control-plane TLS modes. The default is internal (TLS on with a self-signed
// certificate); plaintext (disabled) is an explicit, dev-only opt-in.
const (
	// TLSInternal serves TLS with a self-signed, internally-issued certificate —
	// the default, so the control plane is never plaintext out of the box. Clients
	// trust the trustctl-generated CA (suitable for evaluation / internal use).
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
	Protocols Protocols `json:"protocols"`
}

// Protocols enables/disables the served issuance-protocol endpoints (EXC-WIRE-02).
// Each protocol server (ACME, EST, SCEP, CMP, SPIFFE Workload API, SSH CA) is
// library-complete and, when enabled, mounted on the running control plane behind
// the same orchestrator-backed, signer-backed, tenant-scoped, profile-gated issuance
// path the API mint uses (AN-1..AN-5). A protocol is served only when its issuing CA
// is provisioned (a signer is configured); with no signer the routes fail closed.
//
// Posture: the standards-based enrollment protocols (ACME, EST, SCEP, CMP) default
// ON because the product's purpose is to speak them to stock clients (certbot,
// cert-manager, EST/SCEP devices, telco CMP). The SPIFFE Workload API (a gRPC server
// on a local UDS) and the SSH CA default OFF: they bind a host-local socket / a
// distinct credential type that an operator opts into for a given deployment.
type Protocols struct {
	ACME   ProtocolToggle `json:"acme"`
	EST    ProtocolToggle `json:"est"`
	SCEP   ProtocolToggle `json:"scep"`
	CMP    ProtocolToggle `json:"cmp"`
	SPIFFE SPIFFEProtocol `json:"spiffe"`
	SSH    ProtocolToggle `json:"ssh"`
}

// ProtocolToggle enables a served protocol endpoint and binds it to a tenant. The
// served protocol endpoints are single-tenant by mount (the binary serves one tenant
// per protocol path); a future per-vhost/per-path multi-tenant mount is tracked
// separately. TenantID empty falls back to the platform default tenant.
type ProtocolToggle struct {
	Enabled  bool   `json:"enabled,omitempty"`
	TenantID string `json:"tenant_id,omitempty"`
}

// SPIFFEProtocol configures the served SPIFFE Workload API gRPC server (INTEROP-004).
// It binds a Unix domain socket a go-spiffe / spiffe-helper / Envoy SDS client dials
// to FetchX509SVID. TrustDomain is the SPIFFE trust domain; Entries register which
// SPIFFE IDs a caller's selectors authorize.
type SPIFFEProtocol struct {
	Enabled     bool   `json:"enabled,omitempty"`
	TenantID    string `json:"tenant_id,omitempty"`
	SocketPath  string `json:"socket_path,omitempty"`  // UDS path; empty uses a default under the data dir
	TrustDomain string `json:"trust_domain,omitempty"` // e.g. "example.org"; empty disables (no default trust domain)
}

// Server holds the control-plane listen settings.
type Server struct {
	Addr string `json:"addr"`
	TLS  TLS    `json:"tls"`
	// CORSAllowedOrigins is the explicit allow-list of browser Origins permitted to
	// make cross-origin requests to the API (SEC-003). Empty (the default) means
	// same-origin only: the served console and the API share an origin, so no
	// Access-Control-Allow-Origin is emitted and a cross-origin XHR is blocked by
	// the browser. List exact origins (scheme+host+port, e.g.
	// "https://console.example.com") to allow a separately-hosted UI; "*" is
	// deliberately NOT honored for a credentialed API.
	CORSAllowedOrigins []string `json:"cors_allowed_origins,omitempty"`
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
	DataDir string `json:"data_dir"` // used when bundled (the embedded data lives here)
	Port    int    `json:"port"`     // loopback port for the bundled datastore (default 5432)
}

// NATS selects the embedded file-backed JetStream or an external cluster, and
// carries the source-of-truth event stream's durability and replication knobs
// (RESIL-001 / SPINE-004).
type NATS struct {
	Mode     string `json:"mode"`      // embedded | external
	URL      string `json:"url"`       // required when external
	StoreDir string `json:"store_dir"` // used when embedded

	// Replicas is the JetStream replication factor for the event stream — the
	// source of truth (AN-2). In external (clustered) mode the default is 3, so a
	// single NATS node loss neither loses an acked event nor takes the log offline
	// (SPINE-004). It must not exceed the cluster size. In embedded single-node mode
	// it is forced to 1 (there is only one server), so this knob is a production-
	// cluster concern. Zero means "use the mode's default".
	Replicas int `json:"replicas"`

	// SyncInterval bounds how often the embedded, file-backed JetStream flushes the
	// stream to stable storage (fsync), i.e. the single-node durability/RPO window
	// (RESIL-001). nats-server defaults this to ~2 minutes, so out of the box a
	// Publish ACK is a page-cache write and a power loss within the window can lose
	// up to ~2 minutes of acked events from the source-of-truth log. trustctl
	// tightens it to a short default (see DefaultEmbeddedSyncInterval); an operator
	// may shorten it further, or set SyncAlways for fsync-on-every-append. It only
	// affects embedded mode (an external cluster manages its own durability). A Go
	// duration string, e.g. "1s"; empty uses the trustctl default.
	SyncInterval string `json:"sync_interval"`

	// SyncAlways makes the embedded JetStream fsync the stream on every append
	// (O_SYNC) rather than on the interval, giving a near-zero single-node RPO at a
	// throughput cost (RESIL-001). It only affects embedded mode. Off by default;
	// the bounded SyncInterval already caps the loss window without the per-write
	// fsync penalty.
	SyncAlways bool `json:"sync_always"`
}

// SyncIntervalDuration parses the embedded JetStream fsync cadence (RESIL-001). An
// empty value means the trustctl embedded default (DefaultEmbeddedSyncInterval)
// and returns a zero duration with no error so the caller can apply the default.
func (n NATS) SyncIntervalDuration() (time.Duration, error) {
	if n.SyncInterval == "" {
		return 0, nil
	}
	return time.ParseDuration(n.SyncInterval)
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

// Audit configures the event-sourced audit trail's evidence export (F9 / B5) and
// its retention lifecycle (R4.4). By default (empty Retention) the event log is
// retained indefinitely. When Retention is set AND ArchiveDir is given, a
// background worker enforces it: records older than the window are archived as
// signed, offline-verifiable bundles under ArchiveDir, a signed checkpoint is
// sealed, and the records are then pruned from the hot event log — the chain stays
// verifiable across the prune, and the archive plus the live log remain the
// authoritative history. SigningKeyFile persists the export/checkpoint signing key
// so bundles verify across restarts.
type Audit struct {
	SigningKeyFile string `json:"signing_key_file"` // PEM path; persisted so the export key does not rotate
	Retention      string `json:"retention"`        // Go duration; empty means indefinite (no pruning, the default)
	ArchiveDir     string `json:"archive_dir"`      // cold-storage directory for signed archive bundles; required to enable retention pruning
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
// (`trustctl --migrate-status`), takes a backup, then applies them explicitly
// (`trustctl --migrate`).
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
// mode the control plane supervises trustctl-signer as a child process (single
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
	// SignerChild supervises trustctl-signer as a child process (single binary).
	SignerChild = "child"
	// SignerExternal connects to a separately deployed signer over a socket.
	SignerExternal = "external"
)

// CA configures the assembled issuing CA. CertFile is where its self-signed
// certificate is persisted; reusing it (with the signer's persisted key) keeps
// the CA stable across restarts (R3.2 — no silent rotation).
type CA struct {
	CertFile string `json:"cert_file"`

	// Served-leaf issuance profile (PKIGOV-001). These RFC 5280 / CA-Browser-Forum
	// pointers are stamped on every leaf the served binary mints so relying parties
	// can locate revocation status and build the chain. They are operator-supplied
	// because the URLs are deployment-specific; the Subject Key Identifier is always
	// set regardless. The binary now serves OCSP at /ocsp/{tenant} and a CRL at
	// /crl/{tenant} (EXC-REVOKE-01), so point CRLDistributionPoints/OCSPServers at
	// those routes (behind your ingress) — or at an external responder you prefer.
	CRLDistributionPoints []string `json:"crl_distribution_points,omitempty"`
	OCSPServers           []string `json:"ocsp_servers,omitempty"`
	IssuerURLs            []string `json:"issuer_urls,omitempty"`
	// CertificatePolicyOIDs are placed in the certificatePolicies extension. The
	// default is a single private-enterprise policy OID identifying trustctl
	// issuance; override it with your CP/CPS policy OID(s).
	CertificatePolicyOIDs []string `json:"certificate_policy_oids,omitempty"`

	// DefaultProfile is the certificate-profile name applied to the served mint
	// (PKIGOV-002). When set and the named profile resolves for the tenant, the
	// served issuance is validated against it (validity/EKU/key/DNS-suffix) and an
	// out-of-profile request is rejected with an issuance.profile_evaluated deny
	// event. Empty means no served-side profile binding (the prior behavior).
	DefaultProfile string `json:"default_profile,omitempty"`

	// Policy gates the served issue/deploy/revoke path with the OPA/Rego default-deny
	// engine, the RA scope split, and dual-control approval (EXC-WIRE-03; closes
	// SEC-002/SEC-005/CORRECT-003, the served half of RED-004). The zero value leaves
	// enforcement off so an upgrade does not silently start denying; turn it on per
	// deployment.
	Policy PolicyGate `json:"policy,omitempty"`
}

// PolicyGate configures the served authorization gate on the mutating issuance path
// (EXC-WIRE-03). It is part of the CA config because it governs issuance/revocation.
type PolicyGate struct {
	// Enabled turns on the served default-deny OPA/Rego policy gate: every served
	// issue/deploy/revoke transition is denied unless the policy explicitly allows it
	// (fail closed). The RA scope split (a requester cannot self-issue) is always
	// enforced for privileged transitions independent of this flag.
	Enabled bool `json:"enabled,omitempty"`
	// Module is the Rego policy document (its text). Empty uses the built-in
	// default-deny base policy (permit revoke; require a bound profile to issue/deploy).
	Module string `json:"module,omitempty"`
	// RequireApproval turns on served dual control for privileged transitions: an
	// issue/revoke is denied unless a DISTINCT approver has approved it via the served
	// approval endpoint (self-approval is rejected).
	RequireApproval bool `json:"require_approval,omitempty"`
	// RequiredApprovals is the number of distinct approvals required when
	// RequireApproval is on. Zero defaults to 2 (dual control).
	RequiredApprovals int `json:"required_approvals,omitempty"`
}

// Default returns the built-in configuration: a self-contained single-node
// deployment that needs no external services.
func Default() *Config {
	return &Config{
		Server:   Server{Addr: ":8443", TLS: TLS{Mode: TLSInternal}},
		Postgres: Postgres{Mode: PostgresBundled, DataDir: "data/postgres", Port: 5432},
		// The embedded event log fsyncs on a tight bounded cadence by default so a
		// single-node power loss bounds data loss to ~1s rather than nats-server's
		// ~2-minute default (RESIL-001). Replicas defaults to 0 here ("use the mode
		// default"): embedded forces 1, external uses DefaultExternalReplicas (3) for
		// HA (SPINE-004).
		NATS:      NATS{Mode: NATSEmbedded, StoreDir: "data/nats", SyncInterval: DefaultEmbeddedSyncInterval.String()},
		Log:       Log{Level: "info", Format: "json"},
		Lifecycle: Lifecycle{RenewBefore: "720h", AlertBefore: "336h"}, // 30d renew, 14d alert
		// Telemetry is OFF by default (privacy-first; decided position). The
		// endpoint and interval are defaults that take effect only on opt-in.
		Telemetry: Telemetry{Enabled: false, Endpoint: "https://telemetry.trustctl.io/v1/usage", Interval: "24h"},
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
		// The issuing CA certificate persists so it is stable across restarts. A
		// baseline certificatePolicies OID is set so every served leaf carries a
		// policy (RFC 5280 / BR-thin, PKIGOV-001); CDP/AIA URLs are left empty for the
		// operator to point at their own CDP/OCSP responders. The OID is a private
		// arc under the OID Repository's example/private space — override it with your
		// CP/CPS policy OID.
		CA: CA{
			CertFile:              "data/ca/issuing-ca.crt",
			CertificatePolicyOIDs: []string{"1.3.6.1.4.1.59551.1.1"},
		},
		// Served issuance protocols (EXC-WIRE-02). The standards-based enrollment
		// protocols default ON because speaking them to stock clients is the product's
		// purpose; they activate only when an issuing CA is provisioned (a signer is
		// configured), and fail closed otherwise. SPIFFE (a local UDS gRPC server) and
		// the SSH CA default OFF — an operator opts those into a deployment.
		Protocols: Protocols{
			ACME:   ProtocolToggle{Enabled: true},
			EST:    ProtocolToggle{Enabled: true},
			SCEP:   ProtocolToggle{Enabled: true},
			CMP:    ProtocolToggle{Enabled: true},
			SPIFFE: SPIFFEProtocol{Enabled: false},
			SSH:    ProtocolToggle{Enabled: false},
		},
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
// named by TRUSTCTL_CONFIG_FILE, then environment overrides, and validates it.
// getenv is injected (pass os.Getenv) for testability.
func Load(getenv func(string) string) (*Config, error) {
	cfg := Default()
	if path := getenv("TRUSTCTL_CONFIG_FILE"); path != "" {
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

// applyEnv overlays TRUSTCTL_*-prefixed environment variables. Only non-empty
// variables take effect, so the environment can override but not blank out
// file or default values.
func (c *Config) applyEnv(getenv func(string) string) {
	setString(getenv, "TRUSTCTL_SERVER_ADDR", &c.Server.Addr)
	setString(getenv, "TRUSTCTL_SERVER_TLS_MODE", &c.Server.TLS.Mode)
	setString(getenv, "TRUSTCTL_SERVER_TLS_CERT_FILE", &c.Server.TLS.CertFile)
	setString(getenv, "TRUSTCTL_SERVER_TLS_KEY_FILE", &c.Server.TLS.KeyFile)
	setCSV(getenv, "TRUSTCTL_CORS_ALLOWED_ORIGINS", &c.Server.CORSAllowedOrigins)
	setString(getenv, "TRUSTCTL_POSTGRES_MODE", &c.Postgres.Mode)
	setString(getenv, "TRUSTCTL_POSTGRES_DSN", &c.Postgres.DSN)
	setString(getenv, "TRUSTCTL_POSTGRES_DATA_DIR", &c.Postgres.DataDir)
	setInt(getenv, "TRUSTCTL_POSTGRES_PORT", &c.Postgres.Port)
	setString(getenv, "TRUSTCTL_NATS_MODE", &c.NATS.Mode)
	setString(getenv, "TRUSTCTL_NATS_URL", &c.NATS.URL)
	setString(getenv, "TRUSTCTL_NATS_STORE_DIR", &c.NATS.StoreDir)
	setInt(getenv, "TRUSTCTL_NATS_REPLICAS", &c.NATS.Replicas)
	setString(getenv, "TRUSTCTL_NATS_SYNC_INTERVAL", &c.NATS.SyncInterval)
	setBool(getenv, "TRUSTCTL_NATS_SYNC_ALWAYS", &c.NATS.SyncAlways)
	setString(getenv, "TRUSTCTL_LOG_LEVEL", &c.Log.Level)
	setString(getenv, "TRUSTCTL_LOG_FORMAT", &c.Log.Format)
	setString(getenv, "TRUSTCTL_LIFECYCLE_RENEW_BEFORE", &c.Lifecycle.RenewBefore)
	setString(getenv, "TRUSTCTL_LIFECYCLE_ALERT_BEFORE", &c.Lifecycle.AlertBefore)
	setBool(getenv, "TRUSTCTL_TELEMETRY_ENABLED", &c.Telemetry.Enabled)
	setString(getenv, "TRUSTCTL_TELEMETRY_ENDPOINT", &c.Telemetry.Endpoint)
	setString(getenv, "TRUSTCTL_TELEMETRY_INTERVAL", &c.Telemetry.Interval)
	setString(getenv, "TRUSTCTL_AUDIT_SIGNING_KEY_FILE", &c.Audit.SigningKeyFile)
	setString(getenv, "TRUSTCTL_AUDIT_RETENTION", &c.Audit.Retention)
	setString(getenv, "TRUSTCTL_AUDIT_ARCHIVE_DIR", &c.Audit.ArchiveDir)
	setBool(getenv, "TRUSTCTL_RATE_LIMIT_ENABLED", &c.RateLimit.Enabled)
	setInt(getenv, "TRUSTCTL_RATE_LIMIT_REQUESTS", &c.RateLimit.Requests)
	setString(getenv, "TRUSTCTL_RATE_LIMIT_WINDOW", &c.RateLimit.Window)
	setBool(getenv, "TRUSTCTL_MIGRATE_AUTO", &c.Migrate.Auto)
	setString(getenv, "TRUSTCTL_SECRETS_KEK_FILE", &c.Secrets.KEKFile)
	setString(getenv, "TRUSTCTL_SIGNER_MODE", &c.Signer.Mode)
	setString(getenv, "TRUSTCTL_SIGNER_SOCKET", &c.Signer.Socket)
	setString(getenv, "TRUSTCTL_SIGNER_KEY_STORE_DIR", &c.Signer.KeyStoreDir)
	setString(getenv, "TRUSTCTL_CA_CERT_FILE", &c.CA.CertFile)
	// Served issuance protocols (EXC-WIRE-02): per-protocol enable + tenant binding.
	setBool(getenv, "TRUSTCTL_PROTOCOLS_ACME_ENABLED", &c.Protocols.ACME.Enabled)
	setString(getenv, "TRUSTCTL_PROTOCOLS_ACME_TENANT_ID", &c.Protocols.ACME.TenantID)
	setBool(getenv, "TRUSTCTL_PROTOCOLS_EST_ENABLED", &c.Protocols.EST.Enabled)
	setString(getenv, "TRUSTCTL_PROTOCOLS_EST_TENANT_ID", &c.Protocols.EST.TenantID)
	setBool(getenv, "TRUSTCTL_PROTOCOLS_SCEP_ENABLED", &c.Protocols.SCEP.Enabled)
	setString(getenv, "TRUSTCTL_PROTOCOLS_SCEP_TENANT_ID", &c.Protocols.SCEP.TenantID)
	setBool(getenv, "TRUSTCTL_PROTOCOLS_CMP_ENABLED", &c.Protocols.CMP.Enabled)
	setString(getenv, "TRUSTCTL_PROTOCOLS_CMP_TENANT_ID", &c.Protocols.CMP.TenantID)
	setBool(getenv, "TRUSTCTL_PROTOCOLS_SPIFFE_ENABLED", &c.Protocols.SPIFFE.Enabled)
	setString(getenv, "TRUSTCTL_PROTOCOLS_SPIFFE_TENANT_ID", &c.Protocols.SPIFFE.TenantID)
	setString(getenv, "TRUSTCTL_PROTOCOLS_SPIFFE_SOCKET_PATH", &c.Protocols.SPIFFE.SocketPath)
	setString(getenv, "TRUSTCTL_PROTOCOLS_SPIFFE_TRUST_DOMAIN", &c.Protocols.SPIFFE.TrustDomain)
	setBool(getenv, "TRUSTCTL_PROTOCOLS_SSH_ENABLED", &c.Protocols.SSH.Enabled)
	setString(getenv, "TRUSTCTL_PROTOCOLS_SSH_TENANT_ID", &c.Protocols.SSH.TenantID)
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

// setCSV overlays a comma-separated environment variable as a string slice,
// trimming surrounding whitespace and dropping empty entries (SEC-003 CORS
// allow-list). A non-empty value replaces the destination; an empty/blank value
// leaves the prior value (so the env can override but not blank out a file value).
func setCSV(getenv func(string) string, key string, dst *[]string) {
	v := getenv(key)
	if v == "" {
		return
	}
	var out []string
	for _, part := range strings.Split(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	if len(out) > 0 {
		*dst = out
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
	// Event-stream replication factor (SPINE-004): zero means "use the mode default"
	// (embedded forces 1; external uses DefaultExternalReplicas); a negative value is
	// nonsensical, and JetStream caps a stream at 5 replicas.
	if c.NATS.Replicas < 0 {
		errs = append(errs, errors.New("nats.replicas must not be negative"))
	} else if c.NATS.Replicas > 5 {
		errs = append(errs, fmt.Errorf("nats.replicas %d exceeds the JetStream maximum of 5", c.NATS.Replicas))
	}
	// Embedded fsync cadence (RESIL-001): empty means the trustctl default; when set
	// it must be a valid, positive Go duration.
	if d, err := c.NATS.SyncIntervalDuration(); err != nil {
		errs = append(errs, fmt.Errorf("nats.sync_interval %q is invalid: %w", c.NATS.SyncInterval, err))
	} else if d < 0 {
		errs = append(errs, errors.New("nats.sync_interval must not be negative"))
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
