// Package config loads, merges, and validates trustctl's configuration from a
// JSON file and the environment, with precedence defaults < file < environment.
// It includes the bundled-vs-external datastore switches for PostgreSQL and
// NATS and carries no business logic.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
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
	Auth      Auth      `json:"auth"`
	Plugins   Plugins   `json:"plugins"`
	HA        HA        `json:"ha"`
	AI        AI        `json:"ai"`
}

// HA configures the multi-replica high-availability behavior of the control plane
// (RESIL-002 / RESIL-004 / EXC-RESIL-01). It is SAFE on every deployment: with the
// default values a single replica behaves exactly as before. When >1 control-plane
// replica runs against one PostgreSQL + NATS, leader election ensures only ONE replica
// runs the continuous background workers (the projector tailer, outbox dispatcher,
// GC sweeps, CRL scheduler, audit-retention, snapshot worker) while every replica
// serves reads — so N replicas never double-apply (RESIL-004). Snapshots make a cold
// boot / DR restore O(events-since-snapshot) rather than a full-log replay (SPINE-007).
type HA struct {
	// LeaderElection gates the continuous background workers behind a PostgreSQL
	// session-scoped advisory lock so exactly one replica runs them at a time
	// (RESIL-004). It defaults ON: it is correct and cheap on a single replica (that
	// replica simply always wins the lock), and it is REQUIRED for multi-replica
	// safety. Disabling it on a multi-replica deployment reintroduces the
	// double-projection hazard, so leave it on unless you run exactly one replica and
	// want to skip the lock. The leader frees the lock automatically on crash, so a
	// follower takes over (failover) with no lease tuning.
	LeaderElection *bool `json:"leader_election,omitempty"`
	// LeaderCampaignInterval is how often a follower retries to acquire leadership and
	// how often the leader re-checks it still holds the lock (a Go duration, e.g. "3s").
	// Empty uses the package default (leader.DefaultCampaignInterval). Shorter gives
	// faster failover at the cost of more try-lock probes.
	LeaderCampaignInterval string `json:"leader_campaign_interval,omitempty"`
	// SnapshotInterval is how often the leader persists a read-model snapshot at the
	// current projection checkpoint (SPINE-007 / EXC-SCALE-01), so a later cold boot /
	// DR restore rehydrates from it and replays only the tail. A Go duration (e.g.
	// "5m"); empty uses DefaultSnapshotInterval. Set "0" to disable periodic snapshots
	// entirely (boot then always does a full checkpoint catch-up; the log stays truth).
	SnapshotInterval string `json:"snapshot_interval,omitempty"`
}

// DefaultSnapshotInterval is how often the leader writes a read-model snapshot when
// HA.SnapshotInterval is unset (SPINE-007). Five minutes keeps the per-snapshot work
// modest while bounding a cold boot / DR restore to at most ~five minutes of tail
// replay, regardless of how large the lifetime event log is.
const DefaultSnapshotInterval = 5 * time.Minute

// LeaderElectionEnabled reports whether leader election is on, defaulting to ON when
// unset (RESIL-004): the pointer lets an operator explicitly turn it off (a
// single-replica deployment that wants to skip the lock) while a nil/unset value is
// the safe multi-replica default.
func (h HA) LeaderElectionEnabled() bool {
	return h.LeaderElection == nil || *h.LeaderElection
}

// SnapshotIntervalDuration parses HA.SnapshotInterval (SPINE-007). Empty uses
// DefaultSnapshotInterval; "0" (or any non-positive duration) disables periodic
// snapshots and returns a zero duration. A malformed value is an error.
func (h HA) SnapshotIntervalDuration() (time.Duration, error) {
	if h.SnapshotInterval == "" {
		return DefaultSnapshotInterval, nil
	}
	d, err := time.ParseDuration(h.SnapshotInterval)
	if err != nil {
		return 0, fmt.Errorf("ha.snapshot_interval %q: %w", h.SnapshotInterval, err)
	}
	if d < 0 {
		return 0, nil
	}
	return d, nil
}

// LeaderCampaignIntervalDuration parses HA.LeaderCampaignInterval (RESIL-004). Empty
// returns a zero duration so the caller applies the package default; a malformed or
// non-positive value is an error (a zero/negative campaign interval would busy-loop).
func (h HA) LeaderCampaignIntervalDuration() (time.Duration, error) {
	if h.LeaderCampaignInterval == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(h.LeaderCampaignInterval)
	if err != nil {
		return 0, fmt.Errorf("ha.leader_campaign_interval %q: %w", h.LeaderCampaignInterval, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("ha.leader_campaign_interval must be positive, got %q", h.LeaderCampaignInterval)
	}
	return d, nil
}

// Plugins configures the served WASM-plugin surface (EXC-WIRE-05, closing
// ARCH-007/SUPPLY-004): the running control plane loads operator-supplied
// connector plugins from a directory and runs them capability-sandboxed through
// the wazero plugin host. It is OFF by default (Enabled=false): a connector.deploy
// is acknowledged unrouted, exactly as before. When Enabled, a plugin is admitted
// ONLY after its detached Ed25519 signature verifies against TrustedKeyFiles
// (SUPPLY-004); an unsigned, wrong-key, tampered, or unpinned module makes the
// binary fail closed at startup — it never serves an unverified plugin.
type Plugins struct {
	// Enabled turns on the served plugin surface. Off by default.
	Enabled bool `json:"enabled,omitempty"`
	// Dir is the directory scanned for `<name>.wasm` + detached `<name>.wasm.sig`
	// pairs. Required when Enabled.
	Dir string `json:"dir,omitempty"`
	// TrustedKeyFiles are paths to PEM Ed25519 public keys that admit a signed
	// module (SUPPLY-004). At least one is required when Enabled.
	TrustedKeyFiles []string `json:"trusted_key_files,omitempty"`
	// PinnedDigests optionally restricts admitted modules to an exact-content
	// allowlist (lowercase-hex SHA-256 of the `.wasm`).
	PinnedDigests []string `json:"pinned_digests,omitempty"`
	// Capabilities are the capability names every loaded connector plugin runs
	// under (a subset of fs.read, fs.write, net.dial, process.exec). Empty grants
	// nothing privileged — operators widen it deliberately. A plugin can never
	// exceed this grant at runtime.
	Capabilities []string `json:"capabilities,omitempty"`
	// PathPrefixes constrains fs.read / fs.write to resources under these prefixes
	// (defense-in-depth alongside the capability grant). Empty means the granted
	// filesystem capability is unconstrained by prefix.
	PathPrefixes []string `json:"path_prefixes,omitempty"`
}

// Auth configures interactive authentication for the served control plane. Today
// it carries the OIDC browser-login + session bridge (EXC-WIRE-01); scoped API
// tokens always authenticate the binary regardless of this block.
type Auth struct {
	OIDC OIDC `json:"oidc"`
}

// OIDC configures the served browser single-sign-on flow (EXC-WIRE-01, closing
// SEC-001/WIRE-001/SURFACE-002/TENANT-004): the authorization-code login, id_token
// verification (signature/issuer/audience/nonce/exp/nbf/iat via the AN-3 JOSE
// boundary), the HttpOnly+SameSite session cookie, and per-user → tenant mapping.
// It is OFF by default; when Enabled the served binary mounts /auth/login,
// /auth/callback, /auth/me, /auth/logout, and a session cookie authorizes API calls
// under the SAME RBAC + tenant scoping (RLS, AN-1) as an API token. A misconfigured
// enabled block fails closed at startup (Validate), so the binary never serves a
// half-wired login.
type OIDC struct {
	// Enabled mounts the served OIDC login on the running binary. Off by default
	// (only scoped API tokens authenticate until an operator turns SSO on).
	Enabled bool `json:"enabled,omitempty"`
	// Issuer is the IdP's issuer identifier (the `iss` claim it stamps). Required.
	Issuer string `json:"issuer,omitempty"`
	// ClientID is trustctl's registered OAuth client id (the expected `aud`). Required.
	ClientID string `json:"client_id,omitempty"`
	// ClientSecret authenticates the code→token exchange at the token endpoint.
	// Confidential clients require it; a public/PKCE client may leave it empty.
	ClientSecret string `json:"client_secret,omitempty"`
	// AuthEndpoint is the IdP authorization endpoint the browser is redirected to.
	// Required.
	AuthEndpoint string `json:"auth_endpoint,omitempty"`
	// TokenEndpoint is the IdP token endpoint the callback exchanges the code at.
	// Required.
	TokenEndpoint string `json:"token_endpoint,omitempty"`
	// RedirectURI is this server's /auth/callback URL, registered with the IdP.
	// Required.
	RedirectURI string `json:"redirect_uri,omitempty"`
	// JWKSFile is a path to the IdP's JWKS document (its signing public keys). One of
	// JWKSFile / JWKSJSON is required so id_token signatures verify offline (no
	// network fetch on the hot path).
	JWKSFile string `json:"jwks_file,omitempty"`
	// JWKSJSON is the IdP's JWKS document inline (an alternative to JWKSFile).
	JWKSJSON string `json:"jwks_json,omitempty"`
	// SessionSecretFile persists the HMAC secret that signs session cookies, so a
	// restart does not invalidate live sessions. Created (0600) on first boot if
	// absent. Required when Enabled (a process-random secret would log users out on
	// every restart and could not be shared across HA replicas).
	SessionSecretFile string `json:"session_secret_file,omitempty"`
	// SessionTTL is the lifetime of a session cookie (a Go duration). Empty defaults
	// to 12h.
	SessionTTL string `json:"session_ttl,omitempty"`
	// LoginRedirect is where the browser lands after a successful login. Empty -> "/".
	LoginRedirect string `json:"login_redirect,omitempty"`

	// --- Per-user → tenant mapping (TENANT-004 / RED-004) ---

	// TenantClaim names the id_token claim whose value identifies the user's tenant
	// (e.g. "tenant", "org_id"). Read out of the verified token at login.
	TenantClaim string `json:"tenant_claim,omitempty"`
	// GroupsClaim names the id_token claim carrying the user's group memberships, for
	// an IdP-group → tenant/role mapping. Optional.
	GroupsClaim string `json:"groups_claim,omitempty"`
	// ClaimIsTenant, when true, uses the TenantClaim value directly as the trustctl
	// tenant id (the IdP stamps the real tenant id into the token). Otherwise the
	// claim is matched against TenantMappings.
	ClaimIsTenant bool `json:"claim_is_tenant,omitempty"`
	// TenantMappings is the table that binds a subject / tenant-claim value / IdP
	// group to a tenant and the RBAC roles the session receives.
	TenantMappings []TenantMapping `json:"tenant_mappings,omitempty"`
	// DefaultRoles are the RBAC roles a session receives when its mapping names none.
	DefaultRoles []string `json:"default_roles,omitempty"`
	// DefaultTenant is the LEGACY single-tenant fallback for an unmapped user, applied
	// ONLY when AllowDefaultTenant is true. With AllowDefaultTenant false (the
	// multi-tenant posture) an unmapped login fails closed instead of leaking into a
	// default tenant.
	DefaultTenant string `json:"default_tenant,omitempty"`
	// AllowDefaultTenant opts into the DefaultTenant fallback. Off by default so a
	// multi-tenant deployment that forgets a mapping rejects the login rather than
	// silently mis-attributing the user.
	AllowDefaultTenant bool `json:"allow_default_tenant,omitempty"`
}

// TenantMapping binds an OIDC user (by subject, by tenant-claim value, or by IdP
// group) to a tenant and the roles its session receives (the config mirror of
// auth.TenantMapping).
type TenantMapping struct {
	Subject  string   `json:"subject,omitempty"`
	Claim    string   `json:"claim,omitempty"`
	Group    string   `json:"group,omitempty"`
	TenantID string   `json:"tenant_id"`
	Roles    []string `json:"roles,omitempty"`
}

// ValidateEnabled reports the configuration problems of the OIDC block as if it
// were enabled, joined into a single error (nil when fully configured). It lets the
// server composition re-check the block at Build time so Build is safe to call
// directly with an enabled-but-misconfigured OIDC block (fail closed) even when the
// caller skipped Config.Validate. It is the same gate Validate applies.
func (o OIDC) ValidateEnabled() error { return errors.Join(o.validate()...) }

// SessionTTLDuration parses the session cookie lifetime, defaulting to 12h when
// empty.
func (o OIDC) SessionTTLDuration() (time.Duration, error) {
	if strings.TrimSpace(o.SessionTTL) == "" {
		return 12 * time.Hour, nil
	}
	return time.ParseDuration(o.SessionTTL)
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
	// EnableAPI turns on the served secrets/identity surface (GAP-006): the secret
	// store (CRUD + rotation), one-time secret sharing, the dynamic PKI secret, and
	// machine login under /api/v1/secrets/*. OFF by default (fail closed): an upgrade
	// does not silently expose a secrets surface. When on, the served secret store
	// seals values under the KEK above (envelope encryption at rest, AN-8); every route
	// is auth-gated, tenant-scoped under RLS (AN-1), idempotent (AN-5), and
	// event-sourced (AN-2).
	EnableAPI bool `json:"enable_api,omitempty"`
	// AuthSecretFile is the path to the HMAC key the served machine-login token method
	// verifies a workload token against (authmethod/F58). When set (and EnableAPI is
	// on) the login route accepts the "token" method; when unset, the login route
	// reports the method is not configured while the secret store / share / pki
	// sub-features still work. Like the KEK, it is created (random, 0600) on first boot
	// if absent. The key is held as []byte and never logged (AN-8).
	AuthSecretFile string `json:"auth_secret_file,omitempty"`
}

// AI configures the served AI / RCA / NL-query / MCP surface (SURFACE-003; F75/F76/
// F77/F78) under /api/v1/ai/* and /api/v1/mcp/*. It is OFF by default (fail closed): an
// upgrade does not silently expose an AI surface. When on, the surface is READ-ONLY (no
// write/remediation tools), tenant-scoped under RLS (the tenant is the authenticated
// principal's, never a request field — AN-1), auth-gated, and rate-limited. The AI
// MODEL is AIR-GAPPED / OPT-IN by product posture: with no model configured (the
// default) grounding + citations still work and nothing phones home; when a model is
// configured the boundary redactor + residual-entropy refuse-gate sit between any
// prompt and the model (AN-8).
type AI struct {
	// EnableAPI turns on the served AI/RCA/MCP surface. OFF by default (fail closed).
	EnableAPI bool `json:"enable_api,omitempty"`
	// MCPIdentity is the workload identity the served MCP server presents (dogfooding
	// the F61 broker). Informational; empty is fine.
	MCPIdentity string `json:"mcp_identity,omitempty"`
	// RateMax bounds the per-(caller,tool) MCP call count per RateWindow
	// (enumeration-abuse protection). Zero selects a conservative default.
	RateMax int `json:"rate_max,omitempty"`
	// RateWindowSeconds is the MCP rate-limit window in seconds. Zero selects one
	// minute.
	RateWindowSeconds int `json:"rate_window_seconds,omitempty"`
}

// RateWindow returns the MCP rate-limit window, defaulting to one minute.
func (a AI) RateWindow() time.Duration {
	if a.RateWindowSeconds <= 0 {
		return time.Minute
	}
	return time.Duration(a.RateWindowSeconds) * time.Second
}

// Signer configures the out-of-process signing service (AN-4 / R3.2). In "child"
// mode the control plane supervises trustctl-signer as a child process (single
// binary); in "external" mode it connects to a separately deployed signer over
// either a co-located UDS (Socket) or — across nodes — a mutually-authenticated
// mTLS channel (MTLSAddress + the mTLS material, SIGNER-005). KeyStoreDir is where
// the signer seals its keys at rest so a restart preserves the issuing CA rather
// than rotating it; the keys are sealed with the same KEK as credentials
// (Secrets.KEKFile).
type Signer struct {
	Mode        string `json:"mode"`          // "child" (default) or "external"
	Socket      string `json:"socket"`        // UDS path; in external mode use this OR the mTLS fields
	KeyStoreDir string `json:"key_store_dir"` // sealed key persistence directory

	// Cross-node mTLS transport for an external signer (SIGNER-005 / design §3,§5.2).
	// When MTLSAddress is set in external mode the control plane dials the signer
	// over TLS 1.3 mutual auth, presenting MTLSCertFile/MTLSKeyFile, verifying the
	// signer against MTLSPeerCAFile, and PINNING the signer's key (MTLSPeerPin). It
	// is the cross-host alternative to a shared Socket; exactly one of Socket or
	// MTLSAddress must be set in external mode, and a partial mTLS block fails
	// closed at startup. MTLSServerName is the signer certificate's expected SAN.
	MTLSAddress    string `json:"mtls_address,omitempty"`      // host:port of the signer's mTLS listener
	MTLSServerName string `json:"mtls_server_name,omitempty"`  // expected SAN on the signer certificate
	MTLSCertFile   string `json:"mtls_cert_file,omitempty"`    // control-plane client certificate (PEM)
	MTLSKeyFile    string `json:"mtls_key_file,omitempty"`     // control-plane client key (PEM)
	MTLSPeerCAFile string `json:"mtls_peer_ca_file,omitempty"` // CA bundle anchoring the signer certificate (PEM)
	MTLSPeerPin    string `json:"mtls_peer_pin,omitempty"`     // hex SHA-256 of the signer certificate's public key
}

const (
	// SignerChild supervises trustctl-signer as a child process (single binary).
	SignerChild = "child"
	// SignerExternal connects to a separately deployed signer over a UDS (Socket)
	// or, across nodes, an mTLS channel (MTLSAddress, SIGNER-005).
	SignerExternal = "external"
)

// MTLSEnabled reports whether the external signer is reached over the cross-node
// mTLS channel rather than a co-located UDS.
func (s Signer) MTLSEnabled() bool { return s.MTLSAddress != "" }

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
	setBool(getenv, "TRUSTCTL_SECRETS_ENABLE_API", &c.Secrets.EnableAPI)
	setString(getenv, "TRUSTCTL_SECRETS_AUTH_SECRET_FILE", &c.Secrets.AuthSecretFile)
	// Served AI / RCA / NL-query / MCP surface (SURFACE-003). OFF by default (fail
	// closed). The AI model stays air-gapped/opt-in regardless of these flags.
	setBool(getenv, "TRUSTCTL_AI_ENABLE_API", &c.AI.EnableAPI)
	setString(getenv, "TRUSTCTL_AI_MCP_IDENTITY", &c.AI.MCPIdentity)
	setInt(getenv, "TRUSTCTL_AI_RATE_MAX", &c.AI.RateMax)
	setInt(getenv, "TRUSTCTL_AI_RATE_WINDOW_SECONDS", &c.AI.RateWindowSeconds)
	setString(getenv, "TRUSTCTL_SIGNER_MODE", &c.Signer.Mode)
	setString(getenv, "TRUSTCTL_SIGNER_SOCKET", &c.Signer.Socket)
	setString(getenv, "TRUSTCTL_SIGNER_KEY_STORE_DIR", &c.Signer.KeyStoreDir)
	setString(getenv, "TRUSTCTL_SIGNER_MTLS_ADDRESS", &c.Signer.MTLSAddress)
	setString(getenv, "TRUSTCTL_SIGNER_MTLS_SERVER_NAME", &c.Signer.MTLSServerName)
	setString(getenv, "TRUSTCTL_SIGNER_MTLS_CERT_FILE", &c.Signer.MTLSCertFile)
	setString(getenv, "TRUSTCTL_SIGNER_MTLS_KEY_FILE", &c.Signer.MTLSKeyFile)
	setString(getenv, "TRUSTCTL_SIGNER_MTLS_PEER_CA_FILE", &c.Signer.MTLSPeerCAFile)
	setString(getenv, "TRUSTCTL_SIGNER_MTLS_PEER_PIN", &c.Signer.MTLSPeerPin)
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
	// Served OIDC browser login + session + per-user tenant mapping (EXC-WIRE-01).
	// The structured TenantMappings table is file-only (it is a list of objects); the
	// scalar knobs overlay from the environment like the rest of the config.
	setBool(getenv, "TRUSTCTL_AUTH_OIDC_ENABLED", &c.Auth.OIDC.Enabled)
	setString(getenv, "TRUSTCTL_AUTH_OIDC_ISSUER", &c.Auth.OIDC.Issuer)
	setString(getenv, "TRUSTCTL_AUTH_OIDC_CLIENT_ID", &c.Auth.OIDC.ClientID)
	setString(getenv, "TRUSTCTL_AUTH_OIDC_CLIENT_SECRET", &c.Auth.OIDC.ClientSecret)
	setString(getenv, "TRUSTCTL_AUTH_OIDC_AUTH_ENDPOINT", &c.Auth.OIDC.AuthEndpoint)
	setString(getenv, "TRUSTCTL_AUTH_OIDC_TOKEN_ENDPOINT", &c.Auth.OIDC.TokenEndpoint)
	setString(getenv, "TRUSTCTL_AUTH_OIDC_REDIRECT_URI", &c.Auth.OIDC.RedirectURI)
	setString(getenv, "TRUSTCTL_AUTH_OIDC_JWKS_FILE", &c.Auth.OIDC.JWKSFile)
	setString(getenv, "TRUSTCTL_AUTH_OIDC_JWKS_JSON", &c.Auth.OIDC.JWKSJSON)
	setString(getenv, "TRUSTCTL_AUTH_OIDC_SESSION_SECRET_FILE", &c.Auth.OIDC.SessionSecretFile)
	setString(getenv, "TRUSTCTL_AUTH_OIDC_SESSION_TTL", &c.Auth.OIDC.SessionTTL)
	setString(getenv, "TRUSTCTL_AUTH_OIDC_LOGIN_REDIRECT", &c.Auth.OIDC.LoginRedirect)
	setString(getenv, "TRUSTCTL_AUTH_OIDC_TENANT_CLAIM", &c.Auth.OIDC.TenantClaim)
	setString(getenv, "TRUSTCTL_AUTH_OIDC_GROUPS_CLAIM", &c.Auth.OIDC.GroupsClaim)
	setBool(getenv, "TRUSTCTL_AUTH_OIDC_CLAIM_IS_TENANT", &c.Auth.OIDC.ClaimIsTenant)
	setString(getenv, "TRUSTCTL_AUTH_OIDC_DEFAULT_TENANT", &c.Auth.OIDC.DefaultTenant)
	setBool(getenv, "TRUSTCTL_AUTH_OIDC_ALLOW_DEFAULT_TENANT", &c.Auth.OIDC.AllowDefaultTenant)
	setCSV(getenv, "TRUSTCTL_AUTH_OIDC_DEFAULT_ROLES", &c.Auth.OIDC.DefaultRoles)
	// Served WASM-plugin surface (EXC-WIRE-05; ARCH-007/SUPPLY-004). Off by default;
	// when enabled the binary loads + provenance-verifies connector plugins from the
	// directory against the trusted keys, failing closed on an unverified module.
	setBool(getenv, "TRUSTCTL_PLUGINS_ENABLED", &c.Plugins.Enabled)
	setString(getenv, "TRUSTCTL_PLUGINS_DIR", &c.Plugins.Dir)
	setCSV(getenv, "TRUSTCTL_PLUGINS_TRUSTED_KEY_FILES", &c.Plugins.TrustedKeyFiles)
	setCSV(getenv, "TRUSTCTL_PLUGINS_PINNED_DIGESTS", &c.Plugins.PinnedDigests)
	setCSV(getenv, "TRUSTCTL_PLUGINS_CAPABILITIES", &c.Plugins.Capabilities)
	setCSV(getenv, "TRUSTCTL_PLUGINS_PATH_PREFIXES", &c.Plugins.PathPrefixes)
	// Multi-replica HA (RESIL-002 / RESIL-004 / SPINE-007). Leader election defaults
	// ON (safe on a single replica, required for multi-replica); an operator can turn
	// it off explicitly. Snapshot/campaign intervals tune the SPINE-007 accelerator and
	// failover cadence.
	setBoolPtr(getenv, "TRUSTCTL_HA_LEADER_ELECTION", &c.HA.LeaderElection)
	setString(getenv, "TRUSTCTL_HA_LEADER_CAMPAIGN_INTERVAL", &c.HA.LeaderCampaignInterval)
	setString(getenv, "TRUSTCTL_HA_SNAPSHOT_INTERVAL", &c.HA.SnapshotInterval)
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

// setBoolPtr overlays a boolean environment variable onto a *bool, allocating the
// pointer on first set (RESIL-004 leader-election toggle). A nil/unset pointer means
// "use the default"; an explicit env value materializes it to true or false. A
// malformed value is ignored (the prior value stands), like setBool.
func setBoolPtr(getenv func(string) string, key string, dst **bool) {
	if v := getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			*dst = &b
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
	// The signer runs as a supervised child or connects to an external service. An
	// external signer is reached over EITHER a co-located UDS (signer.socket) OR a
	// cross-node mTLS channel (signer.mtls_address + the mTLS material, SIGNER-005);
	// exactly one must be configured, and a partial mTLS block fails closed here so
	// the binary never serves issuance against a half-configured signer transport.
	switch c.Signer.Mode {
	case SignerChild:
		// ok — single-binary supervises the child
	case SignerExternal:
		switch {
		case c.Signer.Socket != "" && c.Signer.MTLSEnabled():
			errs = append(errs, errors.New("signer.socket and signer.mtls_address are mutually exclusive (the signer has one listener)"))
		case c.Signer.MTLSEnabled():
			var miss []string
			if c.Signer.MTLSCertFile == "" {
				miss = append(miss, "signer.mtls_cert_file")
			}
			if c.Signer.MTLSKeyFile == "" {
				miss = append(miss, "signer.mtls_key_file")
			}
			if c.Signer.MTLSPeerCAFile == "" {
				miss = append(miss, "signer.mtls_peer_ca_file")
			}
			if c.Signer.MTLSPeerPin == "" {
				miss = append(miss, "signer.mtls_peer_pin")
			}
			if c.Signer.MTLSServerName == "" {
				miss = append(miss, "signer.mtls_server_name")
			}
			if len(miss) > 0 {
				errs = append(errs, fmt.Errorf("signer.mtls_address is set but the mTLS material is incomplete; also set %v", miss))
			}
		case c.Signer.Socket == "":
			errs = append(errs, errors.New("signer.socket or signer.mtls_address is required when signer.mode is external"))
		}
	default:
		errs = append(errs, fmt.Errorf("signer.mode %q is invalid (want %q or %q)", c.Signer.Mode, SignerChild, SignerExternal))
	}
	// Served OIDC login (EXC-WIRE-01): when enabled it must be FULLY configured, so
	// the binary never serves a half-wired login (fail closed). When disabled the
	// block is ignored.
	if c.Auth.OIDC.Enabled {
		errs = append(errs, c.Auth.OIDC.validate()...)
	}
	// Served plugin surface (EXC-WIRE-05; ARCH-007/SUPPLY-004): when enabled it must
	// name a directory and at least one trusted key, so the binary never serves an
	// unverifiable plugin path (fail closed). When disabled the block is ignored.
	if c.Plugins.Enabled {
		errs = append(errs, c.Plugins.validate()...)
	}
	// Multi-replica HA (RESIL-004 / SPINE-007): the durations must parse, so a typo in
	// the snapshot or campaign cadence fails fast at startup rather than silently
	// falling back to a default or busy-looping.
	if _, err := c.HA.SnapshotIntervalDuration(); err != nil {
		errs = append(errs, err)
	}
	if _, err := c.HA.LeaderCampaignIntervalDuration(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// validate reports the configuration problems of an enabled plugin surface. It is
// the fail-closed gate (SUPPLY-004): with no directory there is nothing to load,
// and with no trusted key a module could not be provenance-verified — both are
// hard startup errors rather than a silently unverified plugin path. Unknown
// capability names are rejected so a typo cannot silently grant nothing (or, in a
// future vocabulary, the wrong thing).
func (p Plugins) validate() []error {
	var errs []error
	if strings.TrimSpace(p.Dir) == "" {
		errs = append(errs, errors.New("plugins.dir is required when plugins.enabled is true"))
	}
	if len(p.TrustedKeyFiles) == 0 {
		errs = append(errs, errors.New("plugins.trusted_key_files requires at least one Ed25519 public key when plugins.enabled is true (SUPPLY-004: a plugin must be provenance-verified)"))
	}
	known := map[string]bool{"fs.read": true, "fs.write": true, "net.dial": true, "process.exec": true}
	for _, c := range p.Capabilities {
		if !known[strings.TrimSpace(c)] {
			errs = append(errs, fmt.Errorf("plugins.capabilities entry %q is not a known capability (want fs.read, fs.write, net.dial, or process.exec)", c))
		}
	}
	return errs
}

// isLoopbackHost reports whether host is a loopback hostname/IP (127.0.0.0/8, ::1,
// or "localhost"), for the OIDC endpoint http exemption (RFC 8252).
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// validate reports the configuration problems of an enabled OIDC block. It is the
// fail-closed gate: a missing endpoint, missing client id/issuer, no signing keys,
// no session secret, or no way to resolve a tenant is a hard startup error rather
// than a silently degraded login.
func (o OIDC) validate() []error {
	var errs []error
	req := func(v, name string) {
		if strings.TrimSpace(v) == "" {
			errs = append(errs, fmt.Errorf("auth.oidc.%s is required when auth.oidc.enabled is true", name))
		}
	}
	req(o.Issuer, "issuer")
	req(o.ClientID, "client_id")
	req(o.AuthEndpoint, "auth_endpoint")
	req(o.TokenEndpoint, "token_endpoint")
	req(o.RedirectURI, "redirect_uri")
	req(o.SessionSecretFile, "session_secret_file")
	if strings.TrimSpace(o.JWKSFile) == "" && strings.TrimSpace(o.JWKSJSON) == "" {
		errs = append(errs, errors.New("auth.oidc requires jwks_file or jwks_json (the IdP signing keys) when enabled"))
	}
	// Endpoints must be absolute https URLs (an http IdP endpoint would carry the
	// authorization code / token in the clear). A loopback host (127.0.0.1/::1/
	// localhost) is exempted from the https requirement — the IETF native-app BCP
	// (RFC 8252) treats loopback as a safe, non-network transport, which is also what
	// makes a local mock IdP and a `kind`/dev IdP usable.
	for _, e := range []struct{ v, name string }{
		{o.AuthEndpoint, "auth_endpoint"}, {o.TokenEndpoint, "token_endpoint"}, {o.RedirectURI, "redirect_uri"},
	} {
		if strings.TrimSpace(e.v) == "" {
			continue
		}
		u, err := url.Parse(e.v)
		if err != nil || u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackHost(u.Hostname()))) {
			errs = append(errs, fmt.Errorf("auth.oidc.%s %q must be an absolute https URL (http is allowed only for a loopback host)", e.name, e.v))
		}
	}
	if d, err := o.SessionTTLDuration(); err != nil {
		errs = append(errs, fmt.Errorf("auth.oidc.session_ttl %q is invalid: %w", o.SessionTTL, err))
	} else if d <= 0 {
		errs = append(errs, errors.New("auth.oidc.session_ttl must be positive"))
	}
	// There must be SOME way to resolve a tenant, otherwise every login fails closed
	// (TENANT-004): a tenant claim, a mappings table, or an explicit allowed default.
	hasMapping := len(o.TenantMappings) > 0 || strings.TrimSpace(o.TenantClaim) != "" || (o.AllowDefaultTenant && strings.TrimSpace(o.DefaultTenant) != "")
	if !hasMapping {
		errs = append(errs, errors.New("auth.oidc needs a tenant mapping when enabled: set tenant_claim, tenant_mappings, or allow_default_tenant+default_tenant — otherwise every login fails closed"))
	}
	for i, m := range o.TenantMappings {
		keys := 0
		for _, k := range []string{m.Subject, m.Claim, m.Group} {
			if strings.TrimSpace(k) != "" {
				keys++
			}
		}
		if keys != 1 {
			errs = append(errs, fmt.Errorf("auth.oidc.tenant_mappings[%d] must set exactly one of subject/claim/group", i))
		}
		if strings.TrimSpace(m.TenantID) == "" {
			errs = append(errs, fmt.Errorf("auth.oidc.tenant_mappings[%d].tenant_id is required", i))
		}
	}
	return errs
}

func validLevel(level string) bool {
	switch level {
	case "debug", "info", "warn", "error":
		return true
	default:
		return false
	}
}
