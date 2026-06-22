// Package config loads, merges, and validates trstctl's configuration from a
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

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/crypto"
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
	// DefaultEmbeddedSyncInterval is the embedded JetStream fsync cadence trstctl
	// applies when NATS.SyncInterval is unset (RESIL-001). nats-server's own default
	// is ~2 minutes; trstctl tightens it to one second so a single-node power loss
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
	// trust the trstctl-generated CA (suitable for evaluation / internal use).
	TLSInternal = "internal"
	// TLSFile serves TLS with an operator-provided certificate and key (PEM).
	TLSFile = "file"
	// TLSDisabled serves plaintext HTTP. It is for local development only and is
	// loudly warned: credentials and sessions travel in the clear.
	TLSDisabled = "disabled"
)

// AI model serving modes. The default is "off": the AI/RCA/MCP surface can still
// answer from grounded citations, but no prompt leaves the process.
const (
	AIModelOff   = "off"
	AIModelLocal = "local"
	AIModelCloud = "cloud"

	AIModelRuntimeOllama = "ollama"
	AIModelRuntimeVLLM   = "vllm"
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
	Privacy   Privacy   `json:"privacy"`
	Backup    Backup    `json:"backup"`
	RateLimit RateLimit `json:"rate_limit"`
	Bulkheads Bulkheads `json:"bulkheads"`
	Migrate   Migrate   `json:"migrate"`
	Secrets   Secrets   `json:"secrets"`
	Signer    Signer    `json:"signer"`
	CA        CA        `json:"ca"`
	Protocols Protocols `json:"protocols"`
	Auth      Auth      `json:"auth"`
	Plugins   Plugins   `json:"plugins"`
	HA        HA        `json:"ha"`
	AI        AI        `json:"ai"`
	// AgentChannel configures the served agent steady-state mTLS gRPC channel
	// (WIRE-004 / OPS-005). Off by default.
	AgentChannel AgentChannel `json:"agent_channel"`
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
	// ClientID is trstctl's registered OAuth client id (the expected `aud`). Required.
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
	// ClaimIsTenant, when true, uses the TenantClaim value directly as the trstctl
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
// Each enrollment protocol server (ACME, EST, SCEP, CMP, SPIFFE Workload API, SSH
// CA) is library-complete and, when enabled, mounted on the running control plane
// behind the same orchestrator-backed, signer-backed, tenant-scoped, profile-gated
// issuance path the API mint uses (AN-1..AN-5). TSA is also mounted here as an
// opt-in tenant-bound protocol surface: it issues RFC 3161 timestamp evidence through
// a signer-held timestamping key and audit sink rather than minting inventory
// certificates. A protocol is served only when its issuing CA is provisioned (a
// signer is configured); with no signer the routes fail closed.
//
// Posture: every served protocol surface is opt-in until the operator binds it to a
// tenant. The product speaks stock ACME/EST/SCEP/CMP/SPIFFE/SSH/TSA clients, but it
// must never expose a public endpoint that later discovers it has no tenant to mint
// into or issue evidence under (AN-1).
type Protocols struct {
	ACME ProtocolToggle `json:"acme"`
	EST  ProtocolToggle `json:"est"`
	SCEP ProtocolToggle `json:"scep"`
	CMP  ProtocolToggle `json:"cmp"`
	TSA  ProtocolToggle `json:"tsa"`
	// ACMEQuota caps public ACME state retained by the in-process protocol view.
	// It complements the protocol bulkhead: the bulkhead limits concurrent work,
	// while these caps bound total nonce/account/order/authz/challenge state.
	ACMEQuota ACMEQuota `json:"acme_quota,omitempty"`
	// RAKeyFile is the sealed-at-rest RSA transport identity SCEP/CMP use for CMS
	// request decryption and response protection. It is not the issuing CA key, but
	// it must survive restarts and be shared by replicas so clients that cached
	// GetCACert material can keep enrolling during rolling deploys.
	RAKeyFile   string         `json:"ra_key_file,omitempty"`
	TSACertFile string         `json:"tsa_cert_file,omitempty"`
	SPIFFE      SPIFFEProtocol `json:"spiffe"`
	SSH         ProtocolToggle `json:"ssh"`
}

// ProtocolToggle enables a served protocol endpoint and binds it to a tenant. The
// served protocol endpoints are single-tenant by mount (the binary serves one tenant
// per protocol path); a future per-vhost/per-path multi-tenant mount is tracked
// separately. TenantID empty is valid only when the server composition provides an
// explicit platform protocol tenant fallback; normal config-file startup requires
// this field for every enabled protocol.
type ProtocolToggle struct {
	Enabled  bool   `json:"enabled,omitempty"`
	TenantID string `json:"tenant_id,omitempty"`
}

// ACMEQuota bounds the public ACME protocol surface. Durability is handled by the
// event/projection backlog; these numbers are the abuse-budget fence for the
// memory-resident protocol view.
type ACMEQuota struct {
	MaxNonces                  int `json:"max_nonces,omitempty"`
	MaxAccounts                int `json:"max_accounts,omitempty"`
	MaxPendingOrders           int `json:"max_pending_orders,omitempty"`
	MaxPendingAuthorizations   int `json:"max_pending_authorizations,omitempty"`
	MaxPendingChallenges       int `json:"max_pending_challenges,omitempty"`
	MaxPendingOrdersPerAccount int `json:"max_pending_orders_per_account,omitempty"`
	MaxNewNoncesPerSource      int `json:"max_new_nonces_per_source,omitempty"`
	MaxNewAccountsPerSource    int `json:"max_new_accounts_per_source,omitempty"`
	MaxNewOrdersPerSource      int `json:"max_new_orders_per_source,omitempty"`
	SourceWindowSeconds        int `json:"source_window_seconds,omitempty"`
	NonceTTLSeconds            int `json:"nonce_ttl_seconds,omitempty"`
	StateTTLSeconds            int `json:"state_ttl_seconds,omitempty"`
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

// ValidateTenantBindings reports AN-1 configuration errors for enabled served
// protocols. defaultTenant is only for an explicit server composition fallback
// (tests/embeds/single-tenant wrappers); the config file path passes "" so every
// enabled protocol must name protocols.<name>.tenant_id directly.
func (p Protocols) ValidateTenantBindings(defaultTenant string) []error {
	var errs []error
	hasTenant := func(tenant string) bool {
		return strings.TrimSpace(tenant) != "" || strings.TrimSpace(defaultTenant) != ""
	}
	requireTenant := func(name string, enabled bool, tenant string) {
		if enabled && !hasTenant(tenant) {
			errs = append(errs, fmt.Errorf("protocols.%s.tenant_id is required when protocols.%s.enabled is true (AN-1: served enrollment must bind to a tenant)", name, name))
		}
	}
	requireTenant("acme", p.ACME.Enabled, p.ACME.TenantID)
	requireTenant("est", p.EST.Enabled, p.EST.TenantID)
	requireTenant("scep", p.SCEP.Enabled, p.SCEP.TenantID)
	requireTenant("cmp", p.CMP.Enabled, p.CMP.TenantID)
	requireTenant("tsa", p.TSA.Enabled, p.TSA.TenantID)
	requireTenant("ssh", p.SSH.Enabled, p.SSH.TenantID)
	if (p.SCEP.Enabled || p.CMP.Enabled) && strings.TrimSpace(p.RAKeyFile) == "" {
		errs = append(errs, errors.New("protocols.ra_key_file is required when SCEP or CMP is enabled so the RA transport identity survives restart/replicas"))
	}
	if p.TSA.Enabled && strings.TrimSpace(p.TSACertFile) == "" {
		errs = append(errs, errors.New("protocols.tsa_cert_file is required when TSA is enabled so the timestamping certificate stays stable across restart/replicas"))
	}
	if p.SPIFFE.Enabled {
		requireTenant("spiffe", true, p.SPIFFE.TenantID)
		if strings.TrimSpace(p.SPIFFE.TrustDomain) == "" {
			errs = append(errs, errors.New("protocols.spiffe.trust_domain is required when protocols.spiffe.enabled is true"))
		}
	}
	return errs
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
	Mode              string `json:"mode"`
	CertFile          string `json:"cert_file"` // required when mode is file
	KeyFile           string `json:"key_file"`  // required when mode is file
	AllowPlaintextDev bool   `json:"allow_plaintext_dev,omitempty"`
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

	// AllowSingleReplica explicitly permits external JetStream with one replica
	// (RESIL-004). This is an evaluation/dev escape hatch only: production external
	// mode defaults to three replicas and fails closed if the server cannot honor the
	// requested durability. A single-replica external stream gives no HA/RPO
	// protection beyond the one NATS node; require this flag so a production cluster
	// cannot silently degrade to eval durability.
	AllowSingleReplica bool `json:"allow_single_replica,omitempty"`

	// SyncInterval bounds how often the embedded, file-backed JetStream flushes the
	// stream to stable storage (fsync), i.e. the single-node durability/RPO window
	// (RESIL-001). nats-server defaults this to ~2 minutes, so out of the box a
	// Publish ACK is a page-cache write and a power loss within the window can lose
	// up to ~2 minutes of acked events from the source-of-truth log. trstctl
	// tightens it to a short default (see DefaultEmbeddedSyncInterval); an operator
	// may shorten it further, or set SyncAlways for fsync-on-every-append. It only
	// affects embedded mode (an external cluster manages its own durability). A Go
	// duration string, e.g. "1s"; empty uses the trstctl default.
	SyncInterval string `json:"sync_interval"`

	// SyncAlways makes the embedded JetStream fsync the stream on every append
	// (O_SYNC) rather than on the interval, giving a near-zero single-node RPO at a
	// throughput cost (RESIL-001). It only affects embedded mode. Off by default;
	// the bounded SyncInterval already caps the loss window without the per-write
	// fsync penalty.
	SyncAlways bool `json:"sync_always"`
}

// SyncIntervalDuration parses the embedded JetStream fsync cadence (RESIL-001). An
// empty value means the trstctl embedded default (DefaultEmbeddedSyncInterval)
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

// Privacy configures personal-data controls outside the audit log.
type Privacy struct {
	Retention PrivacyRetention `json:"retention"`
}

// PrivacyRetention configures non-audit PII retention. Empty windows use the
// product's conservative class defaults; explicit values are Go durations.
type PrivacyRetention struct {
	Enabled      bool   `json:"enabled,omitempty"`
	Interval     string `json:"interval,omitempty"`
	Owners       string `json:"owners,omitempty"`
	Identities   string `json:"identities,omitempty"`
	Certificates string `json:"certificates,omitempty"`
	SSHKeys      string `json:"ssh_keys,omitempty"`
	Access       string `json:"access,omitempty"`
	Approvals    string `json:"approvals,omitempty"`
	Profiles     string `json:"profiles,omitempty"`
	Attestations string `json:"attestations,omitempty"`
	Agents       string `json:"agents,omitempty"`
}

// IntervalDuration parses the worker cadence. Empty means the server should use
// the privacy package default; disabled retention returns zero.
func (r PrivacyRetention) IntervalDuration() (time.Duration, error) {
	if !r.Enabled {
		return 0, nil
	}
	if r.Interval == "" {
		return 0, nil
	}
	return time.ParseDuration(r.Interval)
}

// Backup configures full disaster-recovery artifact handling. Event-log backups
// are already integrity-protected by the audit key; full backups additionally
// contain operational secrets (audit signing key, signer auth verifier, sealed
// signer keystore), so production backups require an operator-held encryption key.
// The key file is raw bytes (normally 32 random bytes) and is NOT copied into the
// backup set. AllowUnencrypted is a break-glass override for lab/export cases; it
// is recorded in the manifest so an auditor can see that the locked box was not
// used.
type Backup struct {
	EncryptionKeyFile string `json:"encryption_key_file,omitempty"`
	AllowUnencrypted  bool   `json:"allow_unencrypted,omitempty"`
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

// BulkheadLimit configures one bounded worker pool. Workers is the concurrent
// execution cap; Queue is the positive backlog depth before new work is rejected.
type BulkheadLimit struct {
	Workers int `json:"workers"`
	Queue   int `json:"queue"`
}

// Bulkheads configures the AN-7 worker pools that isolate subsystems from each
// other. Defaults match bulkhead.DefaultConfigs; operators tune these per fleet
// size without changing code.
type Bulkheads struct {
	API         BulkheadLimit `json:"api"`
	Projections BulkheadLimit `json:"projections"`
	Outbox      BulkheadLimit `json:"outbox"`
	Signing     BulkheadLimit `json:"signing"`
	Query       BulkheadLimit `json:"query"`
	Policy      BulkheadLimit `json:"policy"`
	Protocols   BulkheadLimit `json:"protocols"`
	Agent       BulkheadLimit `json:"agent"`
}

type bulkheadLimitItem struct {
	name  string
	limit BulkheadLimit
}

func defaultBulkheads() Bulkheads {
	var out Bulkheads
	for _, cfg := range bulkhead.DefaultConfigs() {
		limit := BulkheadLimit{Workers: cfg.Workers, Queue: cfg.Queue}
		switch cfg.Name {
		case bulkhead.SubsystemAPI:
			out.API = limit
		case bulkhead.SubsystemProjections:
			out.Projections = limit
		case bulkhead.SubsystemOutbox:
			out.Outbox = limit
		case bulkhead.SubsystemSigning:
			out.Signing = limit
		case bulkhead.SubsystemQuery:
			out.Query = limit
		case bulkhead.SubsystemPolicy:
			out.Policy = limit
		case bulkhead.SubsystemProtocols:
			out.Protocols = limit
		case bulkhead.SubsystemAgent:
			out.Agent = limit
		}
	}
	return out
}

func (b Bulkheads) items() []bulkheadLimitItem {
	return []bulkheadLimitItem{
		{name: bulkhead.SubsystemAPI, limit: b.API},
		{name: bulkhead.SubsystemProjections, limit: b.Projections},
		{name: bulkhead.SubsystemOutbox, limit: b.Outbox},
		{name: bulkhead.SubsystemSigning, limit: b.Signing},
		{name: bulkhead.SubsystemQuery, limit: b.Query},
		{name: bulkhead.SubsystemPolicy, limit: b.Policy},
		{name: bulkhead.SubsystemProtocols, limit: b.Protocols},
		{name: bulkhead.SubsystemAgent, limit: b.Agent},
	}
}

// Configs converts deployment config into concrete pool configs.
func (b Bulkheads) Configs() []bulkhead.Config {
	items := b.items()
	out := make([]bulkhead.Config, 0, len(items))
	for _, item := range items {
		out = append(out, bulkhead.Config{
			Name: item.name, Workers: item.limit.Workers, Queue: item.limit.Queue,
		})
	}
	return out
}

func (b Bulkheads) validate() []error {
	var errs []error
	for _, item := range b.items() {
		if item.limit.Workers <= 0 {
			errs = append(errs, fmt.Errorf("bulkheads.%s.workers must be positive", item.name))
		}
		if item.limit.Queue <= 0 {
			errs = append(errs, fmt.Errorf("bulkheads.%s.queue must be positive", item.name))
		}
	}
	return errs
}

// Migrate configures database schema migration at boot (R2.5). With Auto on
// (the default), the control plane applies any pending migrations on startup,
// serialized across instances by an advisory lock. With Auto off, a boot that
// finds pending migrations fails fast with guidance instead of migrating
// silently — the pre-migration backup gate: an operator inspects the plan
// (`trstctl --migrate-status`), takes a backup, then applies them explicitly
// (`trstctl --migrate`).
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
	// Model configures the optional reasoning model. Mode "off" is the default and
	// means no prompt egress. Mode "local" targets an operator-owned Ollama/vLLM
	// completion endpoint. Mode "cloud" requires AllowEgress=true so cloud prompt
	// egress is a deliberate, inspectable choice.
	Model AIModel `json:"model,omitempty"`
}

// AIModel configures the optional model adapter behind the served AI surface. It
// carries no credentials by design: secrets belong in operator-managed network
// controls or a future secret-backed auth mechanism, not in JSON/string config.
type AIModel struct {
	Mode        string `json:"mode,omitempty"`         // off | local | cloud
	Runtime     string `json:"runtime,omitempty"`      // local: ollama | vllm
	Provider    string `json:"provider,omitempty"`     // cloud: provider/gateway label
	Endpoint    string `json:"endpoint,omitempty"`     // completion endpoint; never echoed in full
	Name        string `json:"name,omitempty"`         // model name at the endpoint
	AllowEgress bool   `json:"allow_egress,omitempty"` // required only for cloud mode
	// AllowPII consents to sending personal/identifying data (emails, IPs,
	// OIDC/SPIFFE subjects, hostnames, person names) to the configured model
	// (PRIVACY-005). Default false is default-private: such data is redacted before
	// any prompt egress. Set true only after confirming the model provider's data
	// retention/use terms and that egress of subject data is permitted.
	AllowPII bool `json:"allow_pii,omitempty"`
	// BlockPII, when true and AllowPII is false, refuses any prompt that still
	// carries personal/identifying data after secret redaction rather than redacting
	// it in place. Use this for a strict fail-closed posture. Ignored when AllowPII
	// is true.
	BlockPII bool `json:"block_pii,omitempty"`
}

// RateWindow returns the MCP rate-limit window, defaulting to one minute.
func (a AI) RateWindow() time.Duration {
	if a.RateWindowSeconds <= 0 {
		return time.Minute
	}
	return time.Duration(a.RateWindowSeconds) * time.Second
}

// ModeValue normalizes the configured model mode. Empty means off, so old configs
// keep the air-gapped default.
func (m AIModel) ModeValue() string {
	mode := strings.ToLower(strings.TrimSpace(m.Mode))
	if mode == "" {
		return AIModelOff
	}
	return mode
}

// Signer configures the out-of-process signing service (AN-4 / R3.2). In "child"
// mode the control plane supervises trstctl-signer as a child process (single
// binary); in "external" mode it connects to a separately deployed signer over
// either a co-located UDS (Socket) or — across nodes — a mutually-authenticated
// mTLS channel (MTLSAddress + the mTLS material, SIGNER-005). KeyStoreDir is where
// the signer seals its keys at rest so a restart preserves the issuing CA rather
// than rotating it; the keys are sealed with the same KEK as credentials
// (Secrets.KEKFile).
type Signer struct {
	Mode           string `json:"mode"`             // "child" (default) or "external"
	Socket         string `json:"socket"`           // UDS path; in external mode use this OR the mTLS fields
	KeyStoreDir    string `json:"key_store_dir"`    // sealed key persistence directory
	AuthSecretFile string `json:"auth_secret_file"` // signer-side verifier secret path; do not expose to the control plane in production
	// AuthTokenCommand is an independent approval-token authority. The control
	// plane writes sign-intent JSON to stdin and reads a base64 token from stdout.
	AuthTokenCommand string `json:"auth_token_command,omitempty"`
	// AllowCoResidentAuthorizer is an evaluation-only escape hatch that lets the
	// control plane load AuthSecretFile and mint signer tokens locally. Production-
	// like external NATS deployments reject it.
	AllowCoResidentAuthorizer bool `json:"allow_co_resident_authorizer,omitempty"`
	// AllowInsecureDevNonLinux is a local-development-only escape hatch for
	// running child signer mode on non-Linux hosts. Without it, trstctl-signer
	// refuses unsupported hardening targets instead of silently dropping
	// core-dump/ptrace controls, UDS peer UID binding, and locked memory.
	AllowInsecureDevNonLinux bool `json:"allow_insecure_dev_nonlinux,omitempty"`

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
	// SignerChild supervises trstctl-signer as a child process (single binary).
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
	// default is a single private-enterprise policy OID identifying trstctl
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

	// GovernanceMode is the issuance-governance posture (PKIGOV-003). The empty value
	// (and "standard") leave the individual controls independent — each is enabled on
	// its own. "regulated" is the single coherent switch a compliance deployment sets:
	// it FAILS STARTUP unless ALL of the regulated controls are coherently present
	// together — the OPA policy gate, distinct-approver (four-eyes) dual control with a
	// bound approval threshold, a bound default certificate profile, revocation
	// publication (CRL DP and/or OCSP), and — when RequireFIPS is set — an active FIPS
	// 140-3 module. A deployment cannot half-enable a regulated posture and silently
	// drop a control.
	GovernanceMode string `json:"governance_mode,omitempty"`

	// RequireFIPS, in regulated mode, additionally requires the FIPS 140-3
	// cryptographic module to be active for this process (built with GOFIPS140 or run
	// with GODEBUG=fips140=on). When set and the module is inactive, startup fails
	// closed — the same posture as the --fips / TRSTCTL_FIPS assertion, declared in
	// the regulated config so the requirement travels with the deployment. Ignored
	// outside regulated mode.
	RequireFIPS bool `json:"require_fips,omitempty"`
}

// AgentChannel configures the served agent ↔ control-plane steady-state mTLS gRPC
// channel (WIRE-004 / OPS-005): the listener an enrolled agent connects to in order to
// heartbeat its inventory/status and renew its own client certificate. The AGENT CA
// (whose key is custodied in the signer, AN-4) anchors both the channel's server
// certificate and the agents' client certificates. The channel is tenant-scoped by the
// agent's verified certificate (AN-1), event-sourced (AN-2), idempotent (AN-5).
type AgentChannel struct {
	// Enabled mounts the served agent gRPC channel on Addr. OFF by default (fail
	// closed): the bootstrap path still mints agent certs, but there is no steady-state
	// listener until an operator opts in. Requires a signer (the agent CA is custodied
	// there) — enabling it without one is a startup error.
	Enabled bool `json:"enabled,omitempty"`
	// Addr is the agent channel's mTLS gRPC listen address. Empty defaults to ":9443"
	// (the port the shipped fleet manifests point agents at).
	Addr string `json:"addr,omitempty"`
	// ServerName is the DNS SAN the channel's server certificate carries — the name
	// agents set as their --server-name when they pin/verify the control plane.
	// Loopback SANs are always added so a co-located agent can verify a localhost
	// connection. Empty is allowed (loopback-only SANs).
	ServerName string `json:"server_name,omitempty"`
	// CACertFile is where the agent CA certificate is persisted so the agent CA is
	// stable across restarts (an agent's pinned CA does not change on a restart).
	// Empty defaults to "data/ca/agent-ca.crt".
	CACertFile string `json:"ca_cert_file,omitempty"`
	// HeartbeatInterval is the next-beat hint returned to agents (a Go duration, e.g.
	// "30s"). Empty selects a conservative default.
	HeartbeatInterval string `json:"heartbeat_interval,omitempty"`
}

// HeartbeatIntervalDuration parses the agent channel's next-beat hint. An empty value
// returns a zero duration with no error so the caller applies its own default.
func (a AgentChannel) HeartbeatIntervalDuration() (time.Duration, error) {
	if a.HeartbeatInterval == "" {
		return 0, nil
	}
	return time.ParseDuration(a.HeartbeatInterval)
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

const (
	// GovernanceStandard is the default issuance-governance posture: the individual
	// controls are independent and each is enabled on its own. The empty string is
	// treated as standard.
	GovernanceStandard = "standard"
	// GovernanceRegulated is the single coherent compliance posture (PKIGOV-003): it
	// fails startup unless the OPA policy gate, four-eyes dual control, a bound
	// default certificate profile, revocation publication, and any declared FIPS
	// requirement are ALL present together.
	GovernanceRegulated = "regulated"
)

// GovernanceModeValue normalizes the configured governance mode: empty is treated
// as standard. Used by config validation and the server's startup posture.
func (c CA) GovernanceModeValue() string {
	m := strings.ToLower(strings.TrimSpace(c.GovernanceMode))
	if m == "" {
		return GovernanceStandard
	}
	return m
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
		Telemetry: Telemetry{Enabled: false, Endpoint: "https://telemetry.trstctl.com/v1/usage", Interval: "24h"},
		// The audit export key persists under the data directory so signed evidence
		// bundles verify across restarts; retention is indefinite by default.
		Audit: Audit{SigningKeyFile: "data/audit/signing-key.pem"},
		Privacy: Privacy{Retention: PrivacyRetention{
			Enabled:      true,
			Interval:     "24h",
			Owners:       "17520h",
			Identities:   "9528h",
			Certificates: "9528h",
			SSHKeys:      "4320h",
			Access:       "2160h",
			Approvals:    "9528h",
			Profiles:     "9528h",
			Attestations: "9528h",
			Agents:       "4320h",
		}},
		// Per-tenant rate limiting is on by default so the product ships with
		// backpressure; the budget is generous and tunable.
		RateLimit: RateLimit{Enabled: true, Requests: 600, Window: "1m"},
		// Per-subsystem bulkheads are conservative by default and tunable per
		// deployment size (SPINE-08-003 / AN-7).
		Bulkheads: defaultBulkheads(),
		// Automatic migration is on by default so first boot and the single-node
		// eval path apply the schema without extra steps; production deployments
		// can disable it to gate migrations behind an explicit, backed-up step.
		Migrate: Migrate{Auto: true},
		// The credential KEK persists under the data directory so sealed
		// credentials stay openable across restarts; created on first boot if absent.
		Secrets: Secrets{KEKFile: "data/secrets/kek.bin"},
		// The signer runs as a supervised child by default (single binary); its
		// keys are sealed under the data directory so a restart preserves the CA.
		Signer: Signer{Mode: SignerChild, KeyStoreDir: "data/signer/keys", AuthSecretFile: "data/signer/sign-auth.bin", AllowCoResidentAuthorizer: true},
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
		// Served issuance protocols (EXC-WIRE-02). Enrollment protocols are opt-in
		// until explicitly tenant-bound. That keeps a fresh binary from exposing
		// public enrollment routes that later fail or mint into a blank tenant (AN-1).
		Protocols: Protocols{
			ACME: ProtocolToggle{Enabled: false},
			EST:  ProtocolToggle{Enabled: false},
			SCEP: ProtocolToggle{Enabled: false},
			CMP:  ProtocolToggle{Enabled: false},
			TSA:  ProtocolToggle{Enabled: false},
			ACMEQuota: ACMEQuota{
				MaxNonces:                  4096,
				MaxAccounts:                2048,
				MaxPendingOrders:           4096,
				MaxPendingAuthorizations:   8192,
				MaxPendingChallenges:       24576,
				MaxPendingOrdersPerAccount: 128,
				MaxNewNoncesPerSource:      120,
				MaxNewAccountsPerSource:    20,
				MaxNewOrdersPerSource:      60,
				SourceWindowSeconds:        600,
				NonceTTLSeconds:            600,
				StateTTLSeconds:            86400,
			},
			RAKeyFile:   "data/protocols/ra-transport.key",
			TSACertFile: "data/protocols/tsa.crt",
			SPIFFE:      SPIFFEProtocol{Enabled: false},
			SSH:         ProtocolToggle{Enabled: false},
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
// named by TRSTCTL_CONFIG_FILE, then environment overrides, and validates it.
// getenv is injected (pass os.Getenv) for testability.
func Load(getenv func(string) string) (*Config, error) {
	cfg := Default()
	if path := getenv("TRSTCTL_CONFIG_FILE"); path != "" {
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

// applyEnv overlays TRSTCTL_*-prefixed environment variables. Only non-empty
// variables take effect, so the environment can override but not blank out
// file or default values.
func (c *Config) applyEnv(getenv func(string) string) {
	setString(getenv, "TRSTCTL_SERVER_ADDR", &c.Server.Addr)
	setString(getenv, "TRSTCTL_SERVER_TLS_MODE", &c.Server.TLS.Mode)
	setString(getenv, "TRSTCTL_SERVER_TLS_CERT_FILE", &c.Server.TLS.CertFile)
	setString(getenv, "TRSTCTL_SERVER_TLS_KEY_FILE", &c.Server.TLS.KeyFile)
	setBool(getenv, "TRSTCTL_DEV_ALLOW_PLAINTEXT", &c.Server.TLS.AllowPlaintextDev)
	setCSV(getenv, "TRSTCTL_CORS_ALLOWED_ORIGINS", &c.Server.CORSAllowedOrigins)
	setString(getenv, "TRSTCTL_POSTGRES_MODE", &c.Postgres.Mode)
	setString(getenv, "TRSTCTL_POSTGRES_DSN", &c.Postgres.DSN)
	setString(getenv, "TRSTCTL_POSTGRES_DATA_DIR", &c.Postgres.DataDir)
	setInt(getenv, "TRSTCTL_POSTGRES_PORT", &c.Postgres.Port)
	setString(getenv, "TRSTCTL_NATS_MODE", &c.NATS.Mode)
	setString(getenv, "TRSTCTL_NATS_URL", &c.NATS.URL)
	setString(getenv, "TRSTCTL_NATS_STORE_DIR", &c.NATS.StoreDir)
	setInt(getenv, "TRSTCTL_NATS_REPLICAS", &c.NATS.Replicas)
	setBool(getenv, "TRSTCTL_NATS_ALLOW_SINGLE_REPLICA", &c.NATS.AllowSingleReplica)
	setString(getenv, "TRSTCTL_NATS_SYNC_INTERVAL", &c.NATS.SyncInterval)
	setBool(getenv, "TRSTCTL_NATS_SYNC_ALWAYS", &c.NATS.SyncAlways)
	setString(getenv, "TRSTCTL_LOG_LEVEL", &c.Log.Level)
	setString(getenv, "TRSTCTL_LOG_FORMAT", &c.Log.Format)
	setString(getenv, "TRSTCTL_LIFECYCLE_RENEW_BEFORE", &c.Lifecycle.RenewBefore)
	setString(getenv, "TRSTCTL_LIFECYCLE_ALERT_BEFORE", &c.Lifecycle.AlertBefore)
	setBool(getenv, "TRSTCTL_TELEMETRY_ENABLED", &c.Telemetry.Enabled)
	setString(getenv, "TRSTCTL_TELEMETRY_ENDPOINT", &c.Telemetry.Endpoint)
	setString(getenv, "TRSTCTL_TELEMETRY_INTERVAL", &c.Telemetry.Interval)
	setString(getenv, "TRSTCTL_AUDIT_SIGNING_KEY_FILE", &c.Audit.SigningKeyFile)
	setString(getenv, "TRSTCTL_AUDIT_RETENTION", &c.Audit.Retention)
	setString(getenv, "TRSTCTL_AUDIT_ARCHIVE_DIR", &c.Audit.ArchiveDir)
	applyPrivacyEnv(getenv, &c.Privacy)
	setString(getenv, "TRSTCTL_BACKUP_ENCRYPTION_KEY_FILE", &c.Backup.EncryptionKeyFile)
	setBool(getenv, "TRSTCTL_BACKUP_ALLOW_UNENCRYPTED", &c.Backup.AllowUnencrypted)
	setBool(getenv, "TRSTCTL_RATE_LIMIT_ENABLED", &c.RateLimit.Enabled)
	setInt(getenv, "TRSTCTL_RATE_LIMIT_REQUESTS", &c.RateLimit.Requests)
	setString(getenv, "TRSTCTL_RATE_LIMIT_WINDOW", &c.RateLimit.Window)
	applyBulkheadEnv(getenv, &c.Bulkheads)
	setBool(getenv, "TRSTCTL_MIGRATE_AUTO", &c.Migrate.Auto)
	setString(getenv, "TRSTCTL_SECRETS_KEK_FILE", &c.Secrets.KEKFile)
	setBool(getenv, "TRSTCTL_SECRETS_ENABLE_API", &c.Secrets.EnableAPI)
	setString(getenv, "TRSTCTL_SECRETS_AUTH_SECRET_FILE", &c.Secrets.AuthSecretFile)
	// Served AI / RCA / NL-query / MCP surface (SURFACE-003). OFF by default (fail
	// closed). The AI model stays air-gapped/opt-in regardless of these flags.
	setBool(getenv, "TRSTCTL_AI_ENABLE_API", &c.AI.EnableAPI)
	setString(getenv, "TRSTCTL_AI_MCP_IDENTITY", &c.AI.MCPIdentity)
	setInt(getenv, "TRSTCTL_AI_RATE_MAX", &c.AI.RateMax)
	setInt(getenv, "TRSTCTL_AI_RATE_WINDOW_SECONDS", &c.AI.RateWindowSeconds)
	setString(getenv, "TRSTCTL_AI_MODEL_MODE", &c.AI.Model.Mode)
	setString(getenv, "TRSTCTL_AI_MODEL_RUNTIME", &c.AI.Model.Runtime)
	setString(getenv, "TRSTCTL_AI_MODEL_PROVIDER", &c.AI.Model.Provider)
	setString(getenv, "TRSTCTL_AI_MODEL_ENDPOINT", &c.AI.Model.Endpoint)
	setString(getenv, "TRSTCTL_AI_MODEL_NAME", &c.AI.Model.Name)
	setBool(getenv, "TRSTCTL_AI_MODEL_ALLOW_EGRESS", &c.AI.Model.AllowEgress)
	setString(getenv, "TRSTCTL_SIGNER_MODE", &c.Signer.Mode)
	setString(getenv, "TRSTCTL_SIGNER_SOCKET", &c.Signer.Socket)
	setString(getenv, "TRSTCTL_SIGNER_KEY_STORE_DIR", &c.Signer.KeyStoreDir)
	setString(getenv, "TRSTCTL_SIGNER_AUTH_SECRET_FILE", &c.Signer.AuthSecretFile)
	setString(getenv, "TRSTCTL_SIGNER_AUTH_TOKEN_COMMAND", &c.Signer.AuthTokenCommand)
	setBool(getenv, "TRSTCTL_SIGNER_ALLOW_CO_RESIDENT_AUTHORIZER", &c.Signer.AllowCoResidentAuthorizer)
	setBool(getenv, "TRSTCTL_SIGNER_ALLOW_INSECURE_DEV_NONLINUX", &c.Signer.AllowInsecureDevNonLinux)
	setString(getenv, "TRSTCTL_SIGNER_MTLS_ADDRESS", &c.Signer.MTLSAddress)
	setString(getenv, "TRSTCTL_SIGNER_MTLS_SERVER_NAME", &c.Signer.MTLSServerName)
	setString(getenv, "TRSTCTL_SIGNER_MTLS_CERT_FILE", &c.Signer.MTLSCertFile)
	setString(getenv, "TRSTCTL_SIGNER_MTLS_KEY_FILE", &c.Signer.MTLSKeyFile)
	setString(getenv, "TRSTCTL_SIGNER_MTLS_PEER_CA_FILE", &c.Signer.MTLSPeerCAFile)
	setString(getenv, "TRSTCTL_SIGNER_MTLS_PEER_PIN", &c.Signer.MTLSPeerPin)
	setString(getenv, "TRSTCTL_CA_CERT_FILE", &c.CA.CertFile)
	// Regulated CA-governance posture (PKIGOV-003): the single coherent switch and
	// its declared FIPS requirement, operator-settable via env.
	setString(getenv, "TRSTCTL_CA_GOVERNANCE_MODE", &c.CA.GovernanceMode)
	setBool(getenv, "TRSTCTL_CA_REQUIRE_FIPS", &c.CA.RequireFIPS)
	// Served agent steady-state mTLS gRPC channel (WIRE-004 / OPS-005).
	setBool(getenv, "TRSTCTL_AGENT_CHANNEL_ENABLED", &c.AgentChannel.Enabled)
	setString(getenv, "TRSTCTL_AGENT_CHANNEL_ADDR", &c.AgentChannel.Addr)
	setString(getenv, "TRSTCTL_AGENT_CHANNEL_SERVER_NAME", &c.AgentChannel.ServerName)
	setString(getenv, "TRSTCTL_AGENT_CHANNEL_CA_CERT_FILE", &c.AgentChannel.CACertFile)
	setString(getenv, "TRSTCTL_AGENT_CHANNEL_HEARTBEAT_INTERVAL", &c.AgentChannel.HeartbeatInterval)
	// Served issuance protocols (EXC-WIRE-02): per-protocol enable + tenant binding.
	setBool(getenv, "TRSTCTL_PROTOCOLS_ACME_ENABLED", &c.Protocols.ACME.Enabled)
	setString(getenv, "TRSTCTL_PROTOCOLS_ACME_TENANT_ID", &c.Protocols.ACME.TenantID)
	setInt(getenv, "TRSTCTL_PROTOCOLS_ACME_MAX_NONCES", &c.Protocols.ACMEQuota.MaxNonces)
	setInt(getenv, "TRSTCTL_PROTOCOLS_ACME_MAX_ACCOUNTS", &c.Protocols.ACMEQuota.MaxAccounts)
	setInt(getenv, "TRSTCTL_PROTOCOLS_ACME_MAX_PENDING_ORDERS", &c.Protocols.ACMEQuota.MaxPendingOrders)
	setInt(getenv, "TRSTCTL_PROTOCOLS_ACME_MAX_PENDING_AUTHORIZATIONS", &c.Protocols.ACMEQuota.MaxPendingAuthorizations)
	setInt(getenv, "TRSTCTL_PROTOCOLS_ACME_MAX_PENDING_CHALLENGES", &c.Protocols.ACMEQuota.MaxPendingChallenges)
	setInt(getenv, "TRSTCTL_PROTOCOLS_ACME_MAX_PENDING_ORDERS_PER_ACCOUNT", &c.Protocols.ACMEQuota.MaxPendingOrdersPerAccount)
	setInt(getenv, "TRSTCTL_PROTOCOLS_ACME_MAX_NEW_NONCES_PER_SOURCE", &c.Protocols.ACMEQuota.MaxNewNoncesPerSource)
	setInt(getenv, "TRSTCTL_PROTOCOLS_ACME_MAX_NEW_ACCOUNTS_PER_SOURCE", &c.Protocols.ACMEQuota.MaxNewAccountsPerSource)
	setInt(getenv, "TRSTCTL_PROTOCOLS_ACME_MAX_NEW_ORDERS_PER_SOURCE", &c.Protocols.ACMEQuota.MaxNewOrdersPerSource)
	setInt(getenv, "TRSTCTL_PROTOCOLS_ACME_SOURCE_WINDOW_SECONDS", &c.Protocols.ACMEQuota.SourceWindowSeconds)
	setInt(getenv, "TRSTCTL_PROTOCOLS_ACME_NONCE_TTL_SECONDS", &c.Protocols.ACMEQuota.NonceTTLSeconds)
	setInt(getenv, "TRSTCTL_PROTOCOLS_ACME_STATE_TTL_SECONDS", &c.Protocols.ACMEQuota.StateTTLSeconds)
	setBool(getenv, "TRSTCTL_PROTOCOLS_EST_ENABLED", &c.Protocols.EST.Enabled)
	setString(getenv, "TRSTCTL_PROTOCOLS_EST_TENANT_ID", &c.Protocols.EST.TenantID)
	setBool(getenv, "TRSTCTL_PROTOCOLS_SCEP_ENABLED", &c.Protocols.SCEP.Enabled)
	setString(getenv, "TRSTCTL_PROTOCOLS_SCEP_TENANT_ID", &c.Protocols.SCEP.TenantID)
	setBool(getenv, "TRSTCTL_PROTOCOLS_CMP_ENABLED", &c.Protocols.CMP.Enabled)
	setString(getenv, "TRSTCTL_PROTOCOLS_CMP_TENANT_ID", &c.Protocols.CMP.TenantID)
	setBool(getenv, "TRSTCTL_PROTOCOLS_TSA_ENABLED", &c.Protocols.TSA.Enabled)
	setString(getenv, "TRSTCTL_PROTOCOLS_TSA_TENANT_ID", &c.Protocols.TSA.TenantID)
	setString(getenv, "TRSTCTL_PROTOCOLS_RA_KEY_FILE", &c.Protocols.RAKeyFile)
	setString(getenv, "TRSTCTL_PROTOCOLS_TSA_CERT_FILE", &c.Protocols.TSACertFile)
	setBool(getenv, "TRSTCTL_PROTOCOLS_SPIFFE_ENABLED", &c.Protocols.SPIFFE.Enabled)
	setString(getenv, "TRSTCTL_PROTOCOLS_SPIFFE_TENANT_ID", &c.Protocols.SPIFFE.TenantID)
	setString(getenv, "TRSTCTL_PROTOCOLS_SPIFFE_SOCKET_PATH", &c.Protocols.SPIFFE.SocketPath)
	setString(getenv, "TRSTCTL_PROTOCOLS_SPIFFE_TRUST_DOMAIN", &c.Protocols.SPIFFE.TrustDomain)
	setBool(getenv, "TRSTCTL_PROTOCOLS_SSH_ENABLED", &c.Protocols.SSH.Enabled)
	setString(getenv, "TRSTCTL_PROTOCOLS_SSH_TENANT_ID", &c.Protocols.SSH.TenantID)
	// Served OIDC browser login + session + per-user tenant mapping (EXC-WIRE-01).
	// The structured TenantMappings table is file-only (it is a list of objects); the
	// scalar knobs overlay from the environment like the rest of the config.
	setBool(getenv, "TRSTCTL_AUTH_OIDC_ENABLED", &c.Auth.OIDC.Enabled)
	setString(getenv, "TRSTCTL_AUTH_OIDC_ISSUER", &c.Auth.OIDC.Issuer)
	setString(getenv, "TRSTCTL_AUTH_OIDC_CLIENT_ID", &c.Auth.OIDC.ClientID)
	setString(getenv, "TRSTCTL_AUTH_OIDC_CLIENT_SECRET", &c.Auth.OIDC.ClientSecret)
	setString(getenv, "TRSTCTL_AUTH_OIDC_AUTH_ENDPOINT", &c.Auth.OIDC.AuthEndpoint)
	setString(getenv, "TRSTCTL_AUTH_OIDC_TOKEN_ENDPOINT", &c.Auth.OIDC.TokenEndpoint)
	setString(getenv, "TRSTCTL_AUTH_OIDC_REDIRECT_URI", &c.Auth.OIDC.RedirectURI)
	setString(getenv, "TRSTCTL_AUTH_OIDC_JWKS_FILE", &c.Auth.OIDC.JWKSFile)
	setString(getenv, "TRSTCTL_AUTH_OIDC_JWKS_JSON", &c.Auth.OIDC.JWKSJSON)
	setString(getenv, "TRSTCTL_AUTH_OIDC_SESSION_SECRET_FILE", &c.Auth.OIDC.SessionSecretFile)
	setString(getenv, "TRSTCTL_AUTH_OIDC_SESSION_TTL", &c.Auth.OIDC.SessionTTL)
	setString(getenv, "TRSTCTL_AUTH_OIDC_LOGIN_REDIRECT", &c.Auth.OIDC.LoginRedirect)
	setString(getenv, "TRSTCTL_AUTH_OIDC_TENANT_CLAIM", &c.Auth.OIDC.TenantClaim)
	setString(getenv, "TRSTCTL_AUTH_OIDC_GROUPS_CLAIM", &c.Auth.OIDC.GroupsClaim)
	setBool(getenv, "TRSTCTL_AUTH_OIDC_CLAIM_IS_TENANT", &c.Auth.OIDC.ClaimIsTenant)
	setString(getenv, "TRSTCTL_AUTH_OIDC_DEFAULT_TENANT", &c.Auth.OIDC.DefaultTenant)
	setBool(getenv, "TRSTCTL_AUTH_OIDC_ALLOW_DEFAULT_TENANT", &c.Auth.OIDC.AllowDefaultTenant)
	setCSV(getenv, "TRSTCTL_AUTH_OIDC_DEFAULT_ROLES", &c.Auth.OIDC.DefaultRoles)
	// Served WASM-plugin surface (EXC-WIRE-05; ARCH-007/SUPPLY-004). Off by default;
	// when enabled the binary loads + provenance-verifies connector plugins from the
	// directory against the trusted keys, failing closed on an unverified module.
	setBool(getenv, "TRSTCTL_PLUGINS_ENABLED", &c.Plugins.Enabled)
	setString(getenv, "TRSTCTL_PLUGINS_DIR", &c.Plugins.Dir)
	setCSV(getenv, "TRSTCTL_PLUGINS_TRUSTED_KEY_FILES", &c.Plugins.TrustedKeyFiles)
	setCSV(getenv, "TRSTCTL_PLUGINS_PINNED_DIGESTS", &c.Plugins.PinnedDigests)
	setCSV(getenv, "TRSTCTL_PLUGINS_CAPABILITIES", &c.Plugins.Capabilities)
	setCSV(getenv, "TRSTCTL_PLUGINS_PATH_PREFIXES", &c.Plugins.PathPrefixes)
	// Multi-replica HA (RESIL-002 / RESIL-004 / SPINE-007). Leader election defaults
	// ON (safe on a single replica, required for multi-replica); an operator can turn
	// it off explicitly. Snapshot/campaign intervals tune the SPINE-007 accelerator and
	// failover cadence.
	setBoolPtr(getenv, "TRSTCTL_HA_LEADER_ELECTION", &c.HA.LeaderElection)
	setString(getenv, "TRSTCTL_HA_LEADER_CAMPAIGN_INTERVAL", &c.HA.LeaderCampaignInterval)
	setString(getenv, "TRSTCTL_HA_SNAPSHOT_INTERVAL", &c.HA.SnapshotInterval)
}

func applyPrivacyEnv(getenv func(string) string, privacy *Privacy) {
	setBool(getenv, "TRSTCTL_PRIVACY_RETENTION_ENABLED", &privacy.Retention.Enabled)
	setString(getenv, "TRSTCTL_PRIVACY_RETENTION_INTERVAL", &privacy.Retention.Interval)
	setString(getenv, "TRSTCTL_PRIVACY_RETENTION_OWNERS", &privacy.Retention.Owners)
	setString(getenv, "TRSTCTL_PRIVACY_RETENTION_IDENTITIES", &privacy.Retention.Identities)
	setString(getenv, "TRSTCTL_PRIVACY_RETENTION_CERTIFICATES", &privacy.Retention.Certificates)
	setString(getenv, "TRSTCTL_PRIVACY_RETENTION_SSH_KEYS", &privacy.Retention.SSHKeys)
	setString(getenv, "TRSTCTL_PRIVACY_RETENTION_ACCESS", &privacy.Retention.Access)
	setString(getenv, "TRSTCTL_PRIVACY_RETENTION_APPROVALS", &privacy.Retention.Approvals)
	setString(getenv, "TRSTCTL_PRIVACY_RETENTION_PROFILES", &privacy.Retention.Profiles)
	setString(getenv, "TRSTCTL_PRIVACY_RETENTION_ATTESTATIONS", &privacy.Retention.Attestations)
	setString(getenv, "TRSTCTL_PRIVACY_RETENTION_AGENTS", &privacy.Retention.Agents)
}

func applyBulkheadEnv(getenv func(string) string, b *Bulkheads) {
	setInt(getenv, "TRSTCTL_BULKHEAD_API_WORKERS", &b.API.Workers)
	setInt(getenv, "TRSTCTL_BULKHEAD_API_QUEUE", &b.API.Queue)
	setInt(getenv, "TRSTCTL_BULKHEAD_PROJECTIONS_WORKERS", &b.Projections.Workers)
	setInt(getenv, "TRSTCTL_BULKHEAD_PROJECTIONS_QUEUE", &b.Projections.Queue)
	setInt(getenv, "TRSTCTL_BULKHEAD_OUTBOX_WORKERS", &b.Outbox.Workers)
	setInt(getenv, "TRSTCTL_BULKHEAD_OUTBOX_QUEUE", &b.Outbox.Queue)
	setInt(getenv, "TRSTCTL_BULKHEAD_SIGNING_WORKERS", &b.Signing.Workers)
	setInt(getenv, "TRSTCTL_BULKHEAD_SIGNING_QUEUE", &b.Signing.Queue)
	setInt(getenv, "TRSTCTL_BULKHEAD_QUERY_WORKERS", &b.Query.Workers)
	setInt(getenv, "TRSTCTL_BULKHEAD_QUERY_QUEUE", &b.Query.Queue)
	setInt(getenv, "TRSTCTL_BULKHEAD_POLICY_WORKERS", &b.Policy.Workers)
	setInt(getenv, "TRSTCTL_BULKHEAD_POLICY_QUEUE", &b.Policy.Queue)
	setInt(getenv, "TRSTCTL_BULKHEAD_PROTOCOLS_WORKERS", &b.Protocols.Workers)
	setInt(getenv, "TRSTCTL_BULKHEAD_PROTOCOLS_QUEUE", &b.Protocols.Queue)
	setInt(getenv, "TRSTCTL_BULKHEAD_AGENT_WORKERS", &b.Agent.Workers)
	setInt(getenv, "TRSTCTL_BULKHEAD_AGENT_QUEUE", &b.Agent.Queue)
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
	for _, validate := range []func(*Config) []error{
		validateServerConfig,
		validateDatastores,
		validateLoggingAndLifecycle,
		validateOptionalServices,
		validateBulkheadConfig,
		validateSignerConfig,
		validateServedSurfaces,
		validateGovernanceConfig,
		validateHAConfig,
	} {
		errs = append(errs, validate(c)...)
	}
	return errors.Join(errs...)
}

func validateBulkheadConfig(c *Config) []error {
	return c.Bulkheads.validate()
}

func validateServerConfig(c *Config) []error {
	var errs []error
	if c.Server.Addr == "" {
		errs = append(errs, errors.New("server.addr must not be empty"))
	}
	switch c.Server.TLS.Mode {
	case TLSInternal:
		// no extra requirements
	case TLSDisabled:
		if !c.Server.TLS.AllowPlaintextDev {
			errs = append(errs, errors.New("server.tls.mode=disabled requires explicit local-dev override TRSTCTL_DEV_ALLOW_PLAINTEXT=true (or server.tls.allow_plaintext_dev=true)"))
		}
		if !isLoopbackListenAddr(c.Server.Addr) {
			errs = append(errs, fmt.Errorf("server.tls.mode=disabled requires server.addr to bind loopback only, got %q", c.Server.Addr))
		}
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
	return errs
}

func isLoopbackListenAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" {
		return false
	}
	return isLoopbackHost(host)
}

func validateDatastores(c *Config) []error {
	var errs []error
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
	if c.NATS.Mode == NATSExternal && c.NATS.Replicas == 1 && !c.NATS.AllowSingleReplica {
		errs = append(errs, errors.New("nats.replicas=1 in external mode requires nats.allow_single_replica=true (TRSTCTL_NATS_ALLOW_SINGLE_REPLICA=true); this is evaluation-only and not HA"))
	}
	// Embedded fsync cadence (RESIL-001): empty means the trstctl default; when set
	// it must be a valid, positive Go duration.
	if d, err := c.NATS.SyncIntervalDuration(); err != nil {
		errs = append(errs, fmt.Errorf("nats.sync_interval %q is invalid: %w", c.NATS.SyncInterval, err))
	} else if d < 0 {
		errs = append(errs, errors.New("nats.sync_interval must not be negative"))
	}
	return errs
}

func validateLoggingAndLifecycle(c *Config) []error {
	var errs []error
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
	return errs
}

func validateOptionalServices(c *Config) []error {
	var errs []error
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
	if d, err := c.Privacy.Retention.IntervalDuration(); err != nil {
		errs = append(errs, fmt.Errorf("privacy.retention.interval %q is invalid: %w", c.Privacy.Retention.Interval, err))
	} else if c.Privacy.Retention.Enabled && d < 0 {
		errs = append(errs, errors.New("privacy.retention.interval must not be negative"))
	}
	for _, f := range []struct {
		name  string
		value string
	}{
		{"owners", c.Privacy.Retention.Owners},
		{"identities", c.Privacy.Retention.Identities},
		{"certificates", c.Privacy.Retention.Certificates},
		{"ssh_keys", c.Privacy.Retention.SSHKeys},
		{"access", c.Privacy.Retention.Access},
		{"approvals", c.Privacy.Retention.Approvals},
		{"profiles", c.Privacy.Retention.Profiles},
		{"attestations", c.Privacy.Retention.Attestations},
		{"agents", c.Privacy.Retention.Agents},
	} {
		if f.value == "" {
			continue
		}
		if d, err := time.ParseDuration(f.value); err != nil {
			errs = append(errs, fmt.Errorf("privacy.retention.%s %q is invalid: %w", f.name, f.value, err))
		} else if d <= 0 {
			errs = append(errs, fmt.Errorf("privacy.retention.%s must be positive", f.name))
		}
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
	return errs
}

func validateSignerConfig(c *Config) []error {
	var errs []error
	if c.Signer.AuthTokenCommand != "" && c.Signer.AllowCoResidentAuthorizer {
		errs = append(errs, errors.New("signer.auth_token_command and signer.allow_co_resident_authorizer are mutually exclusive"))
	}
	if c.Signer.AllowCoResidentAuthorizer && c.NATS.Mode == NATSExternal && !c.NATS.AllowSingleReplica {
		errs = append(errs, errors.New("signer.allow_co_resident_authorizer is evaluation-only; production external NATS deployments must use signer.auth_token_command or another independent token provider"))
	}
	if c.Signer.AllowInsecureDevNonLinux && c.Signer.Mode != SignerChild {
		errs = append(errs, errors.New("signer.allow_insecure_dev_nonlinux is only valid for local child signer development; external signer deployments must harden the signer process directly"))
	}
	// The signer runs as a supervised child or connects to an external service. An
	// external signer is reached over EITHER a co-located UDS (signer.socket) OR a
	// cross-node mTLS channel (signer.mtls_address + the mTLS material, SIGNER-005);
	// exactly one must be configured, and a partial mTLS block fails closed here so
	// the binary never serves issuance against a half-configured signer transport.
	switch c.Signer.Mode {
	case SignerChild:
		// ok — single-binary supervises the child
		if c.Signer.AuthSecretFile == "" {
			errs = append(errs, errors.New("signer.auth_secret_file is required so the child signer can verify content authorization tokens"))
		}
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
	return errs
}

func validateServedSurfaces(c *Config) []error {
	var errs []error
	// Served OIDC login (EXC-WIRE-01): when enabled it must be FULLY configured, so
	// the binary never serves a half-wired login (fail closed). When disabled the
	// block is ignored.
	if c.Auth.OIDC.Enabled {
		errs = append(errs, c.Auth.OIDC.validate()...)
	}
	// Served enrollment protocols are public protocol endpoints. When one is
	// enabled, startup must know the tenant it mints into before any route is
	// exposed; a blank tenant would violate AN-1 and only fail at enrollment time.
	errs = append(errs, c.Protocols.ValidateTenantBindings("")...)
	errs = append(errs, c.Protocols.ACMEQuota.validate()...)
	// Served plugin surface (EXC-WIRE-05; ARCH-007/SUPPLY-004): when enabled it must
	// name a directory and at least one trusted key, so the binary never serves an
	// unverifiable plugin path (fail closed). When disabled the block is ignored.
	if c.Plugins.Enabled {
		errs = append(errs, c.Plugins.validate()...)
	}
	errs = append(errs, validateAIModel(c.AI.Model)...)
	// Served agent steady-state channel (WIRE-004 / OPS-005): when enabled it requires a
	// signer (the agent CA is custodied there, AN-4) so the binary never advertises an
	// agent channel it cannot back with a signer-custodied CA — fail closed. The
	// heartbeat interval, if set, must parse. When disabled the block is ignored.
	if c.AgentChannel.Enabled {
		if c.Signer.Mode == "" {
			errs = append(errs, errors.New("agent_channel.enabled requires a signer (signer.mode), as the agent CA is custodied in the signer (AN-4)"))
		}
		if _, err := c.AgentChannel.HeartbeatIntervalDuration(); err != nil {
			errs = append(errs, fmt.Errorf("agent_channel.heartbeat_interval: %w", err))
		}
	}
	return errs
}

// fipsActive reports whether the FIPS 140-3 cryptographic module is active for this
// process. It is a package var so regulated-mode validation can be exercised in
// either FIPS state without building a FIPS binary; production reads the real
// boundary value (crypto.FIPSEnabled, the single AN-3 FIPS read).
var fipsActive = crypto.FIPSEnabled

// validateGovernanceConfig enforces the regulated CA-governance posture (PKIGOV-003).
// In the default/standard posture it imposes nothing (the individual controls stay
// independent). In "regulated" mode it FAILS STARTUP unless every regulated control
// is coherently present together, so a compliance deployment cannot half-enable the
// posture and silently drop a control:
//
//   - the OPA/Rego default-deny policy gate is on (ca.policy.enabled);
//   - distinct-approver four-eyes dual control is on with a >=2 approval threshold
//     (ca.policy.require_approval + a bound approval store via required_approvals);
//   - a default certificate profile is bound (ca.default_profile);
//   - revocation publication is configured (a CRL distribution point and/or an OCSP
//     responder URL), so issued leaves carry a checkable status pointer;
//   - and, when ca.require_fips is declared, the FIPS 140-3 module is active.
//
// Each missing piece yields an actionable error naming the field to set. A complete
// regulated config returns no error and boots.
func validateGovernanceConfig(c *Config) []error {
	mode := c.CA.GovernanceModeValue()
	switch mode {
	case GovernanceStandard:
		return nil
	case GovernanceRegulated:
		// fall through to the coherence checks below.
	default:
		return []error{fmt.Errorf("ca.governance_mode %q is invalid (want %q or %q)", c.CA.GovernanceMode, GovernanceStandard, GovernanceRegulated)}
	}

	var errs []error
	if !c.CA.Policy.Enabled {
		errs = append(errs, errors.New("ca.governance_mode=regulated requires the OPA policy gate (set ca.policy.enabled=true / TRSTCTL_CA_POLICY_ENABLED=true)"))
	}
	if !c.CA.Policy.RequireApproval {
		errs = append(errs, errors.New("ca.governance_mode=regulated requires four-eyes dual control (set ca.policy.require_approval=true / TRSTCTL_CA_POLICY_REQUIRE_APPROVAL=true)"))
	} else if c.CA.Policy.RequiredApprovals != 0 && c.CA.Policy.RequiredApprovals < 2 {
		// 0 means the dual-control default of 2; an explicit 1 is single approval,
		// which is not four-eyes.
		errs = append(errs, fmt.Errorf("ca.governance_mode=regulated requires at least 2 distinct approvers (four-eyes); ca.policy.required_approvals=%d is single approval", c.CA.Policy.RequiredApprovals))
	}
	if strings.TrimSpace(c.CA.DefaultProfile) == "" {
		errs = append(errs, errors.New("ca.governance_mode=regulated requires a bound default certificate profile (set ca.default_profile / TRSTCTL_CA_DEFAULT_PROFILE)"))
	}
	if len(c.CA.CRLDistributionPoints) == 0 && len(c.CA.OCSPServers) == 0 {
		errs = append(errs, errors.New("ca.governance_mode=regulated requires revocation publication: set at least one of ca.crl_distribution_points or ca.ocsp_servers so issued certificates carry a status pointer"))
	}
	if c.CA.RequireFIPS && !fipsActive() {
		errs = append(errs, errors.New("ca.governance_mode=regulated with ca.require_fips=true requires the FIPS 140-3 module to be active: build with GOFIPS140=latest (make fips-build) or run with GODEBUG=fips140=on"))
	}
	return errs
}

func validateAIModel(m AIModel) []error {
	var errs []error
	mode := m.ModeValue()
	switch mode {
	case AIModelOff:
		if m.AllowEgress {
			errs = append(errs, errors.New("ai.model.allow_egress is only valid when ai.model.mode is cloud"))
		}
	case AIModelLocal:
		runtime := strings.ToLower(strings.TrimSpace(m.Runtime))
		if runtime != AIModelRuntimeOllama && runtime != AIModelRuntimeVLLM {
			errs = append(errs, fmt.Errorf("ai.model.runtime %q is invalid for local mode (want %q or %q)", m.Runtime, AIModelRuntimeOllama, AIModelRuntimeVLLM))
		}
		if strings.TrimSpace(m.Provider) != "" {
			errs = append(errs, errors.New("ai.model.provider is only valid when ai.model.mode is cloud; use ai.model.runtime for local models"))
		}
		if m.AllowEgress {
			errs = append(errs, errors.New("ai.model.allow_egress is only valid when ai.model.mode is cloud"))
		}
		if strings.TrimSpace(m.Name) == "" {
			errs = append(errs, errors.New("ai.model.name is required when ai.model.mode is local"))
		}
		errs = append(errs, validateAIEndpoint("ai.model.endpoint", m.Endpoint, false)...)
	case AIModelCloud:
		if strings.TrimSpace(m.Provider) == "" {
			errs = append(errs, errors.New("ai.model.provider is required when ai.model.mode is cloud"))
		}
		if strings.TrimSpace(m.Runtime) != "" {
			errs = append(errs, errors.New("ai.model.runtime is only valid when ai.model.mode is local"))
		}
		if strings.TrimSpace(m.Name) == "" {
			errs = append(errs, errors.New("ai.model.name is required when ai.model.mode is cloud"))
		}
		if !m.AllowEgress {
			errs = append(errs, errors.New("ai.model.allow_egress=true is required when ai.model.mode is cloud"))
		}
		errs = append(errs, validateAIEndpoint("ai.model.endpoint", m.Endpoint, true)...)
	default:
		errs = append(errs, fmt.Errorf("ai.model.mode %q is invalid (want %q, %q, or %q)", m.Mode, AIModelOff, AIModelLocal, AIModelCloud))
	}
	return errs
}

func validateAIEndpoint(name, raw string, requireHTTPS bool) []error {
	var errs []error
	if strings.TrimSpace(raw) == "" {
		return []error{fmt.Errorf("%s is required when ai.model.mode is not off", name)}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return []error{fmt.Errorf("%s %q must be an absolute http(s) URL", name, raw)}
	}
	if u.User != nil {
		errs = append(errs, fmt.Errorf("%s must not include credentials in the URL", name))
	}
	switch {
	case requireHTTPS:
		if u.Scheme != "https" {
			errs = append(errs, fmt.Errorf("%s %q must use https for cloud model egress", name, raw))
		}
	case u.Scheme == "https":
		// ok
	case u.Scheme == "http" && isLoopbackHost(u.Hostname()):
		// ok: local Ollama/vLLM loopback endpoint
	default:
		errs = append(errs, fmt.Errorf("%s %q must use https unless it is a loopback local model endpoint", name, raw))
	}
	return errs
}

func (q ACMEQuota) validate() []error {
	var errs []error
	check := func(name string, v int) {
		if v <= 0 {
			errs = append(errs, fmt.Errorf("protocols.acme_quota.%s must be positive", name))
		}
	}
	check("max_nonces", q.MaxNonces)
	check("max_accounts", q.MaxAccounts)
	check("max_pending_orders", q.MaxPendingOrders)
	check("max_pending_authorizations", q.MaxPendingAuthorizations)
	check("max_pending_challenges", q.MaxPendingChallenges)
	check("max_pending_orders_per_account", q.MaxPendingOrdersPerAccount)
	check("max_new_nonces_per_source", q.MaxNewNoncesPerSource)
	check("max_new_accounts_per_source", q.MaxNewAccountsPerSource)
	check("max_new_orders_per_source", q.MaxNewOrdersPerSource)
	check("source_window_seconds", q.SourceWindowSeconds)
	check("nonce_ttl_seconds", q.NonceTTLSeconds)
	check("state_ttl_seconds", q.StateTTLSeconds)
	return errs
}

func validateHAConfig(c *Config) []error {
	var errs []error
	// Multi-replica HA (RESIL-004 / SPINE-007): the durations must parse, so a typo in
	// the snapshot or campaign cadence fails fast at startup rather than silently
	// falling back to a default or busy-looping.
	if _, err := c.HA.SnapshotIntervalDuration(); err != nil {
		errs = append(errs, err)
	}
	if _, err := c.HA.LeaderCampaignIntervalDuration(); err != nil {
		errs = append(errs, err)
	}
	return errs
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
		if err != nil || u.Host == "" || (u.Scheme != "https" && (u.Scheme != "http" || !isLoopbackHost(u.Hostname()))) {
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
