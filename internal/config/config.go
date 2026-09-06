// SPDX-License-Identifier: MPL-2.0

// Package config loads, merges, and validates trstctl's configuration from a
// JSON file and the environment, with precedence defaults < file < environment.
// It includes the bundled-vs-external datastore switches for PostgreSQL and
// NATS and carries no business logic.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/netsec"
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
	Server                    Server                   `json:"server"`
	Postgres                  Postgres                 `json:"postgres"`
	NATS                      NATS                     `json:"nats"`
	Log                       Log                      `json:"log"`
	Lifecycle                 Lifecycle                `json:"lifecycle"`
	Connectors                Connectors               `json:"connectors"`
	ExternalCAs               []ExternalCAConfig       `json:"external_cas,omitempty"`
	SecretIntegrations        SecretIntegrationsConfig `json:"secret_integrations,omitempty"`
	Notifications             Notifications            `json:"notifications"`
	CodeSigning               CodeSigning              `json:"code_signing"`
	ITSM                      ITSM                     `json:"itsm"`
	AirGap                    AirGap                   `json:"air_gap"`
	OutboundEnvCredentialRefs []string                 `json:"outbound_env_credential_refs,omitempty"`
	Telemetry                 Telemetry                `json:"telemetry"`
	OTLP                      OTLP                     `json:"otlp"`
	Audit                     Audit                    `json:"audit"`
	Breakglass                Breakglass               `json:"breakglass"`
	Privacy                   Privacy                  `json:"privacy"`
	AttestedIssuance          AttestedIssuance         `json:"attested_issuance"`
	EphemeralIssuance         EphemeralIssuance        `json:"ephemeral_issuance"`
	Provider                  Provider                 `json:"provider"`
	Reconcile                 Reconcile                `json:"reconcile"`
	AgentBroker               AgentBroker              `json:"agent_broker"`
	PAM                       PAM                      `json:"pam"`
	Backup                    Backup                   `json:"backup"`
	License                   License                  `json:"license"`
	RateLimit                 RateLimit                `json:"rate_limit"`
	Bulkheads                 Bulkheads                `json:"bulkheads"`
	Migrate                   Migrate                  `json:"migrate"`
	Secrets                   Secrets                  `json:"secrets"`
	Transit                   Transit                  `json:"transit"`
	ManagedKeys               ManagedKeys              `json:"managed_keys"`
	Signer                    Signer                   `json:"signer"`
	CA                        CA                       `json:"ca"`
	Protocols                 Protocols                `json:"protocols"`
	Auth                      Auth                     `json:"auth"`
	Plugins                   Plugins                  `json:"plugins"`
	HA                        HA                       `json:"ha"`
	Federation                Federation               `json:"federation"`
	PCAS                      PCAS                     `json:"pcas"`
	AI                        AI                       `json:"ai"`
	// AgentChannel configures the served agent steady-state mTLS gRPC channel
	// (WIRE-004 / OPS-005). Off by default.
	AgentChannel AgentChannel `json:"agent_channel"`
}

// License configures the offline open-core license file. Empty means Community.
type License struct {
	File         string `json:"file,omitempty"`
	DeploymentID string `json:"deployment_id,omitempty"`
	Environment  string `json:"environment,omitempty"`
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

// Federation configures cross-cluster read-state federation (FED-01). It is OFF
// by default. When enabled, the leader imports peer event logs into the local
// event log and projects them locally; no new datastore is introduced.
type Federation struct {
	Enabled   bool             `json:"enabled,omitempty"`
	ClusterID string           `json:"cluster_id,omitempty"`
	Region    string           `json:"region,omitempty"`
	Interval  string           `json:"interval,omitempty"`
	RPO       string           `json:"rpo,omitempty"`
	RTO       string           `json:"rto,omitempty"`
	Peers     []FederationPeer `json:"peers,omitempty"`
}

// FederationPeer is one source cluster this cluster imports from.
type FederationPeer struct {
	ID      string `json:"id,omitempty"`
	Region  string `json:"region,omitempty"`
	NATSURL string `json:"nats_url,omitempty"`
}

// PCAS configures production wiring for patent-covered credential algorithm
// succession mechanisms. It is off by default and is enabled by the EE attach
// seam only when the licensed feature is present.
type PCAS struct {
	Delegation  PCASDelegation  `json:"delegation"`
	Recovery    PCASRecovery    `json:"recovery"`
	Federation  PCASFederation  `json:"federation"`
	KEM         PCASKEM         `json:"kem"`
	Checkpoints PCASCheckpoints `json:"checkpoints"`
	Monitors    PCASMonitors    `json:"monitors"`
	Retirement  PCASRetirement  `json:"retirement"`
	Issuer      PCASIssuer      `json:"issuer"`
	Staple      PCASStaple      `json:"staple"`
}

type PCASDelegation struct {
	Enabled         bool   `json:"enabled,omitempty"`
	RefreshInterval string `json:"refresh_interval,omitempty"`
	SignerStoreDir  string `json:"signer_store_dir,omitempty"`
}

// PCASRecovery configures the threshold-recovery breadth surface. OutboxTopic is
// the outbox destination recovery mints are enqueued under AND drained from —
// both sides resolve it from here, defaulting to "pcas.recovery-request".
// (A worker_concurrency knob existed here once, validated and never read by any
// worker — AUD-7; per-family outbox concurrency is governed by the
// bulkheads.outbox.* pools, so the fictional field is gone rather than kept.)
type PCASRecovery struct {
	Enabled     bool   `json:"enabled,omitempty"`
	OutboxTopic string `json:"outbox_topic,omitempty"`
}

type PCASFederation struct {
	Enabled     bool   `json:"enabled,omitempty"`
	OutboxTopic string `json:"outbox_topic,omitempty"`
}

type PCASKEM struct {
	Enabled     bool   `json:"enabled,omitempty"`
	OutboxTopic string `json:"outbox_topic,omitempty"`
}

type PCASCheckpoints struct {
	Enabled          bool   `json:"enabled,omitempty"`
	Interval         string `json:"interval,omitempty"`
	SigningKeyHandle string `json:"signing_key_handle,omitempty"`
	SigningAlgorithm string `json:"signing_algorithm,omitempty"`
}

type PCASMonitors struct {
	Enabled  bool   `json:"enabled,omitempty"`
	Interval string `json:"interval,omitempty"`
}

type PCASRetirement struct {
	Enabled        bool   `json:"enabled,omitempty"`
	Interval       string `json:"interval,omitempty"`
	ValidityWindow string `json:"validity_window,omitempty"`
}

type PCASIssuer struct {
	Enabled bool `json:"enabled,omitempty"`
}

type PCASStaple struct {
	Enabled bool `json:"enabled,omitempty"`
}

func (f Federation) IntervalDuration() (time.Duration, error) {
	if f.Interval == "" {
		return time.Second, nil
	}
	return time.ParseDuration(f.Interval)
}

func (f Federation) RPODuration() (time.Duration, error) {
	if f.RPO == "" {
		return 5 * time.Second, nil
	}
	return time.ParseDuration(f.RPO)
}

func (f Federation) RTODuration() (time.Duration, error) {
	if f.RTO == "" {
		return 30 * time.Second, nil
	}
	return time.ParseDuration(f.RTO)
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
// ARCH-007/SUPPLY-004): the running control plane loads operator-supplied CA,
// connector, and DNS-provider plugins from directories and runs them capability-sandboxed through
// the wazero plugin host. It is OFF by default (Enabled=false): an otherwise
// unowned connector.deploy fails closed, and no WASM CA appears in the external-CA registry.
// When Enabled, a plugin is admitted ONLY after its detached Ed25519 signature
// verifies against TrustedKeyFiles (SUPPLY-004); an unsigned, wrong-key,
// tampered, or unpinned module makes the binary fail closed at startup — it
// never serves an unverified plugin.
type Plugins struct {
	// Enabled turns on the served plugin surface. Off by default.
	Enabled bool `json:"enabled,omitempty"`
	// Dir is the legacy connector-plugin directory scanned for `<name>.wasm` +
	// detached `<name>.wasm.sig` pairs. ConnectorDir takes precedence when set.
	Dir string `json:"dir,omitempty"`
	// CADir is scanned for signed CA plugins. Each module becomes a
	// `/api/v1/external-cas/{name}/issue` authority of type `wasm-ca`.
	CADir string `json:"ca_dir,omitempty"`
	// DNSDir is scanned for signed DNS-provider plugins. Each module becomes a
	// served ACME DNS-01 provider that can be selected by tenant provider configs.
	DNSDir string `json:"dns_dir,omitempty"`
	// ConnectorDir is scanned for signed deployment connector plugins.
	ConnectorDir string `json:"connector_dir,omitempty"`
	// TrustedKeyFiles are paths to PEM Ed25519 public keys that admit a signed
	// module (SUPPLY-004). At least one is required when Enabled.
	TrustedKeyFiles []string `json:"trusted_key_files,omitempty"`
	// PinnedDigests optionally restricts admitted modules to an exact-content
	// allowlist (lowercase-hex SHA-256 of the `.wasm`).
	PinnedDigests []string `json:"pinned_digests,omitempty"`
	// Capabilities are the capability names every loaded plugin runs
	// under (a subset of fs.read, fs.write, net.dial, process.exec). Empty grants
	// nothing privileged — operators widen it deliberately. A plugin can never
	// exceed this grant at runtime.
	Capabilities []string `json:"capabilities,omitempty"`
	// PathPrefixes constrains fs.read / fs.write to resources under these prefixes
	// (defense-in-depth alongside the capability grant). Empty means the granted
	// filesystem capability is unconstrained by prefix.
	PathPrefixes []string `json:"path_prefixes,omitempty"`
}

// Auth configures interactive authentication for the served control plane. It
// carries the OIDC and SAML browser-login + session bridges; scoped API tokens
// always authenticate the binary regardless of this block.
type Auth struct {
	OIDC OIDC `json:"oidc"`
	SAML SAML `json:"saml"`
	LDAP LDAP `json:"ldap"`
	SCIM SCIM `json:"scim"`
	ABAC ABAC `json:"abac"`
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
	// AuthorizationResponseIssParamSupported enables RFC 9207 callback `iss`
	// validation when the IdP discovery document advertises it.
	AuthorizationResponseIssParamSupported bool `json:"authorization_response_iss_parameter_supported,omitempty"`
	// ClientID is trstctl's registered OAuth client id (the expected `aud`). Required.
	ClientID string `json:"client_id,omitempty"`
	// ClientSecret authenticates the code→token exchange at the token endpoint.
	// Confidential clients require it; a public/PKCE client may leave it empty.
	//
	// AN-8: this is live credential material, so it is held in wipeable byte
	// memory and never in a Go string — an immutable string cannot be zeroed and
	// the garbage collector may copy it freely, so a string-typed client secret
	// persists in the heap (and in any core dump) for the whole process lifetime.
	// That is not academic here: internal/server wipes the buffer it derives from
	// this field after each token exchange, which is pointless while the original
	// is an unwipeable string.
	//
	// secret.JSONBytes decodes from and encodes to a PLAIN JSON string, so the
	// on-disk config form and TRSTCTL_AUTH_OIDC_CLIENT_SECRET are unchanged; a
	// bare []byte would have silently switched this field to base64.
	//
	// Prefer ClientSecretTenant/ClientSecretRef below: they keep the secret
	// encrypted at rest in the credential store instead of in the config file.
	ClientSecret secret.JSONBytes `json:"client_secret,omitempty"`
	// ClientSecretTenant / ClientSecretRef point to an encrypted credential-store
	// entry for confidential clients. The row is tenant-scoped as
	// (tenant, auth.oidc, ref, client_secret), and is opened only for token exchange.
	ClientSecretTenant string `json:"client_secret_tenant,omitempty"`
	ClientSecretRef    string `json:"client_secret_ref,omitempty"`
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

// SAML configures the served SAML 2.0 Service Provider (IAM-02): SP-initiated
// login, IdP-initiated login, signed assertion verification, the shared browser
// session cookie, and the same per-user → tenant mapping table the OIDC path uses.
// It is OFF by default. When enabled, the binary mounts /auth/saml/login,
// /auth/saml/acs, and /auth/saml/metadata. Misconfiguration fails closed at
// startup, so the binary never exposes a half-wired SAML ACS endpoint.
type SAML struct {
	Enabled bool `json:"enabled,omitempty"`
	// EntityID is this service provider's stable SAML entity ID.
	EntityID string `json:"entity_id,omitempty"`
	// MetadataURL is the externally reachable /auth/saml/metadata URL.
	MetadataURL string `json:"metadata_url,omitempty"`
	// ACSURL is the externally reachable /auth/saml/acs URL registered with the IdP.
	ACSURL string `json:"acs_url,omitempty"`
	// IDPMetadataFile points at the IdP metadata XML. One of IDPMetadataFile or
	// IDPMetadataXML is required so IdP certificates verify offline.
	IDPMetadataFile string `json:"idp_metadata_file,omitempty"`
	// IDPMetadataXML is inline IdP metadata XML.
	IDPMetadataXML string `json:"idp_metadata_xml,omitempty"`
	// SessionSecretFile persists the HMAC secret that signs browser sessions.
	SessionSecretFile string `json:"session_secret_file,omitempty"`
	// SessionTTL is the lifetime of a session cookie. Empty defaults to 12h.
	SessionTTL string `json:"session_ttl,omitempty"`
	// LoginRedirect is where the browser lands after a successful login. Empty -> "/".
	LoginRedirect string `json:"login_redirect,omitempty"`

	// SubjectAttribute optionally overrides the assertion NameID as the session
	// subject. It is useful for IdPs that keep the stable user id in an attribute.
	SubjectAttribute string `json:"subject_attribute,omitempty"`
	// EmailAttribute names the SAML attribute carrying the user's email address.
	EmailAttribute string `json:"email_attribute,omitempty"`
	// TenantClaim names the SAML attribute whose value identifies the user's tenant.
	TenantClaim string `json:"tenant_claim,omitempty"`
	// GroupsClaim names the SAML attribute carrying group memberships.
	GroupsClaim string `json:"groups_claim,omitempty"`
	// ClaimIsTenant, when true, uses TenantClaim directly as the trstctl tenant id.
	ClaimIsTenant bool `json:"claim_is_tenant,omitempty"`
	// TenantMappings binds SAML subject / tenant-claim value / group to a tenant and
	// roles. It reuses the OIDC mapping shape deliberately.
	TenantMappings []TenantMapping `json:"tenant_mappings,omitempty"`
	DefaultRoles   []string        `json:"default_roles,omitempty"`
	DefaultTenant  string          `json:"default_tenant,omitempty"`
	// AllowDefaultTenant opts into the DefaultTenant fallback. Off by default.
	AllowDefaultTenant bool `json:"allow_default_tenant,omitempty"`
}

// LDAP configures served LDAP / Active Directory browser login (IAM-03):
// username/password bind, directory group lookup, shared browser session cookies,
// and group-to-tenant/role mapping through the same tenant mapper as OIDC/SAML.
// It is OFF by default. When enabled, the binary mounts /auth/ldap/login and fails
// closed at startup if the directory, search, session, or tenant mapping config is
// incomplete.
type LDAP struct {
	Enabled bool `json:"enabled,omitempty"`
	// URL is the LDAP endpoint. Use ldaps:// for production directories; ldap:// is
	// accepted only on loopback so local OpenLDAP fixtures do not need TLS.
	URL string `json:"url,omitempty"`
	// UserDNTemplate enables direct bind without a service-account search, e.g.
	// "uid={username},ou=people,dc=example,dc=org". The username is DN-escaped.
	UserDNTemplate string `json:"user_dn_template,omitempty"`
	// BindDN and BindPasswordFile optionally configure a service account for user
	// and group searches. The password is file-backed so it is loaded as []byte.
	BindDN           string `json:"bind_dn,omitempty"`
	BindPasswordFile string `json:"bind_password_file,omitempty"`
	// UserSearchBaseDN and UserFilter locate the user DN when UserDNTemplate is not
	// used. UserFilter may contain {username}, which is LDAP-filter escaped.
	UserSearchBaseDN string `json:"user_search_base_dn,omitempty"`
	UserFilter       string `json:"user_filter,omitempty"`
	// GroupSearchBaseDN and GroupFilter locate directory groups after bind.
	// GroupFilter may contain {user_dn} and {username}; both are filter-escaped.
	GroupSearchBaseDN  string `json:"group_search_base_dn,omitempty"`
	GroupFilter        string `json:"group_filter,omitempty"`
	GroupNameAttribute string `json:"group_name_attribute,omitempty"`
	EmailAttribute     string `json:"email_attribute,omitempty"`
	SessionSecretFile  string `json:"session_secret_file,omitempty"`
	SessionTTL         string `json:"session_ttl,omitempty"`
	LoginRedirect      string `json:"login_redirect,omitempty"`
	Timeout            string `json:"timeout,omitempty"`

	TenantMappings     []TenantMapping `json:"tenant_mappings,omitempty"`
	DefaultRoles       []string        `json:"default_roles,omitempty"`
	DefaultTenant      string          `json:"default_tenant,omitempty"`
	AllowDefaultTenant bool            `json:"allow_default_tenant,omitempty"`
}

// SCIM configures served SCIM 2.0 provisioning (IAM-04). Each bearer token is
// tenant-bound before any provisioning request runs, so /scim/v2 never trusts a
// tenant id supplied by the IdP payload.
type SCIM struct {
	Enabled bool        `json:"enabled,omitempty"`
	Tokens  []SCIMToken `json:"tokens,omitempty"`
}

// SCIMToken configures one IdP bearer token. TokenFile points at the raw token
// bytes; startup hashes them through internal/crypto and retains only the hash.
type SCIMToken struct {
	Name      string `json:"name,omitempty"`
	TenantID  string `json:"tenant_id,omitempty"`
	TokenFile string `json:"token_file,omitempty"`
}

// ABAC configures the served attribute-based deny overlay. The Rego module must
// declare package trstctl.abac and boolean `deny`; it may define string `reason`.
type ABAC struct {
	Enabled     bool              `json:"enabled,omitempty"`
	Module      string            `json:"module,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
}

// Breakglass always pins the CA certificate and public key used by the recovery-side
// reconciliation route. OnlineEnabled additionally binds that exact public material
// to a persisted, purpose-constrained signer handle plus an authenticated m-of-n
// operator roster for served issuance, CA rotation, and cross-signing.
type Breakglass struct {
	Enabled       bool     `json:"enabled,omitempty"`
	OnlineEnabled bool     `json:"online_enabled,omitempty"`
	CACertFile    string   `json:"ca_cert_file,omitempty"`
	PublicKeyFile string   `json:"public_key_file,omitempty"`
	TenantID      string   `json:"tenant_id,omitempty"`
	SignerHandle  string   `json:"signer_handle,omitempty"`
	Operators     []string `json:"operators,omitempty"`
	Threshold     int      `json:"threshold,omitempty"`
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

// ValidateEnabled reports the configuration problems of the SAML block as if it
// were enabled.
func (s SAML) ValidateEnabled() error { return errors.Join(s.validate()...) }

// SessionTTLDuration parses the SAML session cookie lifetime, defaulting to 12h
// when empty.
func (s SAML) SessionTTLDuration() (time.Duration, error) {
	if strings.TrimSpace(s.SessionTTL) == "" {
		return 12 * time.Hour, nil
	}
	return time.ParseDuration(s.SessionTTL)
}

// ValidateEnabled reports LDAP configuration problems as if the block were enabled.
func (l LDAP) ValidateEnabled() error { return errors.Join(l.validate()...) }

// SessionTTLDuration parses the LDAP-backed browser session lifetime.
func (l LDAP) SessionTTLDuration() (time.Duration, error) {
	if strings.TrimSpace(l.SessionTTL) == "" {
		return 12 * time.Hour, nil
	}
	return time.ParseDuration(l.SessionTTL)
}

// TimeoutDuration parses the LDAP network/search timeout.
func (l LDAP) TimeoutDuration() (time.Duration, error) {
	if strings.TrimSpace(l.Timeout) == "" {
		return 5 * time.Second, nil
	}
	return time.ParseDuration(l.Timeout)
}

// ValidateEnabled reports SCIM configuration problems as if the block were enabled.
func (s SCIM) ValidateEnabled() error { return errors.Join(s.validate()...) }

// ValidateEnabled reports ABAC configuration problems as if the block were enabled.
func (a ABAC) ValidateEnabled() error { return errors.Join(a.validate()...) }

// ValidateEnabled reports break-glass configuration problems as if the block were
// enabled.
func (b Breakglass) ValidateEnabled() error { return errors.Join(b.validate()...) }

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
	// Profile names an explicit operator-selected protocol preset. Empty preserves
	// the production posture below: every public enrollment surface remains off
	// until individually configured. "eval" is the only preset and is deliberately
	// tenant-bound; it exists so the shipped evaluation stack can expose the
	// already-served protocol implementations without hand-editing seven toggles.
	Profile string `json:"profile,omitempty"`
	// EvalTenantID is mandatory for the eval preset. A single value is copied to
	// every enabled protocol so a convenience profile cannot weaken AN-1 by
	// spraying enrollment events across implicit/default tenants.
	EvalTenantID string `json:"eval_tenant_id,omitempty"`
	// EvalSPIFFETrustDomain optionally replaces the eval preset's non-public trust
	// domain. Production/default-off configuration never consumes this value.
	EvalSPIFFETrustDomain string         `json:"eval_spiffe_trust_domain,omitempty"`
	ACME                  ProtocolToggle `json:"acme"`
	EST                   ProtocolToggle `json:"est"`
	SCEP                  ProtocolToggle `json:"scep"`
	CMP                   ProtocolToggle `json:"cmp"`
	TSA                   ProtocolToggle `json:"tsa"`
	KMIP                  KMIPProtocol   `json:"kmip"`
	// ACMEQuota caps public ACME state retained by the in-process protocol view.
	// It complements the protocol bulkhead: the bulkhead limits concurrent work,
	// while these caps bound total nonce/account/order/authz/challenge state.
	ACMEQuota ACMEQuota `json:"acme_quota,omitempty"`
	// ACMEEAB configures ACME External Account Binding (RFC 8555 §7.3.4).
	// When Required is true, /directory advertises externalAccountRequired and
	// new-account must carry an HMAC-verified binding for one configured key id.
	ACMEEAB ACMEExternalAccountBinding `json:"acme_eab,omitempty"`
	// RAKeyFile is the sealed-at-rest RSA transport identity SCEP/CMP use for CMS
	// request decryption and response protection. It is not the issuing CA key, but
	// it must survive restarts and be shared by replicas so clients that cached
	// GetCACert material can keep enrolling during rolling deploys.
	RAKeyFile string `json:"ra_key_file,omitempty"`
	// CMPClientTrustAnchorFile is the PEM bundle a CMP client's PKIMessage
	// protection identity must chain to. CMP carries that identity in the
	// message's own extraCerts, so without anchors the protection check proves
	// only that the sender signed their own message and a self-signed key pair
	// is enough to enrol. Served CMP refuses to enrol while this is unset.
	CMPClientTrustAnchorFile string `json:"cmp_client_trust_anchor_file,omitempty"`
	// CMPAllowRAEnrollment is the explicit RFC 4210 registration-authority
	// opt-in (AUD-201 follow-up H1/V22). Off (the default), the CMP mount
	// fails closed: a CSR's subject and SANs must be authorized by the
	// authenticated protection identity, so a stolen device credential can
	// renew only itself. On, an authenticated client may enroll on behalf of
	// third parties.
	CMPAllowRAEnrollment bool           `json:"cmp_allow_ra_enrollment,omitempty"`
	TSACertFile          string         `json:"tsa_cert_file,omitempty"`
	SPIFFE               SPIFFEProtocol `json:"spiffe"`
	SSH                  ProtocolToggle `json:"ssh"`
	// SCEPIntuneChallenge pins Microsoft Intune Connector challenge-signing
	// certificates. Served SCEP always wires this validator; without anchors the
	// validator fails closed rather than accepting unauthenticated CSRs.
	SCEPIntuneChallenge SCEPIntuneChallenge `json:"scep_intune_challenge,omitempty"`
}

const (
	// ProtocolProfileEval is the explicit local-evaluation protocol preset. It is
	// never selected by default and does not enable the separately gated KMIP
	// listener, which requires its own mTLS appliance material.
	ProtocolProfileEval = "eval"
	// DefaultEvalSPIFFETrustDomain is intentionally non-public and evaluation-only.
	DefaultEvalSPIFFETrustDomain = "eval.trstctl.local"
)

// Effective returns the protocol configuration the server must assemble. The
// default/empty profile is an exact copy, keeping production default-off. The
// eval profile enables every shipped enrollment/timestamp protocol against one
// explicit tenant and leaves KMIP untouched because KMIP has separate mTLS and
// key-management prerequisites.
func (p Protocols) Effective() (Protocols, error) {
	switch strings.ToLower(strings.TrimSpace(p.Profile)) {
	case "":
		return p, nil
	case ProtocolProfileEval:
		tenantID := strings.TrimSpace(p.EvalTenantID)
		if tenantID == "" {
			return Protocols{}, errors.New("protocols.eval_tenant_id is required when protocols.profile=eval (AN-1)")
		}
		p.Profile = ProtocolProfileEval
		p.ACME = ProtocolToggle{Enabled: true, TenantID: tenantID}
		p.EST = ProtocolToggle{Enabled: true, TenantID: tenantID}
		p.SCEP = ProtocolToggle{Enabled: true, TenantID: tenantID}
		p.CMP = ProtocolToggle{Enabled: true, TenantID: tenantID}
		p.TSA = ProtocolToggle{Enabled: true, TenantID: tenantID}
		p.SSH = ProtocolToggle{Enabled: true, TenantID: tenantID}
		p.SPIFFE.Enabled = true
		p.SPIFFE.TenantID = tenantID
		if trustDomain := strings.TrimSpace(p.EvalSPIFFETrustDomain); trustDomain != "" {
			p.SPIFFE.TrustDomain = trustDomain
		} else if strings.TrimSpace(p.SPIFFE.TrustDomain) == "" {
			p.SPIFFE.TrustDomain = DefaultEvalSPIFFETrustDomain
		}
		return p, nil
	default:
		return Protocols{}, fmt.Errorf("protocols.profile %q is invalid (want empty or %q)", p.Profile, ProtocolProfileEval)
	}
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

// SCEPIntuneChallenge configures the Microsoft Intune dynamic SCEP challenge
// gate. TrustAnchorsDER is runtime/test-only; operators normally use
// TrustAnchorFiles with PEM certificates.
type SCEPIntuneChallenge struct {
	TrustAnchorFiles []string `json:"trust_anchor_files,omitempty"`
	TrustAnchorsDER  [][]byte `json:"-"`
	ExpectedAudience string   `json:"expected_audience,omitempty"`
	ClockSkewSeconds int      `json:"clock_skew_seconds,omitempty"`
}

// KMIPProtocol configures the served KMIP 1.x key-management listener (KMS-02).
// KMIP is a raw mTLS TCP protocol, not an HTTP route: when enabled it binds Addr,
// presents CertFile/KeyFile, and accepts only client certificates chaining to
// ClientCAFile. TenantID is mandatory because every managed object and audit event
// the listener creates is tenant-attributed (AN-1/AN-2).
type KMIPProtocol struct {
	Enabled      bool   `json:"enabled,omitempty"`
	TenantID     string `json:"tenant_id,omitempty"`
	Addr         string `json:"addr,omitempty"`
	CertFile     string `json:"cert_file,omitempty"`
	KeyFile      string `json:"key_file,omitempty"`
	ClientCAFile string `json:"client_ca_file,omitempty"`
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
	MaxNewOrdersPerAccount     int `json:"max_new_orders_per_account,omitempty"`
	MaxNewNoncesPerSource      int `json:"max_new_nonces_per_source,omitempty"`
	MaxNewAccountsPerSource    int `json:"max_new_accounts_per_source,omitempty"`
	MaxNewOrdersPerSource      int `json:"max_new_orders_per_source,omitempty"`
	SourceWindowSeconds        int `json:"source_window_seconds,omitempty"`
	NonceTTLSeconds            int `json:"nonce_ttl_seconds,omitempty"`
	StateTTLSeconds            int `json:"state_ttl_seconds,omitempty"`
}

// ACMEExternalAccountBinding is the server-side EAB key registry for ACME account
// creation. HMAC keys are byte-backed or file-backed because they are shared MAC
// secrets (AN-8); KeyID is only the public external account key identifier.
type ACMEExternalAccountBinding struct {
	Required bool                            `json:"required,omitempty"`
	Keys     []ACMEExternalAccountBindingKey `json:"keys,omitempty"`
}

// ACMEExternalAccountBindingKey maps one ACME EAB kid to its HMAC key and to the
// scope that key authorizes. Operators may supply HMACKey directly in structured
// config/env for single-node evaluation, or HMACKeyFile for production
// file-backed secret injection.
//
// The scope fields turn a kid from a doorbell into an authorization: without them
// every account admitted by any credential is identical, and there is nothing to
// constrain what it goes on to ask for. All of them are optional and a key with
// none behaves exactly as it did before.
type ACMEExternalAccountBindingKey struct {
	KeyID       string `json:"key_id,omitempty"`
	HMACKey     []byte `json:"hmac_key,omitempty"`
	HMACKeyFile string `json:"hmac_key_file,omitempty"`
	// AllowedIdentifiers scopes which DNS names orders under this credential may
	// request. Each entry is an exact name ("api.example.com") or a wildcard
	// suffix ("*.example.com", which covers the apex and anything beneath it).
	// Empty means unscoped.
	AllowedIdentifiers []string `json:"allowed_identifiers,omitempty"`
	// MaxOrders caps how many orders may be created under this credential over
	// the process's lifetime. Zero means uncapped.
	MaxOrders int `json:"max_orders,omitempty"`
	// NotAfter closes the credential at an RFC 3339 instant. Empty means no
	// window. Certificates already issued under it are unaffected.
	NotAfter string `json:"not_after,omitempty"`
	// Disabled refuses new accounts and new orders under this credential while
	// leaving issued certificates alone. It is the configuration floor: the
	// served disable verb can switch a credential off at runtime but cannot
	// switch a config-disabled one back on.
	Disabled bool `json:"disabled,omitempty"`
}

// NotAfterTime parses the credential's validity window ("" = no window).
func (k ACMEExternalAccountBindingKey) NotAfterTime() (time.Time, error) {
	if strings.TrimSpace(k.NotAfter) == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, strings.TrimSpace(k.NotAfter))
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
	requireTenant("kmip", p.KMIP.Enabled, p.KMIP.TenantID)
	requireTenant("ssh", p.SSH.Enabled, p.SSH.TenantID)
	if (p.SCEP.Enabled || p.CMP.Enabled) && strings.TrimSpace(p.RAKeyFile) == "" {
		errs = append(errs, errors.New("protocols.ra_key_file is required when SCEP or CMP is enabled so the RA transport identity survives restart/replicas"))
	}
	if p.TSA.Enabled && strings.TrimSpace(p.TSACertFile) == "" {
		errs = append(errs, errors.New("protocols.tsa_cert_file is required when TSA is enabled so the timestamping certificate stays stable across restart/replicas"))
	}
	if p.KMIP.Enabled {
		if strings.TrimSpace(p.KMIP.CertFile) == "" {
			errs = append(errs, errors.New("protocols.kmip.cert_file is required when protocols.kmip.enabled is true"))
		}
		if strings.TrimSpace(p.KMIP.KeyFile) == "" {
			errs = append(errs, errors.New("protocols.kmip.key_file is required when protocols.kmip.enabled is true"))
		}
		if strings.TrimSpace(p.KMIP.ClientCAFile) == "" {
			errs = append(errs, errors.New("protocols.kmip.client_ca_file is required when protocols.kmip.enabled is true"))
		}
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
	Mode     string `json:"mode"`
	CertFile string `json:"cert_file"` // required when mode is file
	KeyFile  string `json:"key_file"`  // required when mode is file
	// InternalStateFile is the mode-0600 combined certificate/private-key state
	// used only by internal mode. Keeping one identity in the deployment data
	// directory lets explicitly pinned evaluation clients survive a process or
	// container restart. File mode never reads it.
	InternalStateFile string `json:"internal_state_file,omitempty"`
	// InternalTrustFile is a certificate-only PEM published by internal mode for
	// clients that need to verify the self-signed server. It must never alias the
	// combined private state file. Mount or distribute this file, never the state.
	InternalTrustFile string `json:"internal_trust_file,omitempty"`
	AllowPlaintextDev bool   `json:"allow_plaintext_dev,omitempty"`
	// MinVersion is the lowest TLS version the served listener negotiates:
	// "1.3" (the default; the credential control plane never negotiates a
	// legacy version) or "1.2", an explicit opt-in for device-enrollment fleets
	// whose stock EST/SCEP/CMP clients cap at TLS 1.2 (cisco libest does). At
	// 1.2 only AEAD cipher suites are offered. Design-partner finding DP2-036.
	MinVersion string `json:"min_version,omitempty"`
}

// AllowsTLS12 reports whether the operator lowered the served floor to TLS 1.2.
// The crypto constants stay behind internal/crypto (AN-3); configuration only
// carries the decision. Validate rejects anything but "", "1.3" and "1.2".
func (t TLS) AllowsTLS12() bool {
	return strings.TrimSpace(t.MinVersion) == "1.2"
}

// Postgres selects the bundled single-node datastore or an external cluster.
type Postgres struct {
	Mode    string `json:"mode"`     // bundled | external
	DSN     string `json:"dsn"`      // required when external
	DataDir string `json:"data_dir"` // used when bundled (the embedded data lives here)
	Port    int    `json:"port"`     // loopback port for the bundled datastore (default 5432)
	// StatementTimeout bounds every statement server-side; DR rebuild/restore
	// transactions widen it explicitly (OPS-TIMEOUTS-001). Default "60s".
	StatementTimeout string `json:"statement_timeout,omitempty"`
	// AcquireTimeout bounds how long a transaction may wait for a pooled
	// connection before failing closed with a structured 503. Default "10s".
	AcquireTimeout string `json:"acquire_timeout,omitempty"`
}

// StatementTimeoutDuration parses the statement deadline ("" = default 60s).
func (p Postgres) StatementTimeoutDuration() (time.Duration, error) {
	if p.StatementTimeout == "" {
		return 60 * time.Second, nil
	}
	return time.ParseDuration(p.StatementTimeout)
}

// AcquireTimeoutDuration parses the pool-acquire deadline ("" = default 10s).
func (p Postgres) AcquireTimeoutDuration() (time.Duration, error) {
	if p.AcquireTimeout == "" {
		return 10 * time.Second, nil
	}
	return time.ParseDuration(p.AcquireTimeout)
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
	// OwnershipAttestationCadence is how long one authenticated owner
	// attestation authorizes steady-state deployment before re-confirmation is
	// required. Empty selects 90 days.
	OwnershipAttestationCadence string `json:"ownership_attestation_cadence,omitempty"`
	// NotBeforeSkew backdates every issued certificate's NotBefore so fresh
	// certs are immediately valid at verifiers with modest clock skew
	// (OPS-CLOCKSKEW-001). Default "5m" per common CA practice; bounds 30s..1h.
	NotBeforeSkew string `json:"not_before_skew,omitempty"`
	// LeafValidity is the reference leaf lifetime the CA calendar measures a
	// parent authority's remaining horizon against, so the scheduler can warn
	// that a parent is truncating the leaves issued under it before anyone
	// notices their certificates quietly getting shorter. Default "2160h"
	// (90 days). It is a yardstick for CA-horizon alerting, never a cap on what
	// any profile issues.
	LeafValidity string `json:"leaf_validity,omitempty"`

	// MaintenanceWindows restrict when the scheduler may renew (epic D6).
	//
	// A renewal deploys to a listener and reloads a service, and there are hours
	// in every organisation's week when nobody wants that unattended — a change
	// freeze, a month-end close, a trading window. Before this the only control
	// was to switch renewal off, which trades an outage risk for an expiry risk.
	//
	// Each entry is "[Days ]HH:MM-HH:MM[ Timezone]", for example
	// "Mon,Tue,Wed,Thu,Fri 22:00-06:00 Europe/London" or "Sat,Sun 00:00-23:59".
	// A window whose end precedes its start wraps midnight, which is the shape
	// most operators actually want.
	//
	// EMPTY MEANS UNRESTRICTED, never "never". An operator who has configured no
	// windows has not asked for a freeze, and defaulting to closed would turn
	// an upgrade into a fleet-wide expiry event.
	// Parsed by the server rather than here: config stays free of dependencies
	// on the packages that consume it, and a window is only meaningful next to
	// a scheduler.
	MaintenanceWindows []string `json:"maintenance_windows,omitempty"`
}

// NotBeforeSkewDuration parses the issuance backdate window ("" = default 5m).
func (l Lifecycle) NotBeforeSkewDuration() (time.Duration, error) {
	if l.NotBeforeSkew == "" {
		return 5 * time.Minute, nil
	}
	return time.ParseDuration(l.NotBeforeSkew)
}

// RenewBeforeDuration parses the renewal threshold.
func (l Lifecycle) RenewBeforeDuration() (time.Duration, error) {
	return time.ParseDuration(l.RenewBefore)
}

// AlertBeforeDuration parses the alert threshold.
func (l Lifecycle) AlertBeforeDuration() (time.Duration, error) {
	return time.ParseDuration(l.AlertBefore)
}

func (l Lifecycle) OwnershipAttestationCadenceDuration() (time.Duration, error) {
	if l.OwnershipAttestationCadence == "" {
		return 90 * 24 * time.Hour, nil
	}
	return time.ParseDuration(l.OwnershipAttestationCadence)
}

// LeafValidityDuration parses the CA-calendar reference leaf validity
// ("" = default 90 days).
func (l Lifecycle) LeafValidityDuration() (time.Duration, error) {
	if l.LeafValidity == "" {
		return 90 * 24 * time.Hour, nil
	}
	return time.ParseDuration(l.LeafValidity)
}

// Notifications configures operator-managed notification sinks. The REST/console
// channel-authoring surface remains separate; these settings wire the normal binary
// to concrete outbox consumers at startup.
type Notifications struct {
	Slack     NotificationWebhook   `json:"slack,omitempty"`
	Teams     NotificationWebhook   `json:"teams,omitempty"`
	Email     NotificationEmail     `json:"email,omitempty"`
	SMS       NotificationSMS       `json:"sms,omitempty"`
	SIEM      NotificationSIEM      `json:"siem,omitempty"`
	PagerDuty NotificationPagerDuty `json:"pagerduty,omitempty"`
	OpsGenie  NotificationOpsGenie  `json:"opsgenie,omitempty"`
}

// NotificationWebhook configures one incoming-webhook-style channel.
type NotificationWebhook struct {
	Enabled    bool   `json:"enabled,omitempty"`
	WebhookURL string `json:"webhook_url,omitempty"`
}

// NotificationEmail configures the SMTP email channel.
type NotificationEmail struct {
	Enabled      bool     `json:"enabled,omitempty"`
	SMTPAddr     string   `json:"smtp_addr,omitempty"`
	From         string   `json:"from,omitempty"`
	To           []string `json:"to,omitempty"`
	Username     string   `json:"username,omitempty"`
	Password     []byte   `json:"password,omitempty"`
	PasswordFile string   `json:"password_file,omitempty"`
}

// NotificationSMS configures the SMS gateway channel.
type NotificationSMS struct {
	Enabled   bool     `json:"enabled,omitempty"`
	Endpoint  string   `json:"endpoint,omitempty"`
	From      string   `json:"from,omitempty"`
	To        []string `json:"to,omitempty"`
	Token     []byte   `json:"token,omitempty"`
	TokenFile string   `json:"token_file,omitempty"`
}

// NotificationSIEM configures the SIEM collector channel.
type NotificationSIEM struct {
	Enabled   bool   `json:"enabled,omitempty"`
	Endpoint  string `json:"endpoint,omitempty"`
	Token     []byte `json:"token,omitempty"`
	TokenFile string `json:"token_file,omitempty"`
	Source    string `json:"source,omitempty"`
}

// AirGap configures the no-phone-home outbound HTTP guard. When enabled, public
// destinations are denied unless the operator names an explicit host or CIDR.
type AirGap struct {
	Enabled      bool     `json:"enabled,omitempty"`
	AllowPrivate bool     `json:"allow_private,omitempty"`
	AllowHosts   []string `json:"allow_hosts,omitempty"`
	AllowCIDRs   []string `json:"allow_cidrs,omitempty"`
}

// ITSM configures outbound ticketing integrations. Requests use only these
// operator-approved bindings; they cannot supply arbitrary token refs or endpoints.
type ITSM struct {
	ServiceNow ServiceNowITSM `json:"servicenow,omitempty"`
}

// ServiceNowITSM is the ServiceNow Table API integration policy.
type ServiceNowITSM struct {
	Bindings []ServiceNowBinding `json:"bindings,omitempty"`
}

// ServiceNowBinding names one approved ServiceNow destination and credential
// reference. TokenRef is a reference such as env:TRSTCTL_SERVICENOW_TOKEN; it is
// not the token value.
type ServiceNowBinding struct {
	InstanceURL          string   `json:"instance_url,omitempty"`
	TokenRef             string   `json:"token_ref,omitempty"`
	AllowPrivateEndpoint bool     `json:"allow_private_endpoint,omitempty"`
	PrivateEgressCIDRs   []string `json:"private_egress_cidrs,omitempty"`
}

// Provider configures the Provider/MSP plane (L1). OIDC and SAML prove who an
// operator is; SCIM owns whether that identity is still active. A configured
// identity method is deliberately incomplete without its pinned verifier or
// credential file: startup fails instead of accepting a weaker substitute.
type Provider struct {
	OIDC ProviderOIDC `json:"oidc"`
	SAML ProviderSAML `json:"saml"`
	SCIM ProviderSCIM `json:"scim"`
}

// ProviderOIDC pins what a provider-operator bearer token must prove. The
// JWKS is pinned OFFLINE (file or inline): this plane must not fetch keys
// from a URL an attacker who minted the token might also control.
type ProviderOIDC struct {
	Issuer   string `json:"issuer,omitempty"`
	Audience string `json:"audience,omitempty"`
	JWKSFile string `json:"jwks_file,omitempty"`
	JWKSJSON string `json:"jwks_json,omitempty"`
	// RoleClaim names the claim carrying role values (default "roles").
	// AdminValues / OperatorValues map its entries onto the provider roles; a
	// token matching neither is refused outright — federation is not
	// enrollment, and the IdP vouching for the whole workforce must not make
	// every employee someone who can suspend customers.
	RoleClaim      string   `json:"role_claim,omitempty"`
	AdminValues    []string `json:"admin_values,omitempty"`
	OperatorValues []string `json:"operator_values,omitempty"`
	// MFAClaim (default "amr") and MFAValues (default mfa/otp/hwk/swk) decide
	// the Operator's MFA flag; the plane separately refuses mutations without
	// it.
	MFAClaim  string   `json:"mfa_claim,omitempty"`
	MFAValues []string `json:"mfa_values,omitempty"`
}

// Configured reports whether the operator pinned an IdP.
func (p ProviderOIDC) Configured() bool {
	return strings.TrimSpace(p.Issuer) != "" || strings.TrimSpace(p.Audience) != "" ||
		strings.TrimSpace(p.JWKSFile) != "" || strings.TrimSpace(p.JWKSJSON) != ""
}

// ProviderSAML configures the separate Provider-plane SAML Service Provider.
// It intentionally does not reuse the customer login session: a provider
// operator can act across customer boundaries and therefore needs its own
// cookie, role mapping, MFA proof, and signing metadata.
type ProviderSAML struct {
	Enabled           bool     `json:"enabled,omitempty"`
	EntityID          string   `json:"entity_id,omitempty"`
	MetadataURL       string   `json:"metadata_url,omitempty"`
	ACSURL            string   `json:"acs_url,omitempty"`
	IDPMetadataFile   string   `json:"idp_metadata_file,omitempty"`
	IDPMetadataXML    string   `json:"idp_metadata_xml,omitempty"`
	SessionSecretFile string   `json:"session_secret_file,omitempty"`
	SessionTTL        string   `json:"session_ttl,omitempty"`
	LoginRedirect     string   `json:"login_redirect,omitempty"`
	SubjectAttribute  string   `json:"subject_attribute,omitempty"`
	EmailAttribute    string   `json:"email_attribute,omitempty"`
	RoleAttribute     string   `json:"role_attribute,omitempty"`
	AdminValues       []string `json:"admin_values,omitempty"`
	OperatorValues    []string `json:"operator_values,omitempty"`
	MFAAttribute      string   `json:"mfa_attribute,omitempty"`
	MFAValues         []string `json:"mfa_values,omitempty"`
}

func (p ProviderSAML) SessionTTLDuration() (time.Duration, error) {
	if strings.TrimSpace(p.SessionTTL) == "" {
		return 12 * time.Hour, nil
	}
	return time.ParseDuration(p.SessionTTL)
}

// ProviderSCIM is the provider workforce directory joiner/leaver feed. Token
// bytes are loaded from files and hashed at startup; configuration never embeds
// the live bearer credential in an immutable Go string.
type ProviderSCIM struct {
	Enabled bool                `json:"enabled,omitempty"`
	Tokens  []ProviderSCIMToken `json:"tokens,omitempty"`
}

type ProviderSCIMToken struct {
	Name      string `json:"name,omitempty"`
	TokenFile string `json:"token_file,omitempty"`
}

// AttestedIssuance turns on the attestation-gated workload SVID mint (I3/F30).
//
// It existed as a Deps field with no config key at all, so the two routes it
// gates — POST /api/v1/workloads/attested-issuance and
// POST /api/v1/ssh/attested-user-certs — were registered, documented, and
// permanently 503 on every deployment. There was no operator switch: the zero
// value is what production always got, and the six attestors behind them,
// including the GitHub OIDC attestor a CI pipeline needs, were constructed by
// code no request could reach.
//
// Off by default is correct for a mint that trades a cloud attestation for a
// certificate; unreachable-when-on is not.
type AttestedIssuance struct {
	Enabled bool `json:"enabled"`
	// TrustDomain is the SPIFFE trust domain minted SVIDs belong to. Required
	// when enabled: an SVID with no trust domain names nothing.
	TrustDomain string `json:"trust_domain,omitempty"`
	// DefaultTTL and MaxTTL bound the lifetime. Empty takes the built-in
	// 10-minute default and 1-hour ceiling — attested SVIDs are short-lived
	// because the attestation they rest on is a point-in-time claim.
	DefaultTTL string `json:"default_ttl,omitempty"`
	MaxTTL     string `json:"max_ttl,omitempty"`
}

// EphemeralIssuance turns on the approval-gated F25 workload-certificate
// workflow. Trust decisions remain tenant-owned: enabled workload attester
// trust sources supply public verification material, while this process-level
// block only opts into minting and sets hard lifetime/approval bounds.
type EphemeralIssuance struct {
	Enabled           bool   `json:"enabled"`
	TrustDomain       string `json:"trust_domain,omitempty"`
	DefaultTTL        string `json:"default_ttl,omitempty"`
	MaxTTL            string `json:"max_ttl,omitempty"`
	ApprovalTTL       string `json:"approval_ttl,omitempty"`
	RequiredApprovals int    `json:"required_approvals,omitempty"`
}

// AgentBroker turns on the brokered agent-identity mint (AUD-12).
//
// Same defect as AUD-10: Deps.AgentBroker was never assigned anywhere in
// production, so POST /api/v1/broker/agent-identities returned
// ErrBrokerUnavailable on every deployment with no config key an operator could
// set. Off by default is right for a mint; unreachable when on is not.
type AgentBroker struct {
	Enabled bool `json:"enabled"`
	// TrustDomain is required when enabled — an identity with no trust domain
	// names nothing.
	TrustDomain string `json:"trust_domain,omitempty"`
	DefaultTTL  string `json:"default_ttl,omitempty"`
	MaxTTL      string `json:"max_ttl,omitempty"`
	// PolicyModule is an optional policy gate over brokered identities.
	PolicyModule string `json:"policy_module,omitempty"`
}

// PAM turns on just-in-time privileged access sessions (AUD-13).
//
// Four served routes returned ErrPAMUnavailable on every deployment because
// Deps.PAM was never assigned and there was no config key. Targets are
// deliberately NOT configured here yet: a DSN in the main config file is a
// credential in every backup of that file, and PAM's own target model resolves
// them by reference. Enabling without targets yields a working surface with
// nothing to open a session against, which is honest and safe.
type PAM struct {
	Enabled        bool   `json:"enabled"`
	DefaultTTL     string `json:"default_ttl,omitempty"`
	MaxTTL         string `json:"max_ttl,omitempty"`
	ExpiryInterval string `json:"expiry_interval,omitempty"`
}

// Reconcile configures cross-authority reconciliation rounds (C4/XREC, AUD-1).
//
// The rounds worker existed, was registered, and appeared in the runtime worker
// roster — and hit a len(Schedules)==0 guard on its first tick, then blocked for
// the life of the process. Zero rounds ever ran, no witness was ever raised, and
// the served agreement report answered "0 open witnesses" forever. A licensed
// operator saw a healthy registered worker and concluded reconciliation was
// running while nothing was ever compared.
//
// There was no config key to populate schedules. This is it.
type Reconcile struct {
	// Schedules is the set of reconciliation rounds to run. EMPTY means nothing
	// compares anything, which the served report already states as
	// collecting=false rather than letting zero witnesses read as agreement.
	Schedules []ReconcileSchedule `json:"schedules,omitempty"`
}

// ReconcileSchedule is one tenant's reconciliation round.
type ReconcileSchedule struct {
	TenantID string `json:"tenant_id"`
	// Cadence is how often a round runs, e.g. "1h".
	Cadence string `json:"cadence,omitempty"`
	// Jitter spreads rounds so a fleet of control planes does not stampede one
	// authority in the same second.
	Jitter string `json:"jitter,omitempty"`
	// Liveness is how stale an authority's digest may be before staleness is
	// itself a witness. An authority nobody collected from is not agreeing.
	Liveness    string               `json:"liveness,omitempty"`
	Authorities []ReconcileAuthority `json:"authorities,omitempty"`
}

// ReconcileAuthority names one authority in a round.
type ReconcileAuthority struct {
	AuthorityID string `json:"authority_id"`
	Liveness    string `json:"liveness,omitempty"`
}

// Telemetry configures opt-in, off-by-default usage reporting (F-telemetry).
// When Enabled is false (the default) nothing is ever sent. When enabled, the
// reporter sends only coarse, anonymized, non-PII data to Endpoint every
// Interval.
type Telemetry struct {
	Enabled        bool   `json:"enabled"`
	Endpoint       string `json:"endpoint"`
	Interval       string `json:"interval"` // Go duration, e.g. "24h"
	InstanceIDFile string `json:"instance_id_file,omitempty"`
}

// IntervalDuration parses the telemetry reporting interval.
func (t Telemetry) IntervalDuration() (time.Duration, error) {
	return time.ParseDuration(t.Interval)
}

// OTLP configures operator-owned OpenTelemetry collector export for traces and
// audit events. It is off by default and is independent from product telemetry:
// data goes only to the endpoint the operator configures.
type OTLP struct {
	Enabled     bool   `json:"enabled"`
	Endpoint    string `json:"endpoint,omitempty"`
	Insecure    bool   `json:"insecure,omitempty"`
	Token       []byte `json:"token,omitempty"`
	TokenFile   string `json:"token_file,omitempty"`
	Timeout     string `json:"timeout,omitempty"`
	QueueSize   int    `json:"queue_size,omitempty"`
	ServiceName string `json:"service_name,omitempty"`
}

// TimeoutDuration parses the per-export OTLP timeout.
func (o OTLP) TimeoutDuration() (time.Duration, error) {
	return time.ParseDuration(o.Timeout)
}

// Audit configures the event-sourced audit trail's evidence export (F9 / B5) and
// its retention lifecycle (R4.4). By default (empty Retention) the event log is
// retained indefinitely in the served audit view. When Retention is set AND
// ArchiveDir is given, a background worker enforces the served-view window:
// records older than the window are archived as signed, offline-verifiable
// bundles under ArchiveDir, then a replayable checkpoint advances the query
// floor. The underlying AN-2 event envelopes remain in the event log because
// projection rebuild, disaster recovery, and authorized privacy rewrites require
// the complete source history. SigningKeyFile is now migration-only: on upgrade,
// trstctl-signer imports that historical PEM into its sealed audit-export handle
// and deletes the plaintext. Fresh deployments never create it (AUD-63 / AN-4).
type Audit struct {
	SigningKeyFile string `json:"signing_key_file"` // legacy PEM migration path; private custody lives in trstctl-signer
	Retention      string `json:"retention"`        // Go duration; empty means an indefinite served audit view
	ArchiveDir     string `json:"archive_dir"`      // signed cold-storage bundles; required to advance the served-view retention floor
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
	// ManifestSigningKeyFile is the deployment key that signs each artifact's
	// manifest. It is deliberately NOT derived from the KEK: the whole point is
	// that a restorer sharing no secret with this deployment can still establish
	// where an artifact came from, and a KEK-derived key can only ever be checked
	// by something already holding the KEK.
	ManifestSigningKeyFile string `json:"manifest_signing_key_file,omitempty"`
	// TrustedManifestKeyFiles lists the deployment public keys whose signed
	// artifacts this deployment will restore. Empty keeps the previous behaviour
	// (signatures recorded but not required), which is what an in-place restore of
	// this deployment's own backup needs. Set it on a disaster-recovery target and
	// an artifact from an unknown deployment is refused.
	TrustedManifestKeyFiles []string `json:"trusted_manifest_key_files,omitempty"`
	AllowUnencrypted        bool     `json:"allow_unencrypted,omitempty"`
	// Directory is the full-backup directory the served DR posture reports on
	// (epic J2). Empty means the control plane reports "not configured" rather
	// than guessing a path — a guessed default would report a directory that
	// was never meant to exist as a missing backup, which is a false alarm on
	// every deployment that backs up some other way.
	Directory string `json:"directory,omitempty"`
	// DrillInterval is how often the scheduled restore drill runs (epic J2).
	// Empty uses the default; "0" disables the drill.
	//
	// Disabling is spelled explicitly rather than inferred from an absent
	// setting, because a drill that quietly never runs leaves the DR surface
	// reporting "never drilled" forever — a state indistinguishable from a
	// configuration oversight, which is exactly the confusion this surface
	// exists to remove.
	DrillInterval string `json:"drill_interval,omitempty"`
	// DrillRPO and DrillRTO are the largest measured recovery-point loss and
	// isolated-target restore time accepted without an operational alert.
	// Empty values use the explicit defaults below; "0" means every positive
	// measurement breaches the objective, not disabled alerting.
	DrillRPO string `json:"drill_rpo,omitempty"`
	DrillRTO string `json:"drill_rto,omitempty"`
}

// DrillIntervalDuration is how often the restore drill runs, and whether it runs
// at all (epic J2).
//
// Defaults to daily. A drill is not free — it creates a database, replays the
// event log into it, and drops it — so the default is the longest interval that
// still answers "could we restore what we backed up last night" before the next
// night's backup replaces the evidence.
func (b Backup) DrillIntervalDuration() (time.Duration, error) {
	if strings.TrimSpace(b.DrillInterval) == "" {
		return DefaultBackupDrillInterval, nil
	}
	return time.ParseDuration(b.DrillInterval)
}

// DefaultBackupDrillInterval is how often the restore drill runs when the
// operator sets nothing.
//
// Resolved HERE rather than in the scheduler, and that placement is the fix for
// a real bug: while the scheduler also applied a default, a zero could mean
// either "unset" or "the operator asked for no drill", the scheduler could not
// tell them apart, and "0" — documented as the way to disable — silently ran
// the drill daily instead. With the default resolved at parse time, a zero
// reaching the scheduler can only mean disabled.
const DefaultBackupDrillInterval = 24 * time.Hour

const (
	DefaultBackupDrillRPO = 24 * time.Hour
	DefaultBackupDrillRTO = time.Hour
)

// DrillObjectiveDurations parses the alert thresholds. Negative objectives are
// nonsensical and fail startup instead of silently disabling an alarm.
func (b Backup) DrillObjectiveDurations() (time.Duration, time.Duration, error) {
	parse := func(raw string, fallback time.Duration) (time.Duration, error) {
		if strings.TrimSpace(raw) == "" {
			return fallback, nil
		}
		value, err := time.ParseDuration(raw)
		if err != nil {
			return 0, err
		}
		if value < 0 {
			return 0, errors.New("recovery objective must not be negative")
		}
		return value, nil
	}
	rpo, err := parse(b.DrillRPO, DefaultBackupDrillRPO)
	if err != nil {
		return 0, 0, fmt.Errorf("drill_rpo: %w", err)
	}
	rto, err := parse(b.DrillRTO, DefaultBackupDrillRTO)
	if err != nil {
		return 0, 0, fmt.Errorf("drill_rto: %w", err)
	}
	return rpo, rto, nil
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
	// Outbox is the compatibility/default limit and the independent "other"
	// destination lane. A nil family override inherits this value, so existing
	// config files and TRSTCTL_BULKHEAD_OUTBOX_* settings retain their meaning
	// while every family still receives a distinct Pool instance.
	Outbox              BulkheadLimit  `json:"outbox"`
	OutboxExternalCA    *BulkheadLimit `json:"outbox_external_ca,omitempty"`
	OutboxConnectors    *BulkheadLimit `json:"outbox_connectors,omitempty"`
	OutboxSecrets       *BulkheadLimit `json:"outbox_secrets,omitempty"`
	OutboxSecretSync    *BulkheadLimit `json:"outbox_secret_sync,omitempty"`
	OutboxManagedKeys   *BulkheadLimit `json:"outbox_managed_keys,omitempty"`
	OutboxTransparency  *BulkheadLimit `json:"outbox_transparency,omitempty"`
	OutboxCodeSigning   *BulkheadLimit `json:"outbox_code_signing,omitempty"`
	OutboxNotifications *BulkheadLimit `json:"outbox_notifications,omitempty"`
	OutboxTenantSeal    *BulkheadLimit `json:"outbox_tenant_seal,omitempty"`
	OutboxFleet         *BulkheadLimit `json:"outbox_fleet_reissuance,omitempty"`
	OutboxAuditFeeds    *BulkheadLimit `json:"outbox_audit_feeds,omitempty"`
	Signing             BulkheadLimit  `json:"signing"`
	Query               BulkheadLimit  `json:"query"`
	Policy              BulkheadLimit  `json:"policy"`
	Protocols           BulkheadLimit  `json:"protocols"`
	// KMIP is connection-scoped: a worker is held for a whole client
	// connection, TLS handshake included, so it must never share the
	// request-scoped protocols lane (AN-7). This field was missing after the
	// lane was registered in bulkhead.DefaultConfigs(), so the production
	// config-derived set had no kmip pool and the runtime silently fell back
	// to the shared protocols pool (AUD-201 follow-up A2/V11).
	KMIP  BulkheadLimit `json:"kmip"`
	Agent BulkheadLimit `json:"agent"`
	CBOM  BulkheadLimit `json:"cbom"`
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
		case bulkhead.SubsystemKMIP:
			out.KMIP = limit
		case bulkhead.SubsystemAgent:
			out.Agent = limit
		case bulkhead.SubsystemCBOM:
			out.CBOM = limit
		}
	}
	return out
}

func (b Bulkheads) items() []bulkheadLimitItem {
	familyLimit := func(override *BulkheadLimit) BulkheadLimit {
		if override == nil {
			return b.Outbox
		}
		return *override
	}
	return []bulkheadLimitItem{
		{name: bulkhead.SubsystemAPI, limit: b.API},
		{name: bulkhead.SubsystemProjections, limit: b.Projections},
		{name: bulkhead.SubsystemOutbox, limit: b.Outbox},
		{name: bulkhead.SubsystemOutboxExternalCA, limit: familyLimit(b.OutboxExternalCA)},
		{name: bulkhead.SubsystemOutboxConnectors, limit: familyLimit(b.OutboxConnectors)},
		{name: bulkhead.SubsystemOutboxSecrets, limit: familyLimit(b.OutboxSecrets)},
		{name: bulkhead.SubsystemOutboxSecretSync, limit: familyLimit(b.OutboxSecretSync)},
		{name: bulkhead.SubsystemOutboxManagedKeys, limit: familyLimit(b.OutboxManagedKeys)},
		{name: bulkhead.SubsystemOutboxTransparency, limit: familyLimit(b.OutboxTransparency)},
		{name: bulkhead.SubsystemOutboxCodeSigning, limit: familyLimit(b.OutboxCodeSigning)},
		{name: bulkhead.SubsystemOutboxNotifications, limit: familyLimit(b.OutboxNotifications)},
		{name: bulkhead.SubsystemOutboxTenantSeal, limit: familyLimit(b.OutboxTenantSeal)},
		{name: bulkhead.SubsystemOutboxFleet, limit: familyLimit(b.OutboxFleet)},
		{name: bulkhead.SubsystemOutboxAuditFeeds, limit: familyLimit(b.OutboxAuditFeeds)},
		{name: bulkhead.SubsystemSigning, limit: b.Signing},
		{name: bulkhead.SubsystemQuery, limit: b.Query},
		{name: bulkhead.SubsystemPolicy, limit: b.Policy},
		{name: bulkhead.SubsystemProtocols, limit: b.Protocols},
		{name: bulkhead.SubsystemKMIP, limit: b.KMIP},
		{name: bulkhead.SubsystemAgent, limit: b.Agent},
		{name: bulkhead.SubsystemCBOM, limit: b.CBOM},
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
	// TenantSealLocalWrappers are operator-provisioned local custody keys that may
	// independently wrap tenant data-domain KEKs. The database stores only the
	// stable ID; paths stay in operator configuration. Multiple entries are
	// configured in the file. The environment overlay exposes one explicit entry
	// for simple deployments through TRSTCTL_TENANT_SEAL_LOCAL_WRAPPER_ID and
	// TRSTCTL_TENANT_SEAL_LOCAL_WRAPPER_FILE.
	TenantSealLocalWrappers []TenantSealLocalWrapper `json:"tenant_seal_local_wrappers,omitempty"`
	// IdempotencyResultFleetReady is the operator assertion that every writer
	// sharing this PostgreSQL database understands sealed-row-v1 and durable
	// indeterminate claims. Startup then installs the incompatible sealed-only
	// database floor after draining legacy rows. It is never inferred from one
	// process seeing zero legacy rows.
	IdempotencyResultFleetReady bool `json:"idempotency_result_fleet_ready,omitempty"`
	// SecretRotationHistoryFleetReady is the operator assertion that every old
	// process capable of reading, exporting, or writing schema-v1 scheduler runs
	// has been stopped. Startup may then replace unsafe retained error bytes with
	// a signed generation rewrite. It is never inferred from one replica's scan.
	SecretRotationHistoryFleetReady bool `json:"secret_rotation_history_fleet_ready,omitempty"`
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
	// AuthTokenTenantID pins the builtin HMAC machine-token authority to exactly
	// one tenant. The verifier secret is deployment-wide, so serving it without a
	// tenant pin would let a holder mint credentials for neighboring tenants.
	AuthTokenTenantID string `json:"auth_token_tenant_id,omitempty"`
	// AuthTokenScopes are the exact API permissions a successful builtin-token
	// exchange receives. They must be explicit; an empty grant fails closed.
	AuthTokenScopes []string `json:"auth_token_scopes,omitempty"`
	// GitleaksBin points at the pinned Gitleaks v8.27.2 binary used by the served
	// code/CI secret scan route. Empty resolves TRSTCTL_GITLEAKS_BIN, then
	// tools/bin/gitleaks, then PATH at request time.
	GitleaksBin string `json:"gitleaks_bin,omitempty"`
	// ScanRoots is the closed set of local filesystem trees the served Gitleaks
	// bridge may read. Empty means the control-plane working directory. Operators
	// mount repositories/rules beneath these roots; API callers cannot scan other
	// host or container paths merely because they hold secrets:write.
	ScanRoots []string `json:"scan_roots,omitempty"`
	// MachineAuth configures the non-token machine-auth login methods exposed by
	// POST /api/v1/secrets/login. Each entry is either tenant-pinned with tenant_id
	// or token-bound with tenant_claim; otherwise a credential could be replayed
	// across tenant headers.
	MachineAuth []MachineAuthMethod `json:"machine_auth,omitempty"`
}

// Transit configures the encryption-as-a-service keyring's durability.
// KeyringDir is where the transit keyring is sealed at rest under the
// deployment KEK (AN-8). Empty keeps the keyring in memory only — transit keys
// then do not survive a restart, and every ciphertext under them becomes
// permanently undecryptable when the process stops. Persistence also requires
// the deployment KEK (secrets.kek_file): key material is sealed at rest or it
// is not written at all.
type Transit struct {
	KeyringDir string `json:"keyring_dir,omitempty"`
}

// TenantSealLocalWrapper maps one non-secret stable reference to an existing
// local wrapper-key file. trstctl never creates this file: independent custody
// is useful only when the operator provisions and controls it separately.
type TenantSealLocalWrapper struct {
	ID   string `json:"id"`
	File string `json:"file"`
}

// MachineAuthMethod configures one served workload-login method.
type MachineAuthMethod struct {
	Name                   string   `json:"name"`
	TenantID               string   `json:"tenant_id,omitempty"`
	TenantClaim            string   `json:"tenant_claim,omitempty"`
	Issuer                 string   `json:"issuer,omitempty"`
	Audience               string   `json:"audience,omitempty"`
	JWKSFile               string   `json:"jwks_file,omitempty"`
	JWKSJSON               string   `json:"jwks_json,omitempty"`
	SubjectClaim           string   `json:"subject_claim,omitempty"`
	PrincipalPrefix        string   `json:"principal_prefix,omitempty"`
	Scopes                 []string `json:"scopes,omitempty"`
	ScopesClaim            string   `json:"scopes_claim,omitempty"`
	AllowedNamespaces      []string `json:"allowed_namespaces,omitempty"`
	AllowedServiceAccounts []string `json:"allowed_service_accounts,omitempty"`
	AllowedAccounts        []string `json:"allowed_accounts,omitempty"`
	AllowedARNs            []string `json:"allowed_arns,omitempty"`
	AllowedProjects        []string `json:"allowed_projects,omitempty"`
	AllowedAzureTenants    []string `json:"allowed_azure_tenants,omitempty"`
	STSEndpoint            string   `json:"sts_endpoint,omitempty"`
}

// AI configures the served AI / RCA / NL-query / MCP surface (SURFACE-003; F75/F76/
// F77/F78) under /api/v1/ai/* and /api/v1/mcp/*. It is OFF by default (fail closed): an
// upgrade does not silently expose an AI surface. When on, the MCP surface remains
// read-only unless MCPWriteTools is explicitly enabled. All calls are tenant-scoped
// under RLS (the tenant is the authenticated principal's, never a request field —
// AN-1), auth-gated, and rate-limited. The AI
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
	// MCPWriteTools exposes policy-gated write tools such as issue_certificate and
	// rotate_certificate. Default false keeps MCP investigation read-only/fail-closed.
	MCPWriteTools bool `json:"mcp_write_tools,omitempty"`
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
	Mode   string `json:"mode"`   // "child" (default) or "external"
	Socket string `json:"socket"` // UDS path; in external mode use this OR the mTLS fields
	// CallTimeout bounds every signer RPC that lacks a tighter caller
	// deadline, so a hung signer fails closed instead of stalling issuance
	// (OPS-TIMEOUTS-001). Default "10s"; bounds 1s..2m.
	CallTimeout    string `json:"call_timeout,omitempty"`
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
// the CA stable across restarts (R3.2 — no silent rotation). PublicCertFile is
// an optional certificate-only mirror for less-privileged clients that must not
// receive the control plane's private data volume.
type CA struct {
	CertFile       string `json:"cert_file"`
	PublicCertFile string `json:"public_cert_file,omitempty"`

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
	// PublicAddress is the exact host:port an operator should give an agent. Addr is
	// only where this process listens; a container port, Service, load balancer, or
	// reverse tunnel can publish it somewhere else. Empty is allowed, but the web
	// console then refuses to guess an install command.
	PublicAddress string `json:"public_address,omitempty"`
	// HTTPRenewalAddr is the dedicated embedded-client HTTPS renewal listener. It is
	// served only when Enabled is true, uses the same signer-custodied agent CA as the
	// gRPC channel, and requires verified agent client certificates. Empty defaults to
	// ":9444".
	HTTPRenewalAddr string `json:"http_renewal_addr,omitempty"`
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
	// ClaimableJobKinds are the estate-touching job kinds enrolled agents may claim
	// and execute (A1): connector.deploy, connector.rollback, connector.test,
	// endpoint.verify, endpoint.renew, discovery.run, revocation.probe,
	// adcs.inventory, trust.distribute, agent.upgrade, cmdb.sync.
	//
	// Empty — the default — means the job ledger is served but hands nothing out.
	// That is deliberate: a kind should be enabled when an agent-side executor for
	// it exists, and handing out work nothing can perform fills a queue while the
	// control plane's own worker stops doing it. Anything outside the allowlist is
	// dropped rather than honoured, so naming ca.issue here does not move
	// CA-adjacent effects onto a host.
	ClaimableJobKinds []string `json:"claimable_job_kinds,omitempty"`
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
		Server: Server{Addr: ":8443", TLS: TLS{
			Mode: TLSInternal, InternalStateFile: "data/tls/internal-server.pem", InternalTrustFile: "data/tls/internal-server.crt",
		}},
		Postgres: Postgres{Mode: PostgresBundled, DataDir: "data/postgres", Port: 5432},
		// The embedded event log fsyncs on a tight bounded cadence by default so a
		// single-node power loss bounds data loss to ~1s rather than nats-server's
		// ~2-minute default (RESIL-001). Replicas defaults to 0 here ("use the mode
		// default"): embedded forces 1, external uses DefaultExternalReplicas (3) for
		// HA (SPINE-004).
		NATS:       NATS{Mode: NATSEmbedded, StoreDir: "data/nats", SyncInterval: DefaultEmbeddedSyncInterval.String()},
		Log:        Log{Level: "info", Format: "json"},
		Lifecycle:  Lifecycle{RenewBefore: "720h", AlertBefore: "336h", NotBeforeSkew: "5m", OwnershipAttestationCadence: "2160h"}, // 30d renew, 14d alert, 5m issuance backdate, 90d ownership re-attestation
		Connectors: Connectors{HTTPTimeout: "15s"},
		AirGap:     AirGap{Enabled: false, AllowPrivate: true},
		// Telemetry is OFF by default (privacy-first) and ships NO default endpoint:
		// the project runs no public collector, so Validate rejects enabled+empty.
		Telemetry: Telemetry{Enabled: false, Endpoint: "", Interval: "24h", InstanceIDFile: "data/telemetry/instance-id"},
		// OTLP export is OFF by default. When enabled, it sends traces and audit
		// event metadata only to the operator's collector endpoint.
		OTLP: OTLP{Enabled: false, Timeout: "5s", QueueSize: 1024, ServiceName: "trstctl"},
		// Legacy audit PEM migration path. Fresh evidence keys live only in the
		// signer's sealed keystore; retention is indefinite by default.
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
		// Cloud/HSM managed-key custody is opt-in. Leaving it disabled keeps the
		// served managed-key routes fail-closed until an operator binds a backend.
		ManagedKeys: ManagedKeys{Enabled: false, Provider: ManagedKeyProviderAWS},
		// The signer runs as a supervised child by default (single binary); its
		// keys are sealed under the data directory so a restart preserves the CA.
		Signer: Signer{Mode: SignerChild, KeyStoreDir: "data/signer/keys", AuthSecretFile: "data/signer/sign-auth.bin", AllowCoResidentAuthorizer: true}, // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
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
		PCAS: PCAS{
			Delegation:  PCASDelegation{Enabled: false, RefreshInterval: "30s", SignerStoreDir: "data/signer/pcas"},
			Recovery:    PCASRecovery{Enabled: false, OutboxTopic: "pcas.recovery-request"},
			Federation:  PCASFederation{Enabled: false, OutboxTopic: "pcas.federation-import"},
			KEM:         PCASKEM{Enabled: false, OutboxTopic: "pcas.kem-rewrap"},
			Checkpoints: PCASCheckpoints{Enabled: false, Interval: "1m", SigningKeyHandle: "pcas-checkpoint-signer", SigningAlgorithm: string(crypto.ECDSAP256)},
			Monitors:    PCASMonitors{Enabled: false, Interval: "1m"},
			Retirement:  PCASRetirement{Enabled: false, Interval: "1m", ValidityWindow: "24h"},
			Issuer:      PCASIssuer{Enabled: false},
			Staple:      PCASStaple{Enabled: false},
		},
		// Served issuance protocols (EXC-WIRE-02). Enrollment protocols are opt-in
		// until explicitly tenant-bound. That keeps a fresh binary from exposing
		// public enrollment routes that later fail or mint into a blank tenant (AN-1).
		Protocols: Protocols{
			Profile:               "",
			EvalSPIFFETrustDomain: DefaultEvalSPIFFETrustDomain,
			ACME:                  ProtocolToggle{Enabled: false},
			EST:                   ProtocolToggle{Enabled: false},
			SCEP:                  ProtocolToggle{Enabled: false},
			CMP:                   ProtocolToggle{Enabled: false},
			TSA:                   ProtocolToggle{Enabled: false},
			KMIP:                  KMIPProtocol{Enabled: false, Addr: ":5696"},
			ACMEQuota: ACMEQuota{
				MaxNonces:                  4096,
				MaxAccounts:                2048,
				MaxPendingOrders:           4096,
				MaxPendingAuthorizations:   8192,
				MaxPendingChallenges:       24576,
				MaxPendingOrdersPerAccount: 128,
				MaxNewOrdersPerAccount:     100,
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
		data, err := os.ReadFile(path) // #nosec G304 -- the config loader reading the operator's own config file (CWE-22)
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
	applyServerAndSpineEnv(getenv, c)
	applyLifecycleEnv(getenv, &c.Lifecycle)
	setCSV(getenv, "TRSTCTL_CONNECTORS_ENABLED", &c.Connectors.Enabled)
	setString(getenv, "TRSTCTL_CONNECTORS_HTTP_TIMEOUT", &c.Connectors.HTTPTimeout)
	setCSV(getenv, "TRSTCTL_CONNECTORS_ALLOW_PRIVATE_CIDRS", &c.Connectors.AllowPrivateCIDRs)
	setBool(getenv, "TRSTCTL_CONNECTORS_ALLOW_INSECURE_HTTP", &c.Connectors.AllowInsecureHTTP)
	setNotificationEnv(getenv, &c.Notifications)
	applyCodeSigningEnv(getenv, &c.CodeSigning)
	applyProviderEnv(getenv, &c.Provider)
	setServiceNowEnv(getenv, &c.ITSM.ServiceNow)
	setBool(getenv, "TRSTCTL_AIRGAP_ENABLED", &c.AirGap.Enabled)
	setBool(getenv, "TRSTCTL_AIRGAP_ALLOW_PRIVATE", &c.AirGap.AllowPrivate)
	setCSV(getenv, "TRSTCTL_AIRGAP_ALLOW_HOSTS", &c.AirGap.AllowHosts)
	setCSV(getenv, "TRSTCTL_AIRGAP_ALLOW_CIDRS", &c.AirGap.AllowCIDRs)
	setCSV(getenv, "TRSTCTL_OUTBOUND_ENV_CREDENTIAL_REFS", &c.OutboundEnvCredentialRefs)
	setBool(getenv, "TRSTCTL_TELEMETRY_ENABLED", &c.Telemetry.Enabled)
	setString(getenv, "TRSTCTL_TELEMETRY_ENDPOINT", &c.Telemetry.Endpoint)
	setString(getenv, "TRSTCTL_TELEMETRY_INTERVAL", &c.Telemetry.Interval)
	setString(getenv, "TRSTCTL_TELEMETRY_INSTANCE_ID_FILE", &c.Telemetry.InstanceIDFile)
	setBool(getenv, "TRSTCTL_OTLP_ENABLED", &c.OTLP.Enabled)
	setString(getenv, "TRSTCTL_OTLP_ENDPOINT", &c.OTLP.Endpoint)
	setBool(getenv, "TRSTCTL_OTLP_INSECURE", &c.OTLP.Insecure)
	setBytes(getenv, "TRSTCTL_OTLP_BEARER_TOKEN", &c.OTLP.Token)
	setString(getenv, "TRSTCTL_OTLP_BEARER_TOKEN_FILE", &c.OTLP.TokenFile)
	setString(getenv, "TRSTCTL_OTLP_TIMEOUT", &c.OTLP.Timeout)
	setInt(getenv, "TRSTCTL_OTLP_QUEUE_SIZE", &c.OTLP.QueueSize)
	setString(getenv, "TRSTCTL_OTLP_SERVICE_NAME", &c.OTLP.ServiceName)
	setString(getenv, "TRSTCTL_AUDIT_SIGNING_KEY_FILE", &c.Audit.SigningKeyFile)
	setString(getenv, "TRSTCTL_AUDIT_RETENTION", &c.Audit.Retention)
	setString(getenv, "TRSTCTL_AUDIT_ARCHIVE_DIR", &c.Audit.ArchiveDir)
	setBool(getenv, "TRSTCTL_BREAKGLASS_ENABLED", &c.Breakglass.Enabled)
	setBool(getenv, "TRSTCTL_BREAKGLASS_ONLINE_ENABLED", &c.Breakglass.OnlineEnabled)
	setString(getenv, "TRSTCTL_BREAKGLASS_CA_CERT_FILE", &c.Breakglass.CACertFile)
	setString(getenv, "TRSTCTL_BREAKGLASS_PUBLIC_KEY_FILE", &c.Breakglass.PublicKeyFile)
	setString(getenv, "TRSTCTL_BREAKGLASS_TENANT_ID", &c.Breakglass.TenantID)
	setString(getenv, "TRSTCTL_BREAKGLASS_SIGNER_HANDLE", &c.Breakglass.SignerHandle)
	setCSV(getenv, "TRSTCTL_BREAKGLASS_OPERATORS", &c.Breakglass.Operators)
	setInt(getenv, "TRSTCTL_BREAKGLASS_THRESHOLD", &c.Breakglass.Threshold)
	applyPrivacyEnv(getenv, &c.Privacy)
	applyBackupEnv(getenv, &c.Backup)
	setString(getenv, "TRSTCTL_LICENSE_FILE", &c.License.File)
	setString(getenv, "TRSTCTL_LICENSE_DEPLOYMENT_ID", &c.License.DeploymentID)
	setString(getenv, "TRSTCTL_LICENSE_ENVIRONMENT", &c.License.Environment)
	setBool(getenv, "TRSTCTL_RATE_LIMIT_ENABLED", &c.RateLimit.Enabled)
	setInt(getenv, "TRSTCTL_RATE_LIMIT_REQUESTS", &c.RateLimit.Requests)
	setString(getenv, "TRSTCTL_RATE_LIMIT_WINDOW", &c.RateLimit.Window)
	applyBulkheadEnv(getenv, &c.Bulkheads)
	setBool(getenv, "TRSTCTL_MIGRATE_AUTO", &c.Migrate.Auto)
	setString(getenv, "TRSTCTL_SECRETS_KEK_FILE", &c.Secrets.KEKFile)
	setBool(getenv, "TRSTCTL_SECRETS_ENABLE_API", &c.Secrets.EnableAPI)
	setString(getenv, "TRSTCTL_SECRETS_AUTH_SECRET_FILE", &c.Secrets.AuthSecretFile)
	setString(getenv, "TRSTCTL_SECRETS_AUTH_TOKEN_TENANT_ID", &c.Secrets.AuthTokenTenantID)
	setCSV(getenv, "TRSTCTL_SECRETS_AUTH_TOKEN_SCOPES", &c.Secrets.AuthTokenScopes)
	setString(getenv, "TRSTCTL_SECRETS_GITLEAKS_BIN", &c.Secrets.GitleaksBin)
	setCSV(getenv, "TRSTCTL_SECRETS_SCAN_ROOTS", &c.Secrets.ScanRoots)
	setString(getenv, "TRSTCTL_TRANSIT_KEYRING_DIR", &c.Transit.KeyringDir)
	setBool(getenv, "TRSTCTL_IDEMPOTENCY_RESULT_FLEET_READY", &c.Secrets.IdempotencyResultFleetReady)
	setBool(getenv, "TRSTCTL_SECRET_ROTATION_HISTORY_FLEET_READY", &c.Secrets.SecretRotationHistoryFleetReady)
	localWrapperID := getenv("TRSTCTL_TENANT_SEAL_LOCAL_WRAPPER_ID")
	localWrapperFile := getenv("TRSTCTL_TENANT_SEAL_LOCAL_WRAPPER_FILE")
	if localWrapperID != "" || localWrapperFile != "" {
		c.Secrets.TenantSealLocalWrappers = []TenantSealLocalWrapper{{
			ID: localWrapperID, File: localWrapperFile,
		}}
	}
	applyManagedKeysEnv(getenv, &c.ManagedKeys)
	// Served AI / RCA / NL-query / MCP surface (SURFACE-003). OFF by default (fail
	// closed). The AI model stays air-gapped/opt-in regardless of these flags.
	setBool(getenv, "TRSTCTL_AI_ENABLE_API", &c.AI.EnableAPI)
	setString(getenv, "TRSTCTL_AI_MCP_IDENTITY", &c.AI.MCPIdentity)
	setBool(getenv, "TRSTCTL_AI_MCP_WRITE_TOOLS", &c.AI.MCPWriteTools)
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
	setString(getenv, "TRSTCTL_SIGNER_CALL_TIMEOUT", &c.Signer.CallTimeout)
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
	setString(getenv, "TRSTCTL_CA_PUBLIC_CERT_FILE", &c.CA.PublicCertFile)
	// Regulated CA-governance posture (PKIGOV-003): the single coherent switch and
	// its declared FIPS requirement, operator-settable via env.
	setString(getenv, "TRSTCTL_CA_GOVERNANCE_MODE", &c.CA.GovernanceMode)
	setBool(getenv, "TRSTCTL_CA_REQUIRE_FIPS", &c.CA.RequireFIPS)
	applyAgentChannelEnv(getenv, &c.AgentChannel)
	applyWorkloadIdentityEnv(getenv, &c.AttestedIssuance)
	applyEphemeralIssuanceEnv(getenv, &c.EphemeralIssuance)
	// Served issuance protocols (EXC-WIRE-02): per-protocol enable + tenant binding.
	applyProtocolsEnv(getenv, &c.Protocols)
	applyAuthEnv(getenv, &c.Auth)
	// Served WASM-plugin surface (EXC-WIRE-05; ARCH-007/SUPPLY-004). Off by default;
	// when enabled the binary loads + provenance-verifies connector plugins from the
	// directory against the trusted keys, failing closed on an unverified module.
	setBool(getenv, "TRSTCTL_PLUGINS_ENABLED", &c.Plugins.Enabled)
	setString(getenv, "TRSTCTL_PLUGINS_DIR", &c.Plugins.Dir)
	setString(getenv, "TRSTCTL_PLUGINS_CA_DIR", &c.Plugins.CADir)
	setString(getenv, "TRSTCTL_PLUGINS_DNS_DIR", &c.Plugins.DNSDir)
	setString(getenv, "TRSTCTL_PLUGINS_CONNECTOR_DIR", &c.Plugins.ConnectorDir)
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
	setBool(getenv, "TRSTCTL_FEDERATION_ENABLED", &c.Federation.Enabled)
	setString(getenv, "TRSTCTL_FEDERATION_CLUSTER_ID", &c.Federation.ClusterID)
	setString(getenv, "TRSTCTL_FEDERATION_REGION", &c.Federation.Region)
	setString(getenv, "TRSTCTL_FEDERATION_INTERVAL", &c.Federation.Interval)
	setString(getenv, "TRSTCTL_FEDERATION_RPO", &c.Federation.RPO)
	setString(getenv, "TRSTCTL_FEDERATION_RTO", &c.Federation.RTO)
	peer := FederationPeer{}
	setString(getenv, "TRSTCTL_FEDERATION_PEER_ID", &peer.ID)
	setString(getenv, "TRSTCTL_FEDERATION_PEER_REGION", &peer.Region)
	setString(getenv, "TRSTCTL_FEDERATION_PEER_NATS_URL", &peer.NATSURL)
	if peer.ID != "" || peer.Region != "" || peer.NATSURL != "" {
		c.Federation.Peers = []FederationPeer{peer}
	}
	applyPCASEnv(getenv, &c.PCAS)
}

// applyWorkloadIdentityEnv exposes the attestation-gated SVID mint to the same
// container-first deployment model as the served protocol endpoints. The mint
// remains off by default; operators must opt in and name the trust domain and
// lifetime boundaries explicitly.
func applyWorkloadIdentityEnv(getenv func(string) string, a *AttestedIssuance) {
	setBool(getenv, "TRSTCTL_ATTESTED_ISSUANCE_ENABLED", &a.Enabled)
	setString(getenv, "TRSTCTL_ATTESTED_ISSUANCE_TRUST_DOMAIN", &a.TrustDomain)
	setString(getenv, "TRSTCTL_ATTESTED_ISSUANCE_DEFAULT_TTL", &a.DefaultTTL)
	setString(getenv, "TRSTCTL_ATTESTED_ISSUANCE_MAX_TTL", &a.MaxTTL)
}

func applyEphemeralIssuanceEnv(getenv func(string) string, e *EphemeralIssuance) {
	setBool(getenv, "TRSTCTL_EPHEMERAL_ISSUANCE_ENABLED", &e.Enabled)
	setString(getenv, "TRSTCTL_EPHEMERAL_ISSUANCE_TRUST_DOMAIN", &e.TrustDomain)
	setString(getenv, "TRSTCTL_EPHEMERAL_ISSUANCE_DEFAULT_TTL", &e.DefaultTTL)
	setString(getenv, "TRSTCTL_EPHEMERAL_ISSUANCE_MAX_TTL", &e.MaxTTL)
	setString(getenv, "TRSTCTL_EPHEMERAL_ISSUANCE_APPROVAL_TTL", &e.ApprovalTTL)
	setInt(getenv, "TRSTCTL_EPHEMERAL_ISSUANCE_REQUIRED_APPROVALS", &e.RequiredApprovals)
}

func applyLifecycleEnv(getenv func(string) string, lifecycle *Lifecycle) {
	setString(getenv, "TRSTCTL_LIFECYCLE_RENEW_BEFORE", &lifecycle.RenewBefore)
	setString(getenv, "TRSTCTL_LIFECYCLE_ALERT_BEFORE", &lifecycle.AlertBefore)
	setString(getenv, "TRSTCTL_LIFECYCLE_NOT_BEFORE_SKEW", &lifecycle.NotBeforeSkew)
	setString(getenv, "TRSTCTL_LIFECYCLE_LEAF_VALIDITY", &lifecycle.LeafValidity)
	setString(getenv, "TRSTCTL_LIFECYCLE_OWNERSHIP_ATTESTATION_CADENCE", &lifecycle.OwnershipAttestationCadence)
}

func applyProviderEnv(getenv func(string) string, provider *Provider) {
	setString(getenv, "TRSTCTL_PROVIDER_OIDC_ISSUER", &provider.OIDC.Issuer)
	setString(getenv, "TRSTCTL_PROVIDER_OIDC_AUDIENCE", &provider.OIDC.Audience)
	setString(getenv, "TRSTCTL_PROVIDER_OIDC_JWKS_FILE", &provider.OIDC.JWKSFile)
	setString(getenv, "TRSTCTL_PROVIDER_OIDC_JWKS_JSON", &provider.OIDC.JWKSJSON)
	setString(getenv, "TRSTCTL_PROVIDER_OIDC_ROLE_CLAIM", &provider.OIDC.RoleClaim)
	setCSV(getenv, "TRSTCTL_PROVIDER_OIDC_ADMIN_VALUES", &provider.OIDC.AdminValues)
	setCSV(getenv, "TRSTCTL_PROVIDER_OIDC_OPERATOR_VALUES", &provider.OIDC.OperatorValues)
	setString(getenv, "TRSTCTL_PROVIDER_OIDC_MFA_CLAIM", &provider.OIDC.MFAClaim)
	setCSV(getenv, "TRSTCTL_PROVIDER_OIDC_MFA_VALUES", &provider.OIDC.MFAValues)
	setBool(getenv, "TRSTCTL_PROVIDER_SAML_ENABLED", &provider.SAML.Enabled)
	setString(getenv, "TRSTCTL_PROVIDER_SAML_ENTITY_ID", &provider.SAML.EntityID)
	setString(getenv, "TRSTCTL_PROVIDER_SAML_METADATA_URL", &provider.SAML.MetadataURL)
	setString(getenv, "TRSTCTL_PROVIDER_SAML_ACS_URL", &provider.SAML.ACSURL)
	setString(getenv, "TRSTCTL_PROVIDER_SAML_IDP_METADATA_FILE", &provider.SAML.IDPMetadataFile)
	setString(getenv, "TRSTCTL_PROVIDER_SAML_IDP_METADATA_XML", &provider.SAML.IDPMetadataXML)
	setString(getenv, "TRSTCTL_PROVIDER_SAML_SESSION_SECRET_FILE", &provider.SAML.SessionSecretFile)
	setString(getenv, "TRSTCTL_PROVIDER_SAML_SESSION_TTL", &provider.SAML.SessionTTL)
	setString(getenv, "TRSTCTL_PROVIDER_SAML_LOGIN_REDIRECT", &provider.SAML.LoginRedirect)
	setString(getenv, "TRSTCTL_PROVIDER_SAML_SUBJECT_ATTRIBUTE", &provider.SAML.SubjectAttribute)
	setString(getenv, "TRSTCTL_PROVIDER_SAML_EMAIL_ATTRIBUTE", &provider.SAML.EmailAttribute)
	setString(getenv, "TRSTCTL_PROVIDER_SAML_ROLE_ATTRIBUTE", &provider.SAML.RoleAttribute)
	setCSV(getenv, "TRSTCTL_PROVIDER_SAML_ADMIN_VALUES", &provider.SAML.AdminValues)
	setCSV(getenv, "TRSTCTL_PROVIDER_SAML_OPERATOR_VALUES", &provider.SAML.OperatorValues)
	setString(getenv, "TRSTCTL_PROVIDER_SAML_MFA_ATTRIBUTE", &provider.SAML.MFAAttribute)
	setCSV(getenv, "TRSTCTL_PROVIDER_SAML_MFA_VALUES", &provider.SAML.MFAValues)
	setBool(getenv, "TRSTCTL_PROVIDER_SCIM_ENABLED", &provider.SCIM.Enabled)
	token := ProviderSCIMToken{}
	setString(getenv, "TRSTCTL_PROVIDER_SCIM_TOKEN_NAME", &token.Name)
	setString(getenv, "TRSTCTL_PROVIDER_SCIM_TOKEN_FILE", &token.TokenFile)
	if token.Name != "" || token.TokenFile != "" {
		provider.SCIM.Tokens = []ProviderSCIMToken{token}
	}
}

// applyAgentChannelEnv resolves the served agent steady-state mTLS gRPC channel
// (WIRE-004 / OPS-005).
//
// Its own named stage because applyEnv is at the startup-hotspot line budget,
// and that budget is not bookkeeping: applyEnv is where every subsystem's
// environment is resolved, and a function nobody can hold in their head is
// where a precedence bug hides.
func applyAgentChannelEnv(getenv func(string) string, a *AgentChannel) {
	setBool(getenv, "TRSTCTL_AGENT_CHANNEL_ENABLED", &a.Enabled)
	setString(getenv, "TRSTCTL_AGENT_CHANNEL_ADDR", &a.Addr)
	setString(getenv, "TRSTCTL_AGENT_CHANNEL_PUBLIC_ADDRESS", &a.PublicAddress)
	setString(getenv, "TRSTCTL_AGENT_CHANNEL_HTTP_RENEWAL_ADDR", &a.HTTPRenewalAddr)
	setString(getenv, "TRSTCTL_AGENT_CHANNEL_SERVER_NAME", &a.ServerName)
	setString(getenv, "TRSTCTL_AGENT_CHANNEL_CA_CERT_FILE", &a.CACertFile)
	setString(getenv, "TRSTCTL_AGENT_CHANNEL_HEARTBEAT_INTERVAL", &a.HeartbeatInterval)
	// The claimable-job allowlist was the ONE AgentChannel field with no env key,
	// so a container deployment could enable the channel and had no way to let an
	// agent claim anything — the ledger is served, hands nothing out, and the
	// enrolled agent idles while every surface looks healthy. Every sibling above
	// is env-settable; this closes the gap rather than leaving a compose file to
	// set a variable nothing reads.
	setCSV(getenv, "TRSTCTL_AGENT_CHANNEL_CLAIMABLE_JOB_KINDS", &a.ClaimableJobKinds)
}

func applyServerAndSpineEnv(getenv func(string) string, c *Config) {
	setString(getenv, "TRSTCTL_SERVER_ADDR", &c.Server.Addr)
	setString(getenv, "TRSTCTL_SERVER_TLS_MODE", &c.Server.TLS.Mode)
	setString(getenv, "TRSTCTL_SERVER_TLS_CERT_FILE", &c.Server.TLS.CertFile)
	setString(getenv, "TRSTCTL_SERVER_TLS_KEY_FILE", &c.Server.TLS.KeyFile)
	setString(getenv, "TRSTCTL_SERVER_TLS_INTERNAL_STATE_FILE", &c.Server.TLS.InternalStateFile)
	setString(getenv, "TRSTCTL_SERVER_TLS_INTERNAL_TRUST_FILE", &c.Server.TLS.InternalTrustFile)
	setBool(getenv, "TRSTCTL_DEV_ALLOW_PLAINTEXT", &c.Server.TLS.AllowPlaintextDev)
	setString(getenv, "TRSTCTL_SERVER_TLS_MIN_VERSION", &c.Server.TLS.MinVersion)
	setCSV(getenv, "TRSTCTL_CORS_ALLOWED_ORIGINS", &c.Server.CORSAllowedOrigins)
	setString(getenv, "TRSTCTL_POSTGRES_MODE", &c.Postgres.Mode)
	setString(getenv, "TRSTCTL_POSTGRES_DSN", &c.Postgres.DSN)
	setString(getenv, "TRSTCTL_POSTGRES_STATEMENT_TIMEOUT", &c.Postgres.StatementTimeout)
	setString(getenv, "TRSTCTL_POSTGRES_ACQUIRE_TIMEOUT", &c.Postgres.AcquireTimeout)
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
}

func applyPCASEnv(getenv func(string) string, p *PCAS) {
	setBool(getenv, "TRSTCTL_PCAS_DELEGATION_ENABLED", &p.Delegation.Enabled)
	setString(getenv, "TRSTCTL_PCAS_DELEGATION_REFRESH_INTERVAL", &p.Delegation.RefreshInterval)
	setString(getenv, "TRSTCTL_PCAS_DELEGATION_SIGNER_STORE_DIR", &p.Delegation.SignerStoreDir)
	setBool(getenv, "TRSTCTL_PCAS_RECOVERY_ENABLED", &p.Recovery.Enabled)
	setString(getenv, "TRSTCTL_PCAS_RECOVERY_OUTBOX_TOPIC", &p.Recovery.OutboxTopic)
	setBool(getenv, "TRSTCTL_PCAS_FEDERATION_ENABLED", &p.Federation.Enabled)
	setString(getenv, "TRSTCTL_PCAS_FEDERATION_OUTBOX_TOPIC", &p.Federation.OutboxTopic)
	setBool(getenv, "TRSTCTL_PCAS_KEM_ENABLED", &p.KEM.Enabled)
	setString(getenv, "TRSTCTL_PCAS_KEM_OUTBOX_TOPIC", &p.KEM.OutboxTopic)
	setBool(getenv, "TRSTCTL_PCAS_CHECKPOINTS_ENABLED", &p.Checkpoints.Enabled)
	setString(getenv, "TRSTCTL_PCAS_CHECKPOINTS_INTERVAL", &p.Checkpoints.Interval)
	setString(getenv, "TRSTCTL_PCAS_CHECKPOINTS_SIGNING_KEY_HANDLE", &p.Checkpoints.SigningKeyHandle)
	setString(getenv, "TRSTCTL_PCAS_CHECKPOINTS_SIGNING_ALGORITHM", &p.Checkpoints.SigningAlgorithm)
	setBool(getenv, "TRSTCTL_PCAS_MONITORS_ENABLED", &p.Monitors.Enabled)
	setString(getenv, "TRSTCTL_PCAS_MONITORS_INTERVAL", &p.Monitors.Interval)
	setBool(getenv, "TRSTCTL_PCAS_RETIREMENT_ENABLED", &p.Retirement.Enabled)
	setString(getenv, "TRSTCTL_PCAS_RETIREMENT_INTERVAL", &p.Retirement.Interval)
	setString(getenv, "TRSTCTL_PCAS_RETIREMENT_VALIDITY_WINDOW", &p.Retirement.ValidityWindow)
	setBool(getenv, "TRSTCTL_PCAS_ISSUER_ENABLED", &p.Issuer.Enabled)
	setBool(getenv, "TRSTCTL_PCAS_STAPLE_ENABLED", &p.Staple.Enabled)
}

func applyManagedKeysEnv(getenv func(string) string, m *ManagedKeys) {
	setBool(getenv, "TRSTCTL_MANAGED_KEYS_ENABLED", &m.Enabled)
	setString(getenv, "TRSTCTL_MANAGED_KEYS_PROVIDER", &m.Provider)
	setString(getenv, "TRSTCTL_MANAGED_KEYS_AWS_REGION", &m.AWS.Region)
	setString(getenv, "TRSTCTL_MANAGED_KEYS_AWS_ENDPOINT", &m.AWS.Endpoint)
	setBool(getenv, "TRSTCTL_MANAGED_KEYS_AWS_ALLOW_INSECURE_LOOPBACK", &m.AWS.AllowInsecureLoopback)
	setString(getenv, "TRSTCTL_MANAGED_KEYS_AWS_ACCESS_KEY_ID", &m.AWS.AccessKeyID)
	setBytes(getenv, "TRSTCTL_MANAGED_KEYS_AWS_SECRET_ACCESS_KEY", &m.AWS.SecretAccessKey)
	setString(getenv, "TRSTCTL_MANAGED_KEYS_AWS_SECRET_ACCESS_KEY_FILE", &m.AWS.SecretAccessKeyFile)
	setBytes(getenv, "TRSTCTL_MANAGED_KEYS_AWS_SESSION_TOKEN", &m.AWS.SessionToken)
	setString(getenv, "TRSTCTL_MANAGED_KEYS_AWS_SESSION_TOKEN_FILE", &m.AWS.SessionTokenFile)
	setCSV(getenv, "TRSTCTL_MANAGED_KEYS_AWS_PRIVATE_EGRESS_CIDRS", &m.AWS.PrivateEgressCIDRs)
	setString(getenv, "TRSTCTL_MANAGED_KEYS_AZURE_VAULT_URL", &m.Azure.VaultURL)
	setString(getenv, "TRSTCTL_MANAGED_KEYS_AZURE_ENDPOINT", &m.Azure.Endpoint)
	setBool(getenv, "TRSTCTL_MANAGED_KEYS_AZURE_ALLOW_INSECURE_LOOPBACK", &m.Azure.AllowInsecureLoopback)
	setBytes(getenv, "TRSTCTL_MANAGED_KEYS_AZURE_BEARER_TOKEN", &m.Azure.BearerToken)
	setString(getenv, "TRSTCTL_MANAGED_KEYS_AZURE_BEARER_TOKEN_FILE", &m.Azure.BearerTokenFile)
	setCSV(getenv, "TRSTCTL_MANAGED_KEYS_AZURE_PRIVATE_EGRESS_CIDRS", &m.Azure.PrivateEgressCIDRs)
	setString(getenv, "TRSTCTL_MANAGED_KEYS_GCP_PARENT", &m.GCP.Parent)
	setString(getenv, "TRSTCTL_MANAGED_KEYS_GCP_ENDPOINT", &m.GCP.Endpoint)
	setBool(getenv, "TRSTCTL_MANAGED_KEYS_GCP_ALLOW_INSECURE_LOOPBACK", &m.GCP.AllowInsecureLoopback)
	setBytes(getenv, "TRSTCTL_MANAGED_KEYS_GCP_BEARER_TOKEN", &m.GCP.BearerToken)
	setString(getenv, "TRSTCTL_MANAGED_KEYS_GCP_BEARER_TOKEN_FILE", &m.GCP.BearerTokenFile)
	setCSV(getenv, "TRSTCTL_MANAGED_KEYS_GCP_PRIVATE_EGRESS_CIDRS", &m.GCP.PrivateEgressCIDRs)
	setString(getenv, "TRSTCTL_MANAGED_KEYS_PKCS11_MODULE_PATH", &m.PKCS11.ModulePath)
	setString(getenv, "TRSTCTL_MANAGED_KEYS_PKCS11_TOKEN_LABEL", &m.PKCS11.TokenLabel)
	setBytes(getenv, "TRSTCTL_MANAGED_KEYS_PKCS11_USER_PIN", &m.PKCS11.UserPIN)
	setString(getenv, "TRSTCTL_MANAGED_KEYS_PKCS11_USER_PIN_FILE", &m.PKCS11.UserPINFile)
	setString(getenv, "TRSTCTL_MANAGED_KEYS_PKCS11_KEY_LABEL_PREFIX", &m.PKCS11.KeyLabelPrefix)
	setString(getenv, "TRSTCTL_MANAGED_KEYS_TPM2_PATH", &m.TPM2.Path)
	setBytes(getenv, "TRSTCTL_MANAGED_KEYS_TPM2_OWNER_AUTH", &m.TPM2.OwnerAuth)
	setString(getenv, "TRSTCTL_MANAGED_KEYS_TPM2_OWNER_AUTH_FILE", &m.TPM2.OwnerAuthFile)
	setBytes(getenv, "TRSTCTL_MANAGED_KEYS_TPM2_KEY_AUTH", &m.TPM2.KeyAuth)
	setString(getenv, "TRSTCTL_MANAGED_KEYS_TPM2_KEY_AUTH_FILE", &m.TPM2.KeyAuthFile)
	if raw := strings.TrimSpace(getenv("TRSTCTL_MANAGED_KEYS_TPM2_PERSISTENT_HANDLE_BASE")); raw != "" {
		if parsed, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(raw), "0x"), 16, 32); err == nil {
			m.TPM2.PersistentHandleBase = uint32(parsed)
		}
	}
	setString(getenv, "TRSTCTL_MANAGED_KEYS_YUBIHSM2_MODULE_PATH", &m.YubiHSM2.ModulePath)
	setString(getenv, "TRSTCTL_MANAGED_KEYS_YUBIHSM2_TOKEN_LABEL", &m.YubiHSM2.TokenLabel)
	setBytes(getenv, "TRSTCTL_MANAGED_KEYS_YUBIHSM2_USER_PIN", &m.YubiHSM2.UserPIN)
	setString(getenv, "TRSTCTL_MANAGED_KEYS_YUBIHSM2_USER_PIN_FILE", &m.YubiHSM2.UserPINFile)
	setString(getenv, "TRSTCTL_MANAGED_KEYS_YUBIHSM2_KEY_LABEL_PREFIX", &m.YubiHSM2.KeyLabelPrefix)
}

// applyAuthEnv overlays browser-auth environment knobs. The structured
// TenantMappings tables are file-only (lists of objects); scalar knobs overlay from
// the environment like the rest of the config.
func applyAuthEnv(getenv func(string) string, a *Auth) {
	setBool(getenv, "TRSTCTL_AUTH_OIDC_ENABLED", &a.OIDC.Enabled)
	setString(getenv, "TRSTCTL_AUTH_OIDC_ISSUER", &a.OIDC.Issuer)
	setBool(getenv, "TRSTCTL_AUTH_OIDC_AUTHORIZATION_RESPONSE_ISS_PARAMETER_SUPPORTED", &a.OIDC.AuthorizationResponseIssParamSupported)
	setString(getenv, "TRSTCTL_AUTH_OIDC_CLIENT_ID", &a.OIDC.ClientID)
	setJSONBytes(getenv, "TRSTCTL_AUTH_OIDC_CLIENT_SECRET", &a.OIDC.ClientSecret)
	setString(getenv, "TRSTCTL_AUTH_OIDC_CLIENT_SECRET_TENANT", &a.OIDC.ClientSecretTenant)
	setString(getenv, "TRSTCTL_AUTH_OIDC_CLIENT_SECRET_REF", &a.OIDC.ClientSecretRef)
	setString(getenv, "TRSTCTL_AUTH_OIDC_AUTH_ENDPOINT", &a.OIDC.AuthEndpoint)
	setString(getenv, "TRSTCTL_AUTH_OIDC_TOKEN_ENDPOINT", &a.OIDC.TokenEndpoint)
	setString(getenv, "TRSTCTL_AUTH_OIDC_REDIRECT_URI", &a.OIDC.RedirectURI)
	setString(getenv, "TRSTCTL_AUTH_OIDC_JWKS_FILE", &a.OIDC.JWKSFile)
	setString(getenv, "TRSTCTL_AUTH_OIDC_JWKS_JSON", &a.OIDC.JWKSJSON)
	setString(getenv, "TRSTCTL_AUTH_OIDC_SESSION_SECRET_FILE", &a.OIDC.SessionSecretFile)
	setString(getenv, "TRSTCTL_AUTH_OIDC_SESSION_TTL", &a.OIDC.SessionTTL)
	setString(getenv, "TRSTCTL_AUTH_OIDC_LOGIN_REDIRECT", &a.OIDC.LoginRedirect)
	setString(getenv, "TRSTCTL_AUTH_OIDC_TENANT_CLAIM", &a.OIDC.TenantClaim)
	setString(getenv, "TRSTCTL_AUTH_OIDC_GROUPS_CLAIM", &a.OIDC.GroupsClaim)
	setBool(getenv, "TRSTCTL_AUTH_OIDC_CLAIM_IS_TENANT", &a.OIDC.ClaimIsTenant)
	setString(getenv, "TRSTCTL_AUTH_OIDC_DEFAULT_TENANT", &a.OIDC.DefaultTenant)
	setBool(getenv, "TRSTCTL_AUTH_OIDC_ALLOW_DEFAULT_TENANT", &a.OIDC.AllowDefaultTenant)
	setCSV(getenv, "TRSTCTL_AUTH_OIDC_DEFAULT_ROLES", &a.OIDC.DefaultRoles)

	setBool(getenv, "TRSTCTL_AUTH_SAML_ENABLED", &a.SAML.Enabled)
	setString(getenv, "TRSTCTL_AUTH_SAML_ENTITY_ID", &a.SAML.EntityID)
	setString(getenv, "TRSTCTL_AUTH_SAML_METADATA_URL", &a.SAML.MetadataURL)
	setString(getenv, "TRSTCTL_AUTH_SAML_ACS_URL", &a.SAML.ACSURL)
	setString(getenv, "TRSTCTL_AUTH_SAML_IDP_METADATA_FILE", &a.SAML.IDPMetadataFile)
	setString(getenv, "TRSTCTL_AUTH_SAML_IDP_METADATA_XML", &a.SAML.IDPMetadataXML)
	setString(getenv, "TRSTCTL_AUTH_SAML_SESSION_SECRET_FILE", &a.SAML.SessionSecretFile)
	setString(getenv, "TRSTCTL_AUTH_SAML_SESSION_TTL", &a.SAML.SessionTTL)
	setString(getenv, "TRSTCTL_AUTH_SAML_LOGIN_REDIRECT", &a.SAML.LoginRedirect)
	setString(getenv, "TRSTCTL_AUTH_SAML_SUBJECT_ATTRIBUTE", &a.SAML.SubjectAttribute)
	setString(getenv, "TRSTCTL_AUTH_SAML_EMAIL_ATTRIBUTE", &a.SAML.EmailAttribute)
	setString(getenv, "TRSTCTL_AUTH_SAML_TENANT_CLAIM", &a.SAML.TenantClaim)
	setString(getenv, "TRSTCTL_AUTH_SAML_GROUPS_CLAIM", &a.SAML.GroupsClaim)
	setBool(getenv, "TRSTCTL_AUTH_SAML_CLAIM_IS_TENANT", &a.SAML.ClaimIsTenant)
	setString(getenv, "TRSTCTL_AUTH_SAML_DEFAULT_TENANT", &a.SAML.DefaultTenant)
	setBool(getenv, "TRSTCTL_AUTH_SAML_ALLOW_DEFAULT_TENANT", &a.SAML.AllowDefaultTenant)
	setCSV(getenv, "TRSTCTL_AUTH_SAML_DEFAULT_ROLES", &a.SAML.DefaultRoles)

	setBool(getenv, "TRSTCTL_AUTH_LDAP_ENABLED", &a.LDAP.Enabled)
	setString(getenv, "TRSTCTL_AUTH_LDAP_URL", &a.LDAP.URL)
	setString(getenv, "TRSTCTL_AUTH_LDAP_USER_DN_TEMPLATE", &a.LDAP.UserDNTemplate)
	setString(getenv, "TRSTCTL_AUTH_LDAP_BIND_DN", &a.LDAP.BindDN)
	setString(getenv, "TRSTCTL_AUTH_LDAP_BIND_PASSWORD_FILE", &a.LDAP.BindPasswordFile)
	setString(getenv, "TRSTCTL_AUTH_LDAP_USER_SEARCH_BASE_DN", &a.LDAP.UserSearchBaseDN)
	setString(getenv, "TRSTCTL_AUTH_LDAP_USER_FILTER", &a.LDAP.UserFilter)
	setString(getenv, "TRSTCTL_AUTH_LDAP_GROUP_SEARCH_BASE_DN", &a.LDAP.GroupSearchBaseDN)
	setString(getenv, "TRSTCTL_AUTH_LDAP_GROUP_FILTER", &a.LDAP.GroupFilter)
	setString(getenv, "TRSTCTL_AUTH_LDAP_GROUP_NAME_ATTRIBUTE", &a.LDAP.GroupNameAttribute)
	setString(getenv, "TRSTCTL_AUTH_LDAP_EMAIL_ATTRIBUTE", &a.LDAP.EmailAttribute)
	setString(getenv, "TRSTCTL_AUTH_LDAP_SESSION_SECRET_FILE", &a.LDAP.SessionSecretFile)
	setString(getenv, "TRSTCTL_AUTH_LDAP_SESSION_TTL", &a.LDAP.SessionTTL)
	setString(getenv, "TRSTCTL_AUTH_LDAP_LOGIN_REDIRECT", &a.LDAP.LoginRedirect)
	setString(getenv, "TRSTCTL_AUTH_LDAP_TIMEOUT", &a.LDAP.Timeout)
	setString(getenv, "TRSTCTL_AUTH_LDAP_DEFAULT_TENANT", &a.LDAP.DefaultTenant)
	setBool(getenv, "TRSTCTL_AUTH_LDAP_ALLOW_DEFAULT_TENANT", &a.LDAP.AllowDefaultTenant)
	setCSV(getenv, "TRSTCTL_AUTH_LDAP_DEFAULT_ROLES", &a.LDAP.DefaultRoles)

	setBool(getenv, "TRSTCTL_AUTH_SCIM_ENABLED", &a.SCIM.Enabled)
	scimToken := SCIMToken{}
	setString(getenv, "TRSTCTL_AUTH_SCIM_TOKEN_NAME", &scimToken.Name)
	setString(getenv, "TRSTCTL_AUTH_SCIM_TOKEN_TENANT_ID", &scimToken.TenantID)
	setString(getenv, "TRSTCTL_AUTH_SCIM_TOKEN_FILE", &scimToken.TokenFile)
	if scimToken.Name != "" || scimToken.TenantID != "" || scimToken.TokenFile != "" {
		a.SCIM.Tokens = []SCIMToken{scimToken}
	}

	setBool(getenv, "TRSTCTL_AUTH_ABAC_ENABLED", &a.ABAC.Enabled)
	setString(getenv, "TRSTCTL_AUTH_ABAC_MODULE", &a.ABAC.Module)
	setStringMap(getenv, "TRSTCTL_AUTH_ABAC_ENVIRONMENT", &a.ABAC.Environment)
}

// applyProtocolsEnv overlays the served issuance-protocol environment knobs
// (EXC-WIRE-02). It is split out of applyEnv as a named stage so applyEnv stays
// within the control-plane startup hotspot budget (CODE-102); behavior is
// identical to the previous inline block.
func applyProtocolsEnv(getenv func(string) string, p *Protocols) {
	setString(getenv, "TRSTCTL_PROTOCOLS_PROFILE", &p.Profile)
	setString(getenv, "TRSTCTL_PROTOCOLS_EVAL_TENANT_ID", &p.EvalTenantID)
	setString(getenv, "TRSTCTL_PROTOCOLS_EVAL_SPIFFE_TRUST_DOMAIN", &p.EvalSPIFFETrustDomain)
	setBool(getenv, "TRSTCTL_PROTOCOLS_ACME_ENABLED", &p.ACME.Enabled)
	setString(getenv, "TRSTCTL_PROTOCOLS_ACME_TENANT_ID", &p.ACME.TenantID)
	setBool(getenv, "TRSTCTL_PROTOCOLS_ACME_EAB_REQUIRED", &p.ACMEEAB.Required)
	eabKey := ACMEExternalAccountBindingKey{}
	setString(getenv, "TRSTCTL_PROTOCOLS_ACME_EAB_KEY_ID", &eabKey.KeyID)
	setBytes(getenv, "TRSTCTL_PROTOCOLS_ACME_EAB_HMAC_KEY", &eabKey.HMACKey)
	setString(getenv, "TRSTCTL_PROTOCOLS_ACME_EAB_HMAC_KEY_FILE", &eabKey.HMACKeyFile)
	if eabKey.KeyID != "" || len(eabKey.HMACKey) > 0 || eabKey.HMACKeyFile != "" {
		p.ACMEEAB.Keys = []ACMEExternalAccountBindingKey{eabKey}
	}
	setInt(getenv, "TRSTCTL_PROTOCOLS_ACME_MAX_NONCES", &p.ACMEQuota.MaxNonces)
	setInt(getenv, "TRSTCTL_PROTOCOLS_ACME_MAX_ACCOUNTS", &p.ACMEQuota.MaxAccounts)
	setInt(getenv, "TRSTCTL_PROTOCOLS_ACME_MAX_PENDING_ORDERS", &p.ACMEQuota.MaxPendingOrders)
	setInt(getenv, "TRSTCTL_PROTOCOLS_ACME_MAX_PENDING_AUTHORIZATIONS", &p.ACMEQuota.MaxPendingAuthorizations)
	setInt(getenv, "TRSTCTL_PROTOCOLS_ACME_MAX_PENDING_CHALLENGES", &p.ACMEQuota.MaxPendingChallenges)
	setInt(getenv, "TRSTCTL_PROTOCOLS_ACME_MAX_PENDING_ORDERS_PER_ACCOUNT", &p.ACMEQuota.MaxPendingOrdersPerAccount)
	setInt(getenv, "TRSTCTL_PROTOCOLS_ACME_MAX_NEW_ORDERS_PER_ACCOUNT", &p.ACMEQuota.MaxNewOrdersPerAccount)
	setInt(getenv, "TRSTCTL_PROTOCOLS_ACME_MAX_NEW_NONCES_PER_SOURCE", &p.ACMEQuota.MaxNewNoncesPerSource)
	setInt(getenv, "TRSTCTL_PROTOCOLS_ACME_MAX_NEW_ACCOUNTS_PER_SOURCE", &p.ACMEQuota.MaxNewAccountsPerSource)
	setInt(getenv, "TRSTCTL_PROTOCOLS_ACME_MAX_NEW_ORDERS_PER_SOURCE", &p.ACMEQuota.MaxNewOrdersPerSource)
	setInt(getenv, "TRSTCTL_PROTOCOLS_ACME_SOURCE_WINDOW_SECONDS", &p.ACMEQuota.SourceWindowSeconds)
	setInt(getenv, "TRSTCTL_PROTOCOLS_ACME_NONCE_TTL_SECONDS", &p.ACMEQuota.NonceTTLSeconds)
	setInt(getenv, "TRSTCTL_PROTOCOLS_ACME_STATE_TTL_SECONDS", &p.ACMEQuota.StateTTLSeconds)
	setBool(getenv, "TRSTCTL_PROTOCOLS_EST_ENABLED", &p.EST.Enabled)
	setString(getenv, "TRSTCTL_PROTOCOLS_EST_TENANT_ID", &p.EST.TenantID)
	setBool(getenv, "TRSTCTL_PROTOCOLS_SCEP_ENABLED", &p.SCEP.Enabled)
	setString(getenv, "TRSTCTL_PROTOCOLS_SCEP_TENANT_ID", &p.SCEP.TenantID)
	setCSV(getenv, "TRSTCTL_PROTOCOLS_SCEP_INTUNE_TRUST_ANCHOR_FILES", &p.SCEPIntuneChallenge.TrustAnchorFiles)
	setString(getenv, "TRSTCTL_PROTOCOLS_SCEP_INTUNE_EXPECTED_AUDIENCE", &p.SCEPIntuneChallenge.ExpectedAudience)
	setInt(getenv, "TRSTCTL_PROTOCOLS_SCEP_INTUNE_CLOCK_SKEW_SECONDS", &p.SCEPIntuneChallenge.ClockSkewSeconds)
	setBool(getenv, "TRSTCTL_PROTOCOLS_CMP_ENABLED", &p.CMP.Enabled)
	setString(getenv, "TRSTCTL_PROTOCOLS_CMP_TENANT_ID", &p.CMP.TenantID)
	setBool(getenv, "TRSTCTL_PROTOCOLS_TSA_ENABLED", &p.TSA.Enabled)
	setString(getenv, "TRSTCTL_PROTOCOLS_TSA_TENANT_ID", &p.TSA.TenantID)
	setBool(getenv, "TRSTCTL_PROTOCOLS_KMIP_ENABLED", &p.KMIP.Enabled)
	setString(getenv, "TRSTCTL_PROTOCOLS_KMIP_TENANT_ID", &p.KMIP.TenantID)
	setString(getenv, "TRSTCTL_PROTOCOLS_KMIP_ADDR", &p.KMIP.Addr)
	setString(getenv, "TRSTCTL_PROTOCOLS_KMIP_CERT_FILE", &p.KMIP.CertFile)
	setString(getenv, "TRSTCTL_PROTOCOLS_KMIP_KEY_FILE", &p.KMIP.KeyFile)
	setString(getenv, "TRSTCTL_PROTOCOLS_KMIP_CLIENT_CA_FILE", &p.KMIP.ClientCAFile)
	setString(getenv, "TRSTCTL_PROTOCOLS_RA_KEY_FILE", &p.RAKeyFile)
	setString(getenv, "TRSTCTL_PROTOCOLS_CMP_CLIENT_TRUST_ANCHOR_FILE", &p.CMPClientTrustAnchorFile)
	setBool(getenv, "TRSTCTL_PROTOCOLS_CMP_ALLOW_RA_ENROLLMENT", &p.CMPAllowRAEnrollment)
	setString(getenv, "TRSTCTL_PROTOCOLS_TSA_CERT_FILE", &p.TSACertFile)
	setBool(getenv, "TRSTCTL_PROTOCOLS_SPIFFE_ENABLED", &p.SPIFFE.Enabled)
	setString(getenv, "TRSTCTL_PROTOCOLS_SPIFFE_TENANT_ID", &p.SPIFFE.TenantID)
	setString(getenv, "TRSTCTL_PROTOCOLS_SPIFFE_SOCKET_PATH", &p.SPIFFE.SocketPath)
	setString(getenv, "TRSTCTL_PROTOCOLS_SPIFFE_TRUST_DOMAIN", &p.SPIFFE.TrustDomain)
	setBool(getenv, "TRSTCTL_PROTOCOLS_SSH_ENABLED", &p.SSH.Enabled)
	setString(getenv, "TRSTCTL_PROTOCOLS_SSH_TENANT_ID", &p.SSH.TenantID)
}

// applyBackupEnv is the DR/backup stage of the environment overlay. Every
// exported Backup field has a TRSTCTL_BACKUP_* line here — enforced by the
// reflection guard TestEveryBackupFieldHasEnvWiring, because the manifest
// signing fields shipped without theirs (AUD-201 follow-up A3/V35) and
// env-configured deployments silently wrote unsigned backups.
func applyBackupEnv(getenv func(string) string, b *Backup) {
	setString(getenv, "TRSTCTL_BACKUP_ENCRYPTION_KEY_FILE", &b.EncryptionKeyFile)
	setString(getenv, "TRSTCTL_BACKUP_MANIFEST_SIGNING_KEY_FILE", &b.ManifestSigningKeyFile)
	setCSV(getenv, "TRSTCTL_BACKUP_TRUSTED_MANIFEST_KEY_FILES", &b.TrustedManifestKeyFiles)
	setBool(getenv, "TRSTCTL_BACKUP_ALLOW_UNENCRYPTED", &b.AllowUnencrypted)
	setString(getenv, "TRSTCTL_BACKUP_DIRECTORY", &b.Directory)
	setString(getenv, "TRSTCTL_BACKUP_DRILL_INTERVAL", &b.DrillInterval)
	setString(getenv, "TRSTCTL_BACKUP_DRILL_RPO", &b.DrillRPO)
	setString(getenv, "TRSTCTL_BACKUP_DRILL_RTO", &b.DrillRTO)
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
	applyOptionalBulkheadEnv(getenv, "TRSTCTL_BULKHEAD_OUTBOX_EXTERNAL_CA", b.Outbox, &b.OutboxExternalCA)
	applyOptionalBulkheadEnv(getenv, "TRSTCTL_BULKHEAD_OUTBOX_CONNECTORS", b.Outbox, &b.OutboxConnectors)
	applyOptionalBulkheadEnv(getenv, "TRSTCTL_BULKHEAD_OUTBOX_SECRETS", b.Outbox, &b.OutboxSecrets)
	applyOptionalBulkheadEnv(getenv, "TRSTCTL_BULKHEAD_OUTBOX_SECRET_SYNC", b.Outbox, &b.OutboxSecretSync)
	applyOptionalBulkheadEnv(getenv, "TRSTCTL_BULKHEAD_OUTBOX_MANAGED_KEYS", b.Outbox, &b.OutboxManagedKeys)
	applyOptionalBulkheadEnv(getenv, "TRSTCTL_BULKHEAD_OUTBOX_TRANSPARENCY", b.Outbox, &b.OutboxTransparency)
	applyOptionalBulkheadEnv(getenv, "TRSTCTL_BULKHEAD_OUTBOX_CODE_SIGNING", b.Outbox, &b.OutboxCodeSigning)
	applyOptionalBulkheadEnv(getenv, "TRSTCTL_BULKHEAD_OUTBOX_NOTIFICATIONS", b.Outbox, &b.OutboxNotifications)
	applyOptionalBulkheadEnv(getenv, "TRSTCTL_BULKHEAD_OUTBOX_TENANT_SEAL", b.Outbox, &b.OutboxTenantSeal)
	applyOptionalBulkheadEnv(getenv, "TRSTCTL_BULKHEAD_OUTBOX_FLEET_REISSUANCE", b.Outbox, &b.OutboxFleet)
	applyOptionalBulkheadEnv(getenv, "TRSTCTL_BULKHEAD_OUTBOX_AUDIT_FEEDS", b.Outbox, &b.OutboxAuditFeeds)
	setInt(getenv, "TRSTCTL_BULKHEAD_SIGNING_WORKERS", &b.Signing.Workers)
	setInt(getenv, "TRSTCTL_BULKHEAD_SIGNING_QUEUE", &b.Signing.Queue)
	setInt(getenv, "TRSTCTL_BULKHEAD_QUERY_WORKERS", &b.Query.Workers)
	setInt(getenv, "TRSTCTL_BULKHEAD_QUERY_QUEUE", &b.Query.Queue)
	setInt(getenv, "TRSTCTL_BULKHEAD_POLICY_WORKERS", &b.Policy.Workers)
	setInt(getenv, "TRSTCTL_BULKHEAD_POLICY_QUEUE", &b.Policy.Queue)
	setInt(getenv, "TRSTCTL_BULKHEAD_PROTOCOLS_WORKERS", &b.Protocols.Workers)
	setInt(getenv, "TRSTCTL_BULKHEAD_PROTOCOLS_QUEUE", &b.Protocols.Queue)
	setInt(getenv, "TRSTCTL_BULKHEAD_KMIP_WORKERS", &b.KMIP.Workers)
	setInt(getenv, "TRSTCTL_BULKHEAD_KMIP_QUEUE", &b.KMIP.Queue)
	setInt(getenv, "TRSTCTL_BULKHEAD_AGENT_WORKERS", &b.Agent.Workers)
	setInt(getenv, "TRSTCTL_BULKHEAD_AGENT_QUEUE", &b.Agent.Queue)
	setInt(getenv, "TRSTCTL_BULKHEAD_CBOM_WORKERS", &b.CBOM.Workers)
	setInt(getenv, "TRSTCTL_BULKHEAD_CBOM_QUEUE", &b.CBOM.Queue)
}

func applyOptionalBulkheadEnv(getenv func(string) string, prefix string, fallback BulkheadLimit, dst **BulkheadLimit) {
	workers := strings.TrimSpace(getenv(prefix + "_WORKERS"))
	queue := strings.TrimSpace(getenv(prefix + "_QUEUE"))
	if workers == "" && queue == "" {
		return
	}
	limit := fallback
	if n, err := strconv.Atoi(workers); workers != "" && err == nil {
		limit.Workers = n
	}
	if n, err := strconv.Atoi(queue); queue != "" && err == nil {
		limit.Queue = n
	}
	*dst = &limit
}

func setString(getenv func(string) string, key string, dst *string) {
	if v := getenv(key); v != "" {
		*dst = v
	}
}

func setBytes(getenv func(string) string, key string, dst *[]byte) {
	if v := getenv(key); v != "" {
		*dst = []byte(v)
	}
}

// setJSONBytes is setBytes for secret.JSONBytes fields: credential material that
// decodes from a plain JSON string but is held as wipeable bytes (AN-8). The
// environment hands us a string we cannot control, so this is the earliest point
// the value can be moved into byte memory; everything downstream stays bytes.
func setJSONBytes(getenv func(string) string, key string, dst *secret.JSONBytes) {
	if v := getenv(key); v != "" {
		*dst = secret.JSONBytes(v)
	}
}

func setNotificationEnv(getenv func(string) string, n *Notifications) {
	setBool(getenv, "TRSTCTL_NOTIFICATIONS_SLACK_ENABLED", &n.Slack.Enabled)
	setString(getenv, "TRSTCTL_NOTIFICATIONS_SLACK_WEBHOOK_URL", &n.Slack.WebhookURL)
	setBool(getenv, "TRSTCTL_NOTIFICATIONS_TEAMS_ENABLED", &n.Teams.Enabled)
	setString(getenv, "TRSTCTL_NOTIFICATIONS_TEAMS_WEBHOOK_URL", &n.Teams.WebhookURL)
	setBool(getenv, "TRSTCTL_NOTIFICATIONS_EMAIL_ENABLED", &n.Email.Enabled)
	setString(getenv, "TRSTCTL_NOTIFICATIONS_EMAIL_SMTP_ADDR", &n.Email.SMTPAddr)
	setString(getenv, "TRSTCTL_NOTIFICATIONS_EMAIL_FROM", &n.Email.From)
	setCSV(getenv, "TRSTCTL_NOTIFICATIONS_EMAIL_TO", &n.Email.To)
	setString(getenv, "TRSTCTL_NOTIFICATIONS_EMAIL_USERNAME", &n.Email.Username)
	setBytes(getenv, "TRSTCTL_NOTIFICATIONS_EMAIL_PASSWORD", &n.Email.Password)
	setString(getenv, "TRSTCTL_NOTIFICATIONS_EMAIL_PASSWORD_FILE", &n.Email.PasswordFile)
	setBool(getenv, "TRSTCTL_NOTIFICATIONS_SMS_ENABLED", &n.SMS.Enabled)
	setString(getenv, "TRSTCTL_NOTIFICATIONS_SMS_ENDPOINT", &n.SMS.Endpoint)
	setString(getenv, "TRSTCTL_NOTIFICATIONS_SMS_FROM", &n.SMS.From)
	setCSV(getenv, "TRSTCTL_NOTIFICATIONS_SMS_TO", &n.SMS.To)
	setBytes(getenv, "TRSTCTL_NOTIFICATIONS_SMS_TOKEN", &n.SMS.Token)
	setString(getenv, "TRSTCTL_NOTIFICATIONS_SMS_TOKEN_FILE", &n.SMS.TokenFile)
	setBool(getenv, "TRSTCTL_NOTIFICATIONS_SIEM_ENABLED", &n.SIEM.Enabled)
	setString(getenv, "TRSTCTL_NOTIFICATIONS_SIEM_ENDPOINT", &n.SIEM.Endpoint)
	setBytes(getenv, "TRSTCTL_NOTIFICATIONS_SIEM_TOKEN", &n.SIEM.Token)
	setString(getenv, "TRSTCTL_NOTIFICATIONS_SIEM_TOKEN_FILE", &n.SIEM.TokenFile)
	setString(getenv, "TRSTCTL_NOTIFICATIONS_SIEM_SOURCE", &n.SIEM.Source)
	setIncidentNotificationEnv(getenv, &n.PagerDuty, &n.OpsGenie)
}

func setServiceNowEnv(getenv func(string) string, sn *ServiceNowITSM) {
	instanceURL := strings.TrimSpace(getenv("TRSTCTL_SERVICENOW_INSTANCE_URL"))
	tokenRef := strings.TrimSpace(getenv("TRSTCTL_SERVICENOW_TOKEN_REF"))
	allowPrivateRaw := strings.TrimSpace(getenv("TRSTCTL_SERVICENOW_ALLOW_PRIVATE_ENDPOINT"))
	privateCIDRsRaw := strings.TrimSpace(getenv("TRSTCTL_SERVICENOW_PRIVATE_EGRESS_CIDRS"))
	if instanceURL == "" && tokenRef == "" && allowPrivateRaw == "" && privateCIDRsRaw == "" {
		return
	}
	if tokenRef == "" {
		tokenRef = "env:TRSTCTL_SERVICENOW_TOKEN" // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
	}
	binding := ServiceNowBinding{InstanceURL: instanceURL, TokenRef: tokenRef}
	if allowPrivateRaw != "" {
		if b, err := strconv.ParseBool(allowPrivateRaw); err == nil {
			binding.AllowPrivateEndpoint = b
		}
	}
	if privateCIDRsRaw != "" {
		binding.PrivateEgressCIDRs = splitCSV(privateCIDRsRaw)
	}
	sn.Bindings = []ServiceNowBinding{binding}
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
	out := splitCSV(v)
	if len(out) > 0 {
		*dst = out
	}
}

func splitCSV(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// setStringMap overlays comma-separated key=value pairs into a string map. It is
// used for small operator-state maps such as ABAC environment attributes.
func setStringMap(getenv func(string) string, key string, dst *map[string]string) {
	v := getenv(key)
	if v == "" {
		return
	}
	out := map[string]string{}
	for _, part := range strings.Split(v, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		k, val, ok := strings.Cut(p, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		val = strings.TrimSpace(val)
		if k != "" {
			out[k] = val
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
// validateProviderConfig checks every Provider identity input (L1). Partial
// setup must stop startup because an operator must never believe SAML or SCIM is
// protecting the plane while the runtime silently fell back to bearer-only.
func validateProviderConfig(c *Config) []error {
	var errs []error
	oidc := c.Provider.OIDC
	if oidc.Configured() {
		if strings.TrimSpace(oidc.Issuer) == "" {
			errs = append(errs, errors.New("provider.oidc.issuer is required when provider OIDC is configured"))
		}
		if strings.TrimSpace(oidc.Audience) == "" {
			errs = append(errs, errors.New("provider.oidc.audience is required when provider OIDC is configured"))
		}
		if strings.TrimSpace(oidc.JWKSFile) == "" && strings.TrimSpace(oidc.JWKSJSON) == "" {
			errs = append(errs, errors.New("provider.oidc needs jwks_file or jwks_json: the IdP's keys are pinned offline, never fetched from a URL the token's minter might control"))
		}
		if strings.TrimSpace(oidc.JWKSFile) != "" && strings.TrimSpace(oidc.JWKSJSON) != "" {
			errs = append(errs, errors.New("provider.oidc.jwks_file and jwks_json are mutually exclusive; two key sets invite the wrong one to win silently"))
		}
		if len(oidc.AdminValues) == 0 && len(oidc.OperatorValues) == 0 {
			errs = append(errs, errors.New("provider.oidc needs admin_values and/or operator_values: without a role mapping every authenticated token is refused, and the plane reads as broken rather than unmapped"))
		}
	}

	saml := c.Provider.SAML
	if saml.Enabled {
		require := func(value, name string) {
			if strings.TrimSpace(value) == "" {
				errs = append(errs, fmt.Errorf("provider.saml.%s is required when provider.saml.enabled is true", name))
			}
		}
		require(saml.EntityID, "entity_id")
		require(saml.MetadataURL, "metadata_url")
		require(saml.ACSURL, "acs_url")
		require(saml.SessionSecretFile, "session_secret_file")
		require(saml.RoleAttribute, "role_attribute")
		require(saml.MFAAttribute, "mfa_attribute")
		if strings.TrimSpace(saml.IDPMetadataFile) == "" && strings.TrimSpace(saml.IDPMetadataXML) == "" {
			errs = append(errs, errors.New("provider.saml requires idp_metadata_file or idp_metadata_xml when enabled"))
		}
		if strings.TrimSpace(saml.IDPMetadataFile) != "" && strings.TrimSpace(saml.IDPMetadataXML) != "" {
			errs = append(errs, errors.New("provider.saml.idp_metadata_file and idp_metadata_xml are mutually exclusive"))
		}
		if len(saml.AdminValues) == 0 && len(saml.OperatorValues) == 0 {
			errs = append(errs, errors.New("provider.saml needs admin_values and/or operator_values"))
		}
		if len(saml.MFAValues) == 0 {
			errs = append(errs, errors.New("provider.saml.mfa_values requires at least one accepted MFA proof"))
		}
		for _, endpoint := range []struct{ value, name string }{{saml.EntityID, "entity_id"}, {saml.MetadataURL, "metadata_url"}, {saml.ACSURL, "acs_url"}} {
			if strings.TrimSpace(endpoint.value) == "" {
				continue
			}
			u, err := url.Parse(endpoint.value)
			if err != nil || u.Host == "" || (u.Scheme != "https" && (u.Scheme != "http" || !netsec.IsLoopbackHost(u.Hostname()))) {
				errs = append(errs, fmt.Errorf("provider.saml.%s %q must be an absolute https URL (http is allowed only for loopback)", endpoint.name, endpoint.value))
			}
		}
		if ttl, err := saml.SessionTTLDuration(); err != nil || ttl <= 0 {
			errs = append(errs, fmt.Errorf("provider.saml.session_ttl %q must be a positive Go duration", saml.SessionTTL))
		}
	}

	if scim := c.Provider.SCIM; scim.Enabled {
		if len(scim.Tokens) == 0 {
			errs = append(errs, errors.New("provider.scim.tokens requires at least one file-backed bearer token when enabled"))
		}
		seen := map[string]bool{}
		for i, token := range scim.Tokens {
			name := strings.TrimSpace(token.Name)
			if name == "" {
				errs = append(errs, fmt.Errorf("provider.scim.tokens[%d].name is required", i))
			}
			if strings.TrimSpace(token.TokenFile) == "" {
				errs = append(errs, fmt.Errorf("provider.scim.tokens[%d].token_file is required", i))
			}
			if seen[name] && name != "" {
				errs = append(errs, fmt.Errorf("provider.scim token name %q is duplicated", name))
			}
			seen[name] = true
		}
	}
	return errs
}

func (c *Config) Validate() error {
	var errs []error
	for _, validate := range []func(*Config) []error{
		validateServerConfig,
		validateDatastores,
		validateLoggingAndLifecycle,
		func(c *Config) []error { return validateConnectors(c.Connectors) },
		func(c *Config) []error { return validateExternalCAs(c.ExternalCAs) },
		func(c *Config) []error { return validateSecretIntegrations(c.SecretIntegrations, c.Secrets.EnableAPI) },
		func(c *Config) []error { return validateCodeSigning(c.CodeSigning) },
		validateOptionalServices,
		validateBulkheadConfig,
		validateSignerConfig,
		validateServedSurfaces,
		validateGovernanceConfig,
		validateHAConfig,
		validateFederationConfig,
		validatePCASConfig,
		validateProviderConfig,
		validateLicenseConfig,
	} {
		errs = append(errs, validate(c)...)
	}
	return errors.Join(errs...)
}

func validateLicenseConfig(c *Config) []error {
	var errs []error
	identityConfigured := c.License.DeploymentID != "" || c.License.Environment != ""
	if identityConfigured && c.License.File == "" {
		errs = append(errs, errors.New("license.file is required when a license deployment identity is configured"))
	}
	if (c.License.DeploymentID == "") != (c.License.Environment == "") {
		errs = append(errs, errors.New("license.deployment_id and license.environment must be configured together"))
	}
	if c.License.Environment != "" && c.License.Environment != "production" && c.License.Environment != "non_production" {
		errs = append(errs, errors.New("license.environment must be production or non_production"))
	}
	return errs
}

func validateBulkheadConfig(c *Config) []error {
	return c.Bulkheads.validate()
}

func validateServerConfig(c *Config) []error {
	var errs []error
	if c.Server.Addr == "" {
		errs = append(errs, errors.New("server.addr must not be empty"))
	}
	switch strings.TrimSpace(c.Server.TLS.MinVersion) {
	case "", "1.3", "1.2":
	default:
		errs = append(errs, fmt.Errorf("server.tls.min_version %q is invalid (want \"1.3\" or \"1.2\")", c.Server.TLS.MinVersion))
	}
	switch c.Server.TLS.Mode {
	case TLSInternal:
		if strings.TrimSpace(c.Server.TLS.InternalStateFile) == "" {
			errs = append(errs, errors.New("server.tls.internal_state_file is required when server.tls.mode is internal"))
		}
		if strings.TrimSpace(c.Server.TLS.InternalTrustFile) == "" {
			errs = append(errs, errors.New("server.tls.internal_trust_file is required when server.tls.mode is internal"))
		}
		if c.Server.TLS.InternalStateFile != "" && c.Server.TLS.InternalTrustFile != "" && filepath.Clean(c.Server.TLS.InternalStateFile) == filepath.Clean(c.Server.TLS.InternalTrustFile) {
			errs = append(errs, errors.New("server.tls.internal_trust_file must not alias the private server.tls.internal_state_file"))
		}
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
	return netsec.IsLoopbackHost(host)
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
	if d, err := c.Lifecycle.OwnershipAttestationCadenceDuration(); err != nil {
		errs = append(errs, fmt.Errorf("lifecycle.ownership_attestation_cadence %q is invalid: %w", c.Lifecycle.OwnershipAttestationCadence, err))
	} else if d < time.Hour || d > 365*24*time.Hour {
		errs = append(errs, errors.New("lifecycle.ownership_attestation_cadence must be within [1h, 1 year]"))
	}
	if d, err := c.Postgres.StatementTimeoutDuration(); err != nil {
		errs = append(errs, fmt.Errorf("postgres.statement_timeout %q is invalid: %w", c.Postgres.StatementTimeout, err))
	} else if d < time.Second || d > 10*time.Minute {
		errs = append(errs, errors.New("postgres.statement_timeout must be within [1s, 10m]"))
	}
	if d, err := c.Postgres.AcquireTimeoutDuration(); err != nil {
		errs = append(errs, fmt.Errorf("postgres.acquire_timeout %q is invalid: %w", c.Postgres.AcquireTimeout, err))
	} else if d < 100*time.Millisecond || d > time.Minute {
		errs = append(errs, errors.New("postgres.acquire_timeout must be within [100ms, 1m]"))
	}
	if c.Signer.CallTimeout != "" {
		if d, err := time.ParseDuration(c.Signer.CallTimeout); err != nil {
			errs = append(errs, fmt.Errorf("signer.call_timeout %q is invalid: %w", c.Signer.CallTimeout, err))
		} else if d < time.Second || d > 2*time.Minute {
			errs = append(errs, errors.New("signer.call_timeout must be within [1s, 2m]"))
		}
	}
	if d, err := c.Lifecycle.LeafValidityDuration(); err != nil {
		errs = append(errs, fmt.Errorf("lifecycle.leaf_validity %q is invalid: %w", c.Lifecycle.LeafValidity, err))
	} else if d < time.Hour || d > 10*365*24*time.Hour {
		errs = append(errs, errors.New("lifecycle.leaf_validity must be within [1h, 10 years]"))
	}
	if d, err := c.Lifecycle.NotBeforeSkewDuration(); err != nil {
		errs = append(errs, fmt.Errorf("lifecycle.not_before_skew %q is invalid: %w", c.Lifecycle.NotBeforeSkew, err))
	} else if d < 30*time.Second || d > time.Hour {
		errs = append(errs, errors.New("lifecycle.not_before_skew must be within [30s, 1h]"))
	}
	errs = append(errs, validateNotifications(c.Notifications)...)
	return errs
}

func validateNotifications(n Notifications) []error {
	var errs []error
	if n.Slack.Enabled && strings.TrimSpace(n.Slack.WebhookURL) == "" {
		errs = append(errs, errors.New("notifications.slack.webhook_url is required when Slack notifications are enabled"))
	}
	if n.Teams.Enabled && strings.TrimSpace(n.Teams.WebhookURL) == "" {
		errs = append(errs, errors.New("notifications.teams.webhook_url is required when Teams notifications are enabled"))
	}
	if n.Email.Enabled {
		if strings.TrimSpace(n.Email.SMTPAddr) == "" {
			errs = append(errs, errors.New("notifications.email.smtp_addr is required when email notifications are enabled"))
		}
		if strings.TrimSpace(n.Email.From) == "" {
			errs = append(errs, errors.New("notifications.email.from is required when email notifications are enabled"))
		}
		if len(n.Email.To) == 0 {
			errs = append(errs, errors.New("notifications.email.to must name at least one recipient when email notifications are enabled"))
		}
		if n.Email.Username != "" && len(n.Email.Password) == 0 && strings.TrimSpace(n.Email.PasswordFile) == "" {
			errs = append(errs, errors.New("notifications.email.password or password_file is required when email username is set"))
		}
	}
	if n.SMS.Enabled {
		if strings.TrimSpace(n.SMS.Endpoint) == "" {
			errs = append(errs, errors.New("notifications.sms.endpoint is required when SMS notifications are enabled"))
		}
		if len(n.SMS.To) == 0 {
			errs = append(errs, errors.New("notifications.sms.to must name at least one recipient when SMS notifications are enabled"))
		}
	}
	if n.SIEM.Enabled && strings.TrimSpace(n.SIEM.Endpoint) == "" {
		errs = append(errs, errors.New("notifications.siem.endpoint is required when SIEM notifications are enabled"))
	}
	errs = append(errs, validateIncidentNotifications(n.PagerDuty, n.OpsGenie)...)
	return errs
}

func validateOptionalServices(c *Config) []error {
	var errs []error
	// Telemetry only constrains anything when the operator has opted in;
	// disabled telemetry needs no endpoint or interval.
	if c.Telemetry.Enabled {
		if strings.TrimSpace(c.Telemetry.Endpoint) == "" {
			errs = append(errs, errors.New("telemetry.endpoint is required when telemetry is enabled: trstctl ships no default collector, so set TRSTCTL_TELEMETRY_ENDPOINT to an https collector you operate"))
		} else if u, err := url.Parse(c.Telemetry.Endpoint); err != nil || u.Scheme != "https" || u.Host == "" {
			errs = append(errs, fmt.Errorf("telemetry.endpoint %q must be an absolute https URL", c.Telemetry.Endpoint))
		}
		if d, err := c.Telemetry.IntervalDuration(); err != nil {
			errs = append(errs, fmt.Errorf("telemetry.interval %q is invalid: %w", c.Telemetry.Interval, err))
		} else if d <= 0 {
			errs = append(errs, errors.New("telemetry.interval must be positive"))
		}
		if strings.TrimSpace(c.Telemetry.InstanceIDFile) == "" {
			errs = append(errs, errors.New("telemetry.instance_id_file is required when telemetry is enabled"))
		}
	}
	errs = append(errs, validateAirGap(c)...)
	errs = append(errs, validateITSM(c)...)
	errs = append(errs, validateOutboundEnvCredentialRefs(c)...)
	if c.OTLP.Enabled {
		if strings.TrimSpace(c.OTLP.Endpoint) == "" {
			errs = append(errs, errors.New("otlp.endpoint is required when otlp is enabled"))
		} else if u, err := url.Parse(c.OTLP.Endpoint); err != nil || u.Scheme == "" || u.Host == "" {
			errs = append(errs, fmt.Errorf("otlp.endpoint %q must be an absolute URL", c.OTLP.Endpoint))
		} else if u.Scheme != "https" && (u.Scheme != "http" || !c.OTLP.Insecure) {
			errs = append(errs, fmt.Errorf("otlp.endpoint %q must be https, or http with otlp.insecure=true", c.OTLP.Endpoint))
		}
		if d, err := c.OTLP.TimeoutDuration(); err != nil {
			errs = append(errs, fmt.Errorf("otlp.timeout %q is invalid: %w", c.OTLP.Timeout, err))
		} else if d <= 0 {
			errs = append(errs, errors.New("otlp.timeout must be positive"))
		}
		if c.OTLP.QueueSize < 0 {
			errs = append(errs, errors.New("otlp.queue_size must be zero or positive"))
		}
		if len(c.OTLP.Token) > 0 && strings.TrimSpace(c.OTLP.TokenFile) != "" {
			errs = append(errs, errors.New("otlp.token and otlp.token_file are mutually exclusive"))
		}
	}
	// Audit retention is optional (empty means indefinite); when set it must be a
	// valid, non-negative Go duration.
	if d, err := c.Audit.RetentionDuration(); err != nil {
		errs = append(errs, fmt.Errorf("audit.retention %q is invalid: %w", c.Audit.Retention, err))
	} else if d < 0 {
		errs = append(errs, errors.New("audit.retention must not be negative"))
	}
	if _, _, err := c.Backup.DrillObjectiveDurations(); err != nil {
		errs = append(errs, fmt.Errorf("backup recovery objectives are invalid: %w", err))
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

func validateAirGap(c *Config) []error {
	var errs []error
	for _, raw := range c.AirGap.AllowHosts {
		host := strings.TrimSpace(raw)
		if host == "" {
			continue
		}
		if strings.Contains(host, "://") {
			errs = append(errs, fmt.Errorf("air_gap.allow_hosts entry %q must be a host, not a URL", raw))
		}
	}
	for _, raw := range c.AirGap.AllowCIDRs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		// Route through the shared egress-prefix parser like every other egress
		// allowlist surface (J1): it rejects host-bits ("10.1.2.3/8" silently
		// widening to 10.0.0.0/8) and wildcards ("0.0.0.0/0" meaning allow-all),
		// which the air-gap guard — the platform's strictest control — must not
		// accept while reading as a normal entry (AUD-201 follow-up).
		if _, err := netsec.ParseEgressAllowPrefix(raw); err != nil {
			errs = append(errs, fmt.Errorf("air_gap.allow_cidrs entry %q is invalid: %w", raw, err))
		}
	}
	if c.AirGap.Enabled {
		if c.Telemetry.Enabled {
			errs = append(errs, errors.New("telemetry.enabled must be false when air_gap.enabled is true"))
		}
		if c.AI.Model.ModeValue() == AIModelCloud {
			errs = append(errs, errors.New("ai.model.mode=cloud is not allowed when air_gap.enabled is true"))
		}
	}
	return errs
}

func validateITSM(c *Config) []error {
	var errs []error
	for i, b := range c.ITSM.ServiceNow.Bindings {
		prefix := fmt.Sprintf("itsm.servicenow.bindings[%d]", i)
		instanceURL := strings.TrimSpace(b.InstanceURL)
		if instanceURL == "" {
			errs = append(errs, fmt.Errorf("%s.instance_url is required", prefix))
			continue
		}
		u, err := url.Parse(instanceURL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			errs = append(errs, fmt.Errorf("%s.instance_url must be an absolute HTTP(S) URL", prefix))
		} else {
			if u.Scheme != "http" && u.Scheme != "https" {
				errs = append(errs, fmt.Errorf("%s.instance_url must use http or https", prefix))
			}
			if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
				errs = append(errs, fmt.Errorf("%s.instance_url must not include credentials, query, or fragment", prefix))
			}
			if u.Scheme != "https" && !b.AllowPrivateEndpoint {
				errs = append(errs, fmt.Errorf("%s.instance_url must use https unless allow_private_endpoint is true", prefix))
			}
		}
		tokenRef := strings.TrimSpace(b.TokenRef)
		if tokenRef == "" {
			errs = append(errs, fmt.Errorf("%s.token_ref is required", prefix))
		} else if name, ok := strings.CutPrefix(tokenRef, "env:"); !ok || strings.TrimSpace(name) == "" {
			errs = append(errs, fmt.Errorf("%s.token_ref must be an env:NAME credential reference", prefix))
		}
		if len(b.PrivateEgressCIDRs) > 0 && !b.AllowPrivateEndpoint {
			errs = append(errs, fmt.Errorf("%s.private_egress_cidrs requires allow_private_endpoint", prefix))
		}
		if b.AllowPrivateEndpoint && len(b.PrivateEgressCIDRs) == 0 {
			errs = append(errs, fmt.Errorf("%s.private_egress_cidrs is required when allow_private_endpoint is true", prefix))
		}
		for _, raw := range b.PrivateEgressCIDRs {
			if _, err := netsec.ParseEgressAllowPrefix(raw); err != nil {
				errs = append(errs, fmt.Errorf("%s.private_egress_cidrs contains invalid CIDR %q: %w", prefix, raw, err))
			}
		}
	}
	return errs
}

func validateOutboundEnvCredentialRefs(c *Config) []error {
	var errs []error
	seen := map[string]bool{}
	for i, raw := range c.OutboundEnvCredentialRefs {
		ref := strings.TrimSpace(raw)
		prefix := fmt.Sprintf("outbound_env_credential_refs[%d]", i)
		name, ok := strings.CutPrefix(ref, "env:")
		if !ok || strings.TrimSpace(name) == "" {
			errs = append(errs, fmt.Errorf("%s must be an env:NAME credential reference", prefix))
			continue
		}
		if seen[ref] {
			errs = append(errs, fmt.Errorf("%s duplicates outbound env credential reference %q", prefix, ref))
			continue
		}
		seen[ref] = true
	}
	return errs
}

func validateSignerConfig(c *Config) []error {
	var errs []error
	if c.Signer.AuthTokenCommand != "" && c.Signer.AllowCoResidentAuthorizer {
		errs = append(errs, errors.New("signer.auth_token_command and signer.allow_co_resident_authorizer are mutually exclusive"))
	}
	if c.NATS.Mode == NATSExternal && !c.NATS.AllowSingleReplica {
		if c.Signer.AllowCoResidentAuthorizer {
			errs = append(errs, errors.New("signer.allow_co_resident_authorizer is evaluation-only; production external NATS deployments must use signer.auth_token_command or another independent token provider"))
		}
		if c.Signer.AuthTokenCommand == "" {
			errs = append(errs, errors.New("signer.auth_token_command is required for production external NATS deployments so privileged signer handles have an independent token provider"))
		}
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
	errs = append(errs, validateEphemeralIssuance(c.EphemeralIssuance)...)
	// Served OIDC login (EXC-WIRE-01): when enabled it must be FULLY configured, so
	// the binary never serves a half-wired login (fail closed). When disabled the
	// block is ignored.
	if c.Auth.OIDC.Enabled {
		errs = append(errs, c.Auth.OIDC.validate()...)
	}
	if c.Auth.SAML.Enabled {
		errs = append(errs, c.Auth.SAML.validate()...)
	}
	if c.Auth.LDAP.Enabled {
		errs = append(errs, c.Auth.LDAP.validate()...)
	}
	if c.Auth.SCIM.Enabled {
		errs = append(errs, c.Auth.SCIM.validate()...)
	}
	if c.Auth.ABAC.Enabled {
		errs = append(errs, c.Auth.ABAC.validate()...)
	}
	if c.Breakglass.Enabled || c.Breakglass.OnlineEnabled {
		errs = append(errs, c.Breakglass.validate()...)
	}
	if c.Secrets.AuthSecretFile != "" {
		if err := uuid.Validate(c.Secrets.AuthTokenTenantID); err != nil {
			errs = append(errs, errors.New("secrets.auth_token_tenant_id must be a UUID when secrets.auth_secret_file is configured"))
		}
		if len(c.Secrets.AuthTokenScopes) == 0 {
			errs = append(errs, errors.New("secrets.auth_token_scopes must grant at least one explicit permission when secrets.auth_secret_file is configured"))
		}
		seen := map[string]bool{}
		for i, rawScope := range c.Secrets.AuthTokenScopes {
			scope := strings.TrimSpace(rawScope)
			if scope == "" {
				errs = append(errs, fmt.Errorf("secrets.auth_token_scopes[%d] must be a non-empty permission", i))
				continue
			}
			if scope != rawScope {
				errs = append(errs, fmt.Errorf("secrets.auth_token_scopes[%d] must not contain leading or trailing whitespace", i))
			}
			if seen[scope] {
				errs = append(errs, fmt.Errorf("secrets.auth_token_scopes contains duplicate %q", scope))
			}
			seen[scope] = true
		}
	}
	errs = append(errs, validateSecretsMachineAuth(c.Secrets.MachineAuth)...)
	errs = append(errs, validateTenantSealLocalWrappers(c.Secrets.TenantSealLocalWrappers)...)
	errs = append(errs, validateManagedKeys(c.ManagedKeys)...)
	// Served enrollment protocols are public protocol endpoints. Resolve the
	// explicit eval preset before validation so its convenience never bypasses the
	// same tenant/material checks as seven hand-written toggles. Production keeps
	// an empty profile and therefore the exact default-off posture.
	effectiveProtocols, profileErr := c.Protocols.Effective()
	if profileErr != nil {
		errs = append(errs, profileErr)
	} else {
		errs = append(errs, effectiveProtocols.ValidateTenantBindings("")...)
	}
	errs = append(errs, c.Protocols.ACMEQuota.validate()...)
	errs = append(errs, validateACMEEAB(c.Protocols.ACMEEAB)...)
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
		if public := c.AgentChannel.PublicAddress; public != "" {
			host, port, err := net.SplitHostPort(public)
			parsedPort, portErr := strconv.ParseUint(port, 10, 16)
			if strings.TrimSpace(public) != public || err != nil || strings.TrimSpace(host) == "" || portErr != nil || parsedPort == 0 {
				errs = append(errs, errors.New("agent_channel.public_address must be a trimmed host:port such as agents.example.com:9443 or localhost:19443"))
			} else if !agentPublicHostIsLoopback(host) && strings.TrimSpace(c.AgentChannel.ServerName) == "" {
				errs = append(errs, errors.New("agent_channel.public_address for a non-loopback host requires agent_channel.server_name so agents can verify the channel certificate"))
			}
		}
	}
	return errs
}

func validateEphemeralIssuance(e EphemeralIssuance) []error {
	if !e.Enabled {
		return nil
	}
	var errs []error
	if strings.TrimSpace(e.TrustDomain) == "" {
		errs = append(errs, errors.New("ephemeral_issuance.trust_domain is required when ephemeral issuance is enabled"))
	}
	parsePositive := func(name, raw string) time.Duration {
		if strings.TrimSpace(raw) == "" {
			return 0
		}
		d, err := time.ParseDuration(strings.TrimSpace(raw))
		if err != nil || d <= 0 {
			errs = append(errs, fmt.Errorf("ephemeral_issuance.%s %q must be a positive Go duration", name, raw))
			return 0
		}
		return d
	}
	defaultTTL := parsePositive("default_ttl", e.DefaultTTL)
	maxTTL := parsePositive("max_ttl", e.MaxTTL)
	_ = parsePositive("approval_ttl", e.ApprovalTTL)
	if defaultTTL > 0 && maxTTL > 0 && defaultTTL > maxTTL {
		errs = append(errs, errors.New("ephemeral_issuance.default_ttl must not exceed max_ttl"))
	}
	if e.RequiredApprovals < 0 {
		errs = append(errs, errors.New("ephemeral_issuance.required_approvals must not be negative; zero uses the secure default"))
	}
	return errs
}

func agentPublicHostIsLoopback(host string) bool {
	if strings.EqualFold(strings.TrimSpace(host), "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func validateTenantSealLocalWrappers(wrappers []TenantSealLocalWrapper) []error {
	var errs []error
	seen := make(map[string]struct{}, len(wrappers))
	for index, wrapper := range wrappers {
		if wrapper.ID == "" || strings.TrimSpace(wrapper.ID) != wrapper.ID {
			errs = append(errs, fmt.Errorf("secrets.tenant_seal_local_wrappers[%d].id must be non-empty and trimmed", index))
		}
		if wrapper.File == "" {
			errs = append(errs, fmt.Errorf("secrets.tenant_seal_local_wrappers[%d].file must not be empty", index))
		}
		if _, duplicate := seen[wrapper.ID]; duplicate && wrapper.ID != "" {
			errs = append(errs, fmt.Errorf("secrets.tenant_seal_local_wrappers contains duplicate id %q", wrapper.ID))
		}
		seen[wrapper.ID] = struct{}{}
	}
	return errs
}

func validateACMEEAB(e ACMEExternalAccountBinding) []error {
	if !e.Required && len(e.Keys) == 0 {
		return nil
	}
	var errs []error
	if e.Required && len(e.Keys) == 0 {
		errs = append(errs, errors.New("protocols.acme_eab.keys is required when protocols.acme_eab.required is true"))
	}
	seen := map[string]bool{}
	for i, key := range e.Keys {
		label := fmt.Sprintf("protocols.acme_eab.keys[%d]", i)
		keyID := strings.TrimSpace(key.KeyID)
		if keyID == "" {
			errs = append(errs, fmt.Errorf("%s.key_id is required", label))
		} else if seen[keyID] {
			errs = append(errs, fmt.Errorf("%s.key_id %q is duplicated", label, keyID))
		}
		seen[keyID] = true
		hasInline := len(key.HMACKey) > 0
		hasFile := strings.TrimSpace(key.HMACKeyFile) != ""
		switch {
		case !hasInline && !hasFile:
			errs = append(errs, fmt.Errorf("%s.hmac_key or %s.hmac_key_file is required", label, label))
		case hasInline && hasFile:
			errs = append(errs, fmt.Errorf("%s must not set both hmac_key and hmac_key_file", label))
		case hasInline && len(key.HMACKey) < 16:
			errs = append(errs, fmt.Errorf("%s.hmac_key must be at least 16 bytes", label))
		}
		if _, err := key.NotAfterTime(); err != nil {
			errs = append(errs, fmt.Errorf("%s.not_after %q is invalid (want RFC 3339): %w", label, key.NotAfter, err))
		}
		if key.MaxOrders < 0 {
			errs = append(errs, fmt.Errorf("%s.max_orders must not be negative", label))
		}
		for j, identifier := range key.AllowedIdentifiers {
			if strings.TrimSpace(identifier) == "" {
				errs = append(errs, fmt.Errorf("%s.allowed_identifiers[%d] must not be empty; an empty entry silently widens the scope it looks like it narrows", label, j))
			}
		}
	}
	return errs
}

func validateSecretsMachineAuth(methods []MachineAuthMethod) []error {
	var errs []error
	for i, m := range methods {
		name := strings.TrimSpace(m.Name)
		if name == "" {
			errs = append(errs, fmt.Errorf("secrets.machine_auth[%d].name is required", i))
			continue
		}
		switch name {
		case "kubernetes", "aws-iam", "gcp", "azure", "oidc", "jwt":
		default:
			errs = append(errs, fmt.Errorf("secrets.machine_auth[%d].name %q is invalid (want kubernetes, aws-iam, gcp, azure, oidc, or jwt)", i, name))
			continue
		}
		hasScopes := false
		seenScopes := map[string]bool{}
		for j, rawScope := range m.Scopes {
			scope := strings.TrimSpace(rawScope)
			if scope == "" {
				errs = append(errs, fmt.Errorf("secrets.machine_auth[%d].scopes[%d] must not be empty", i, j))
				continue
			}
			hasScopes = true
			if scope != rawScope {
				errs = append(errs, fmt.Errorf("secrets.machine_auth[%d].scopes[%d] must not contain leading or trailing whitespace", i, j))
			}
			if seenScopes[scope] {
				errs = append(errs, fmt.Errorf("secrets.machine_auth[%d].scopes contains duplicate %q", i, scope))
			}
			seenScopes[scope] = true
		}
		hasScopesClaim := strings.TrimSpace(m.ScopesClaim) != ""
		if !hasScopes && !hasScopesClaim {
			errs = append(errs, fmt.Errorf("secrets.machine_auth[%d] must set scopes or scopes_claim so a successful login has explicit least-privilege authority", i))
		}
		if hasScopes && hasScopesClaim {
			errs = append(errs, fmt.Errorf("secrets.machine_auth[%d] must not set both scopes and scopes_claim; choose one permission authority", i))
		}
		if hasScopesClaim && name != "oidc" && name != "jwt" {
			errs = append(errs, fmt.Errorf("secrets.machine_auth[%d].scopes_claim is supported only for oidc or jwt", i))
		}
		if name == "aws-iam" {
			if strings.TrimSpace(m.TenantID) == "" {
				errs = append(errs, fmt.Errorf("secrets.machine_auth[%d].tenant_id is required for aws-iam because STS has no trstctl tenant claim", i))
			}
			if len(m.AllowedAccounts) == 0 && len(m.AllowedARNs) == 0 {
				errs = append(errs, fmt.Errorf("secrets.machine_auth[%d] aws-iam requires allowed_accounts or allowed_arns", i))
			}
			continue
		}
		if strings.TrimSpace(m.TenantID) == "" && strings.TrimSpace(m.TenantClaim) == "" {
			errs = append(errs, fmt.Errorf("secrets.machine_auth[%d] must set tenant_id or tenant_claim", i))
		}
		if strings.TrimSpace(m.Audience) == "" {
			errs = append(errs, fmt.Errorf("secrets.machine_auth[%d].audience is required", i))
		}
		if strings.TrimSpace(m.JWKSFile) == "" && strings.TrimSpace(m.JWKSJSON) == "" {
			errs = append(errs, fmt.Errorf("secrets.machine_auth[%d] requires jwks_file or jwks_json", i))
		}
		if strings.TrimSpace(m.JWKSFile) != "" && strings.TrimSpace(m.JWKSJSON) != "" {
			errs = append(errs, fmt.Errorf("secrets.machine_auth[%d] must set only one of jwks_file or jwks_json", i))
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
		errs = append(errs, errors.New("ca.governance_mode=regulated with ca.require_fips=true requires the FIPS 140-3 module to be active: build with GOFIPS140=v1.0.0 (make fips-build) or run with GODEBUG=fips140=on"))
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
	case u.Scheme == "http" && netsec.IsLoopbackHost(u.Hostname()):
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
	check("max_new_orders_per_account", q.MaxNewOrdersPerAccount)
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

func validateFederationConfig(c *Config) []error {
	var errs []error
	if _, err := c.Federation.IntervalDuration(); err != nil {
		errs = append(errs, fmt.Errorf("federation.interval %q is invalid: %w", c.Federation.Interval, err))
	}
	if _, err := c.Federation.RPODuration(); err != nil {
		errs = append(errs, fmt.Errorf("federation.rpo %q is invalid: %w", c.Federation.RPO, err))
	}
	if _, err := c.Federation.RTODuration(); err != nil {
		errs = append(errs, fmt.Errorf("federation.rto %q is invalid: %w", c.Federation.RTO, err))
	}
	if !c.Federation.Enabled {
		return errs
	}
	if strings.TrimSpace(c.Federation.ClusterID) == "" {
		errs = append(errs, errors.New("federation.cluster_id is required when federation.enabled is true"))
	}
	if len(c.Federation.Peers) == 0 {
		errs = append(errs, errors.New("federation.peers requires at least one peer when federation.enabled is true"))
	}
	for i, peer := range c.Federation.Peers {
		if strings.TrimSpace(peer.ID) == "" {
			errs = append(errs, fmt.Errorf("federation.peers[%d].id is required", i))
		}
		if peer.ID == c.Federation.ClusterID {
			errs = append(errs, fmt.Errorf("federation.peers[%d].id must not equal federation.cluster_id", i))
		}
		if strings.TrimSpace(peer.NATSURL) == "" {
			errs = append(errs, fmt.Errorf("federation.peers[%d].nats_url is required", i))
		}
	}
	for _, d := range []struct {
		name string
		val  time.Duration
	}{
		{"interval", mustDuration(c.Federation.IntervalDuration())},
		{"rpo", mustDuration(c.Federation.RPODuration())},
		{"rto", mustDuration(c.Federation.RTODuration())},
	} {
		if d.val <= 0 {
			errs = append(errs, fmt.Errorf("federation.%s must be positive", d.name))
		}
	}
	return errs
}

func validatePCASConfig(c *Config) []error {
	var errs []error
	parsePositive := func(name, value string, enabled bool) {
		if strings.TrimSpace(value) == "" {
			if enabled {
				errs = append(errs, fmt.Errorf("%s is required when enabled", name))
			}
			return
		}
		d, err := time.ParseDuration(value)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s %q is invalid: %w", name, value, err))
			return
		}
		if d <= 0 {
			errs = append(errs, fmt.Errorf("%s must be positive", name))
		}
	}
	parsePositive("pcas.delegation.refresh_interval", c.PCAS.Delegation.RefreshInterval, c.PCAS.Delegation.Enabled)
	parsePositive("pcas.checkpoints.interval", c.PCAS.Checkpoints.Interval, c.PCAS.Checkpoints.Enabled)
	parsePositive("pcas.monitors.interval", c.PCAS.Monitors.Interval, c.PCAS.Monitors.Enabled)
	parsePositive("pcas.retirement.interval", c.PCAS.Retirement.Interval, c.PCAS.Retirement.Enabled)
	parsePositive("pcas.retirement.validity_window", c.PCAS.Retirement.ValidityWindow, c.PCAS.Retirement.Enabled)
	if c.PCAS.Delegation.Enabled && strings.TrimSpace(c.PCAS.Delegation.SignerStoreDir) == "" {
		errs = append(errs, errors.New("pcas.delegation.signer_store_dir is required when pcas.delegation.enabled is true"))
	}
	if c.PCAS.Checkpoints.Enabled {
		if strings.TrimSpace(c.PCAS.Checkpoints.SigningKeyHandle) == "" {
			errs = append(errs, errors.New("pcas.checkpoints.signing_key_handle is required when pcas.checkpoints.enabled is true"))
		}
		if strings.TrimSpace(c.PCAS.Checkpoints.SigningAlgorithm) == "" {
			errs = append(errs, errors.New("pcas.checkpoints.signing_algorithm is required when pcas.checkpoints.enabled is true"))
		}
	}
	for _, worker := range []struct {
		enabled bool
		topic   string
		name    string
	}{
		{c.PCAS.Recovery.Enabled, c.PCAS.Recovery.OutboxTopic, "pcas.recovery"},
		{c.PCAS.Federation.Enabled, c.PCAS.Federation.OutboxTopic, "pcas.federation"},
		{c.PCAS.KEM.Enabled, c.PCAS.KEM.OutboxTopic, "pcas.kem"},
	} {
		if !worker.enabled {
			continue
		}
		if strings.TrimSpace(worker.topic) == "" {
			errs = append(errs, fmt.Errorf("%s.outbox_topic is required when enabled", worker.name))
		}
	}
	return errs
}

func mustDuration(d time.Duration, _ error) time.Duration { return d }

// validate reports the configuration problems of an enabled plugin surface. It is
// the fail-closed gate (SUPPLY-004): with no directory there is nothing to load,
// and with no trusted key a module could not be provenance-verified — both are
// hard startup errors rather than a silently unverified plugin path. Unknown
// capability names are rejected so a typo cannot silently grant nothing (or, in a
// future vocabulary, the wrong thing).
func (p Plugins) validate() []error {
	var errs []error
	if strings.TrimSpace(p.Dir) == "" && strings.TrimSpace(p.CADir) == "" && strings.TrimSpace(p.DNSDir) == "" && strings.TrimSpace(p.ConnectorDir) == "" {
		errs = append(errs, errors.New("one of plugins.dir, plugins.ca_dir, plugins.dns_dir, or plugins.connector_dir is required when plugins.enabled is true"))
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
	// bytes.TrimSpace, not strings.TrimSpace(string(...)): converting the secret to
	// a string here would reintroduce exactly the unwipeable copy this field's type
	// exists to prevent (AN-8). Trimming preserves the previous semantics, where a
	// whitespace-only client_secret counts as unset.
	if len(bytes.TrimSpace(o.ClientSecret)) > 0 && strings.TrimSpace(o.ClientSecretRef) != "" {
		errs = append(errs, errors.New("auth.oidc.client_secret and auth.oidc.client_secret_ref are mutually exclusive"))
	}
	if strings.TrimSpace(o.ClientSecretRef) != "" && strings.TrimSpace(o.ClientSecretTenant) == "" {
		errs = append(errs, errors.New("auth.oidc.client_secret_tenant is required when auth.oidc.client_secret_ref is set"))
	}
	if strings.TrimSpace(o.ClientSecretTenant) != "" && strings.TrimSpace(o.ClientSecretRef) == "" {
		errs = append(errs, errors.New("auth.oidc.client_secret_ref is required when auth.oidc.client_secret_tenant is set"))
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
		if err != nil || u.Host == "" || (u.Scheme != "https" && (u.Scheme != "http" || !netsec.IsLoopbackHost(u.Hostname()))) {
			errs = append(errs, fmt.Errorf("auth.oidc.%s %q must be an absolute https URL (http is allowed only for a loopback host)", e.name, e.v))
		}
	}
	if d, err := o.SessionTTLDuration(); err != nil {
		errs = append(errs, fmt.Errorf("auth.oidc.session_ttl %q is invalid: %w", o.SessionTTL, err))
	} else if d <= 0 {
		errs = append(errs, errors.New("auth.oidc.session_ttl must be positive"))
	}
	errs = append(errs, validateTenantMappings("auth.oidc", o.TenantMappings, o.TenantClaim, o.AllowDefaultTenant, o.DefaultTenant)...)
	return errs
}

func (s SAML) validate() []error {
	var errs []error
	req := func(v, name string) {
		if strings.TrimSpace(v) == "" {
			errs = append(errs, fmt.Errorf("auth.saml.%s is required when auth.saml.enabled is true", name))
		}
	}
	req(s.EntityID, "entity_id")
	req(s.MetadataURL, "metadata_url")
	req(s.ACSURL, "acs_url")
	req(s.SessionSecretFile, "session_secret_file")
	if strings.TrimSpace(s.IDPMetadataFile) == "" && strings.TrimSpace(s.IDPMetadataXML) == "" {
		errs = append(errs, errors.New("auth.saml requires idp_metadata_file or idp_metadata_xml (the IdP signing metadata) when enabled"))
	}
	for _, e := range []struct{ v, name string }{
		{s.EntityID, "entity_id"}, {s.MetadataURL, "metadata_url"}, {s.ACSURL, "acs_url"},
	} {
		if strings.TrimSpace(e.v) == "" {
			continue
		}
		u, err := url.Parse(e.v)
		if err != nil || u.Host == "" || (u.Scheme != "https" && (u.Scheme != "http" || !netsec.IsLoopbackHost(u.Hostname()))) {
			errs = append(errs, fmt.Errorf("auth.saml.%s %q must be an absolute https URL (http is allowed only for a loopback host)", e.name, e.v))
		}
	}
	if d, err := s.SessionTTLDuration(); err != nil {
		errs = append(errs, fmt.Errorf("auth.saml.session_ttl %q is invalid: %w", s.SessionTTL, err))
	} else if d <= 0 {
		errs = append(errs, errors.New("auth.saml.session_ttl must be positive"))
	}
	errs = append(errs, validateTenantMappings("auth.saml", s.TenantMappings, s.TenantClaim, s.AllowDefaultTenant, s.DefaultTenant)...)
	return errs
}

func (l LDAP) validate() []error {
	var errs []error
	req := func(v, name string) {
		if strings.TrimSpace(v) == "" {
			errs = append(errs, fmt.Errorf("auth.ldap.%s is required when auth.ldap.enabled is true", name))
		}
	}
	req(l.URL, "url")
	req(l.SessionSecretFile, "session_secret_file")
	req(l.GroupSearchBaseDN, "group_search_base_dn")
	req(l.GroupFilter, "group_filter")
	if strings.TrimSpace(l.GroupNameAttribute) == "" {
		errs = append(errs, errors.New("auth.ldap.group_name_attribute is required when auth.ldap.enabled is true"))
	}
	if strings.TrimSpace(l.UserDNTemplate) == "" {
		req(l.UserSearchBaseDN, "user_search_base_dn")
		req(l.UserFilter, "user_filter")
	}
	if strings.TrimSpace(l.BindPasswordFile) != "" && strings.TrimSpace(l.BindDN) == "" {
		errs = append(errs, errors.New("auth.ldap.bind_dn is required when auth.ldap.bind_password_file is set"))
	}
	if strings.TrimSpace(l.BindDN) != "" && strings.TrimSpace(l.BindPasswordFile) == "" {
		errs = append(errs, errors.New("auth.ldap.bind_password_file is required when auth.ldap.bind_dn is set"))
	}
	if strings.TrimSpace(l.URL) != "" {
		u, err := url.Parse(l.URL)
		if err != nil || u.Host == "" {
			errs = append(errs, fmt.Errorf("auth.ldap.url %q must be an absolute ldap:// or ldaps:// URL", l.URL))
		} else {
			switch u.Scheme {
			case "ldaps":
			case "ldap":
				if !netsec.IsLoopbackHost(u.Hostname()) {
					errs = append(errs, fmt.Errorf("auth.ldap.url %q uses plaintext ldap://; use ldaps:// for non-loopback directories", l.URL))
				}
			default:
				errs = append(errs, fmt.Errorf("auth.ldap.url %q must use ldap:// or ldaps://", l.URL))
			}
		}
	}
	if d, err := l.SessionTTLDuration(); err != nil {
		errs = append(errs, fmt.Errorf("auth.ldap.session_ttl %q is invalid: %w", l.SessionTTL, err))
	} else if d <= 0 {
		errs = append(errs, errors.New("auth.ldap.session_ttl must be positive"))
	}
	if d, err := l.TimeoutDuration(); err != nil {
		errs = append(errs, fmt.Errorf("auth.ldap.timeout %q is invalid: %w", l.Timeout, err))
	} else if d <= 0 {
		errs = append(errs, errors.New("auth.ldap.timeout must be positive"))
	}
	errs = append(errs, validateTenantMappings("auth.ldap", l.TenantMappings, "", l.AllowDefaultTenant, l.DefaultTenant)...)
	return errs
}

func (s SCIM) validate() []error {
	var errs []error
	if len(s.Tokens) == 0 {
		errs = append(errs, errors.New("auth.scim.tokens requires at least one tenant-bound token when auth.scim.enabled is true"))
	}
	for i, tok := range s.Tokens {
		if strings.TrimSpace(tok.TenantID) == "" {
			errs = append(errs, fmt.Errorf("auth.scim.tokens[%d].tenant_id is required", i))
		}
		if strings.TrimSpace(tok.TokenFile) == "" {
			errs = append(errs, fmt.Errorf("auth.scim.tokens[%d].token_file is required", i))
		}
	}
	return errs
}

func (a ABAC) validate() []error {
	var errs []error
	if strings.TrimSpace(a.Module) == "" {
		errs = append(errs, errors.New("auth.abac.module is required when auth.abac.enabled is true"))
	}
	for k := range a.Environment {
		if strings.TrimSpace(k) == "" {
			errs = append(errs, errors.New("auth.abac.environment keys must be non-empty"))
		}
	}
	return errs
}

func (b Breakglass) validate() []error {
	var errs []error
	if strings.TrimSpace(b.CACertFile) == "" {
		errs = append(errs, errors.New("breakglass.ca_cert_file is required when breakglass.enabled is true"))
	}
	if strings.TrimSpace(b.PublicKeyFile) == "" {
		errs = append(errs, errors.New("breakglass.public_key_file is required when breakglass.enabled is true"))
	}
	if !b.OnlineEnabled {
		return errs
	}
	if !b.Enabled {
		errs = append(errs, errors.New("breakglass.enabled must be true when breakglass.online_enabled is true"))
	}
	if strings.TrimSpace(b.TenantID) == "" {
		errs = append(errs, errors.New("breakglass.tenant_id is required when breakglass.online_enabled is true"))
	}
	if strings.TrimSpace(b.SignerHandle) == "" {
		errs = append(errs, errors.New("breakglass.signer_handle is required when breakglass.online_enabled is true"))
	}
	if b.Threshold < 2 {
		errs = append(errs, errors.New("breakglass.threshold must be at least 2 when breakglass.online_enabled is true"))
	}
	seen := map[string]bool{}
	for i, operator := range b.Operators {
		operator = strings.TrimSpace(operator)
		if operator == "" {
			errs = append(errs, fmt.Errorf("breakglass.operators[%d] must be non-empty", i))
			continue
		}
		if seen[operator] {
			errs = append(errs, fmt.Errorf("breakglass.operators contains duplicate %q", operator))
		}
		seen[operator] = true
	}
	if len(seen) < b.Threshold {
		errs = append(errs, fmt.Errorf("breakglass.operators must contain at least threshold=%d distinct operators", b.Threshold))
	}
	return errs
}

func validateTenantMappings(prefix string, mappings []TenantMapping, tenantClaim string, allowDefault bool, defaultTenant string) []error {
	var errs []error
	// There must be SOME way to resolve a tenant, otherwise every login fails closed:
	// a tenant claim, a mappings table, or an explicit allowed default.
	hasMapping := len(mappings) > 0 || strings.TrimSpace(tenantClaim) != "" || (allowDefault && strings.TrimSpace(defaultTenant) != "")
	if !hasMapping {
		errs = append(errs, fmt.Errorf("%s needs a tenant mapping when enabled: set tenant_claim, tenant_mappings, or allow_default_tenant+default_tenant — otherwise every login fails closed", prefix))
	}
	for i, m := range mappings {
		keys := 0
		for _, k := range []string{m.Subject, m.Claim, m.Group} {
			if strings.TrimSpace(k) != "" {
				keys++
			}
		}
		if keys != 1 {
			errs = append(errs, fmt.Errorf("%s.tenant_mappings[%d] must set exactly one of subject/claim/group", prefix, i))
		}
		if strings.TrimSpace(m.TenantID) == "" {
			errs = append(errs, fmt.Errorf("%s.tenant_mappings[%d].tenant_id is required", prefix, i))
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
