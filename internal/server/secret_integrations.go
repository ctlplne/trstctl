// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"trstctl.com/trstctl/internal/accessconsole"
	"trstctl.com/trstctl/internal/accessdesktop"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/cloudauth"
	"trstctl.com/trstctl/internal/cloudhttp"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mongosignin"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/pgsignin"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
	"trstctl.com/trstctl/internal/dbaccess"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/egress"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/rotation"
	"trstctl.com/trstctl/internal/secretsync"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/synctarget"
	"trstctl.com/trstctl/internal/tenantseal"
)

// DynamicSecretProviderRegistry is the production registry assembled by
// buildRunDeps. Providers are tenant-bound in configuration and are never exposed
// to another tenant's lease engine.
type DynamicSecretProviderRegistry map[string][]dynsecret.Provider

// ForTenant returns an isolated copy of the provider slice for tenantID.
func (r DynamicSecretProviderRegistry) ForTenant(tenantID string) []dynsecret.Provider {
	return append([]dynsecret.Provider(nil), r[tenantID]...)
}

// TenantIDs returns deterministic configured tenant ids for restart-time lease
// expiry recovery before any tenant makes a new API request.
func (r DynamicSecretProviderRegistry) TenantIDs() []string {
	out := make([]string, 0, len(r))
	for tenantID := range r {
		out = append(out, tenantID)
	}
	sort.Strings(out)
	return out
}

// SecretSyncTargetRegistry is the tenant-bound production target registry.
type SecretSyncTargetRegistry map[string]map[string]*secretsync.Target

// ForTenant returns an isolated target map for tenantID.
func (r SecretSyncTargetRegistry) ForTenant(tenantID string) map[string]*secretsync.Target {
	out := make(map[string]*secretsync.Target, len(r[tenantID]))
	for id, target := range r[tenantID] {
		out[id] = target
	}
	return out
}

type integrationCredentialResolver struct {
	store  *store.Store
	kek    seal.KeyWrapper
	crypto tenantseal.Access
}

// resolve loads one authority-bearing value at operation time. file: refs are
// custody-checked by secretfile; secret:// refs are tenant-scoped RLS reads and
// opened with the same AAD used by the served secret store. The result is a
// locked/non-dumpable lease; the caller must Destroy it on every path.
func (r integrationCredentialResolver) resolve(ctx context.Context, tenantID, ref string) (*secret.Buffer, error) {
	ref = strings.TrimSpace(ref)
	switch {
	case strings.HasPrefix(ref, "file:"):
		value, err := secretfile.Load(strings.TrimSpace(strings.TrimPrefix(ref, "file:")))
		if err != nil {
			return nil, fmt.Errorf("load credential file: %w", err)
		}
		locked, lockErr := secret.NewFrom(value)
		secret.Wipe(value)
		if lockErr != nil {
			return nil, fmt.Errorf("lock credential file value: %w", lockErr)
		}
		return locked, nil
	case strings.HasPrefix(ref, "secret://"):
		if r.store == nil || r.kek == nil {
			return nil, errors.New("server: secret:// credential refs require store and KEK")
		}
		name := strings.Trim(strings.TrimPrefix(ref, "secret://"), "/")
		if name == "" {
			return nil, errors.New("server: empty secret:// credential ref")
		}
		var value []byte
		err := withTenantCipher(ctx, r.crypto, r.kek, tenantID, func(_ context.Context, cipher tenantseal.Cipher) (err error) {
			rec, err := r.store.GetSecret(ctx, tenantID, name)
			if err != nil {
				return fmt.Errorf("load tenant credential %q: %w", name, err)
			}
			value, err = cipher.Open(rec.Sealed, secretIntegrationStoreAAD(tenantID, name))
			return err
		})
		if err != nil {
			return nil, fmt.Errorf("open tenant credential %q: %w", name, err)
		}
		locked, lockErr := secret.NewFrom(value)
		secret.Wipe(value)
		if lockErr != nil {
			return nil, fmt.Errorf("lock tenant credential %q: %w", name, lockErr)
		}
		return locked, nil
	default:
		return nil, errors.New("server: credential ref must use file: or secret://")
	}
}

// ResolveNotificationCredential opens a tenant notification channel's
// credential reference for one delivery (A98, notify.CredentialResolver).
func (r integrationCredentialResolver) ResolveNotificationCredential(ctx context.Context, tenantID, ref string) (*secret.Buffer, error) {
	return r.resolve(ctx, tenantID, ref)
}

func secretIntegrationStoreAAD(tenantID, name string) []byte {
	// Keep this wire-compatible with api.sealAAD. This scope is part of the
	// secret-store ciphertext format, not an alternate storage path.
	return []byte(tenantID + "/secret-store/" + name)
}

// dynamicSecretProvidersFromConfig turns every configured backend into a real,
// tenant-bound provider reachable from the shipped server. Admin credentials and
// network clients are deliberately reopened for each operation instead of being
// retained for the process lifetime.
func dynamicSecretProvidersFromConfig(
	_ context.Context,
	entries []config.DynamicSecretProviderConfig,
	st *store.Store,
	kek seal.KeyWrapper,
	guard *egress.Guard,
	tenantCrypto ...tenantseal.Access,
) (DynamicSecretProviderRegistry, error) {
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: entries}, true); err != nil {
		return nil, fmt.Errorf("server: invalid dynamic-secret provider config: %w", err)
	}
	registry := DynamicSecretProviderRegistry{}
	var access tenantseal.Access
	if len(tenantCrypto) > 0 {
		access = tenantCrypto[0]
	}
	resolver := integrationCredentialResolver{store: st, kek: kek, crypto: access}
	seen := map[string]bool{}
	for _, entry := range entries {
		key := entry.TenantID + "\x00" + entry.ID
		if seen[key] {
			return nil, fmt.Errorf("server: duplicate dynamic-secret provider %s/%s", entry.TenantID, entry.ID)
		}
		seen[key] = true
		maxTTL, err := entry.MaxTTLDuration()
		if err != nil {
			return nil, fmt.Errorf("server: dynamic-secret provider %s/%s max_ttl: %w", entry.TenantID, entry.ID, err)
		}
		if maxTTL <= 0 {
			return nil, fmt.Errorf("server: dynamic-secret provider %s/%s max_ttl must be positive", entry.TenantID, entry.ID)
		}
		if strings.TrimSpace(entry.Endpoint) != "" {
			if _, err := secretIntegrationHTTPClient(entry.Endpoint, entry.AllowPrivate, entry.AllowInsecureLoopback, entry.PrivateEgressCIDRs, guard); err != nil {
				return nil, fmt.Errorf("server: dynamic-secret provider %s/%s endpoint: %w", entry.TenantID, entry.ID, err)
			}
		}
		if strings.TrimSpace(entry.IAMEndpoint) != "" {
			if _, err := secretIntegrationHTTPClient(entry.IAMEndpoint, entry.AllowPrivate, entry.AllowInsecureLoopback, entry.PrivateEgressCIDRs, guard); err != nil {
				return nil, fmt.Errorf("server: dynamic-secret provider %s/%s iam_endpoint: %w", entry.TenantID, entry.ID, err)
			}
		}
		allowed := make(map[string]bool, len(entry.AllowedRoles))
		for _, role := range entry.AllowedRoles {
			role = strings.TrimSpace(role)
			if role != "" {
				allowed[role] = true
			}
		}
		if entry.TenantID == "" || entry.ID == "" || len(allowed) == 0 {
			return nil, fmt.Errorf("server: dynamic-secret provider requires tenant, id, and allowed roles")
		}
		provider := newConfiguredDynamicProvider(entry, allowed, maxTTL, resolver, guard)
		registry[entry.TenantID] = append(registry[entry.TenantID], provider)
	}
	return registry, nil
}

type configuredDynamicProvider struct {
	reconcileMode  bool
	rotationBindDN string
	id             string
	tenantID       string
	cfg            config.DynamicSecretProviderConfig
	allowedRoles   map[string]bool
	maxTTL         time.Duration
	// configurationRevision is a runtime-scoped, non-secret identity for the
	// exact validated provider attachment. A restart creates a new identity, so
	// an old review cannot authorize work against replacement configuration.
	configurationRevision string
	credentials           integrationCredentialResolver
	guard                 *egress.Guard
	open                  func(context.Context) (requestDynamicBackend, func(), error)
}

// newConfiguredDynamicProvider assembles the concrete backend opener now, while
// retaining credential resolution until the outbox worker performs one operation.
// This keeps authority-bearing bytes short-lived and makes every shipped backend
// constructor part of buildRunDeps' production call graph.
func newConfiguredDynamicProvider(cfg config.DynamicSecretProviderConfig, allowed map[string]bool, maxTTL time.Duration, credentials integrationCredentialResolver, guard *egress.Guard) dynsecret.Provider {
	if cfg.DirectoryMode == "active_directory" {
		cfg.ADReconcile = copyADReconcileConfig(cfg.ADReconcile)
		names := make(map[string]string, len(cfg.ADLogonNames))
		for ref, name := range cfg.ADLogonNames {
			names[ref] = name
		}
		cfg.ADLogonNames = names
		bindings := make(map[string]string, len(cfg.RoleBindings))
		for role, dn := range cfg.RoleBindings {
			bindings[role] = dn
		}
		cfg.RoleBindings = bindings
		pairs := make(map[string][]string, len(cfg.RotationAccounts))
		for role, pair := range cfg.RotationAccounts {
			pairs[role] = append([]string(nil), pair...)
		}
		cfg.RotationAccounts = pairs
	}

	if cfg.Gateway != nil {
		gateway := *cfg.Gateway
		gateway.Scopes = append([]string(nil), cfg.Gateway.Scopes...)
		cfg.Gateway = &gateway
	}

	if cfg.Desktop != nil {
		binding := *cfg.Desktop
		binding.Accounts = append([]accessdesktop.BoundAccount(nil), binding.Accounts...)
		cfg.Desktop = &binding
	}
	if cfg.Console != nil {
		binding := *cfg.Console
		cfg.Console = &binding
	}

	provider := &configuredDynamicProvider{
		id: cfg.ID, tenantID: cfg.TenantID, cfg: cfg,
		allowedRoles: allowed, maxTTL: maxTTL, configurationRevision: uuid.NewString(),
		credentials: credentials, guard: guard,
	}
	provider.open = func(ctx context.Context) (requestDynamicBackend, func(), error) {
		return openConfiguredDynamicBackend(ctx, provider)
	}
	if cfg.Type == "ldap" && cfg.DirectoryMode == "active_directory" {
		return &configuredADRotationProvider{configuredDynamicProvider: provider}
	}
	if cfg.Type == "windows" && cfg.WindowsHostAgentID != "" {
		bindings := make(map[string]string, len(cfg.RoleBindings))
		for k, v := range cfg.RoleBindings {
			bindings[k] = v
		}
		provider.cfg.RoleBindings = bindings
		return &configuredWindowsLocalRotationProvider{configuredDynamicProvider: provider}
	}
	if cfg.Type == "gcp-iam" {
		return &configuredPreparedDynamicProvider{configuredDynamicProvider: provider}
	}
	if cfg.Type == "ssh-certificate" {
		roles := make(map[string]config.SSHCertificateRole, len(cfg.SSHRoles))
		for name, role := range cfg.SSHRoles {
			role.Principals = append([]string(nil), role.Principals...)
			role.Extensions = cloneSSHStringMap(role.Extensions)
			role.CriticalOptions = cloneSSHStringMap(role.CriticalOptions)
			roles[name] = role
		}
		provider.cfg.SSHRoles = roles
		return &configuredSSHCertificateProvider{configuredDynamicProvider: provider}
	}
	switch cfg.Type {
	case "iosxe", "junos", "eos", "fortigate", "bigip", "redfish", "esxi", "vcenter-sso", "okta-user", "entra-user", "google-workspace-user":
		return &configuredNetworkDeviceProvider{configuredDynamicProvider: provider}
	}
	return provider
}

func (p *configuredDynamicProvider) Name() string { return p.id }

// DynamicSecretTOTPSeed is a TOTP provider's seed reference and code
// parameters (A239-L5): where a replacement seed is stored, and how its proof
// code is checked. ok is false for every other type.
func (p *configuredDynamicProvider) DynamicSecretTOTPSeed() (ref string, digits int, period time.Duration, algorithm string, ok bool) {
	if p.cfg.Type != "totp" {
		return "", 0, 0, "", false
	}
	if raw := strings.TrimSpace(p.cfg.Period); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil {
			return "", 0, 0, "", false
		}
		period = parsed
	}
	return strings.TrimSpace(p.cfg.SeedRef), p.cfg.Digits, period, p.cfg.Algorithm, true
}

// DynamicSecretProviderType is the non-secret backend family displayed by the
// operator review. It deliberately does not expose endpoint or credential refs.
func (p *configuredDynamicProvider) DynamicSecretProviderType() string { return p.cfg.Type }

// AWS STS has no idempotency token or lookup by our lease ID, and neither has an
// OAuth token endpoint. The outbox must retain an at-most-once effect claim
// around AssumeRole or the token request so a lost response can never mint a
// second live credential for the same lease.
func (p *configuredDynamicProvider) DynamicSecretNeedsAtMostOnceEffect() bool {
	switch p.cfg.Type {
	case "aws-iam", "aws-sts", "oauth-client-credentials", "tailscale", "github-app":
		return true
	}
	return false
}

// DynamicSecretIndeterminateIssue states what may exist upstream after an
// at-most-once issuance whose outcome is unknown, and what the operator does
// before issuing another credential.
func (p *configuredDynamicProvider) DynamicSecretIndeterminateIssue() string {
	if p.cfg.Type == "oauth-client-credentials" {
		return fmt.Sprintf("OAuth token request outcome is indeterminate; an access token for client %q may exist for at most %s from the request. Revoke it at the authorization server or let it expire before issuing another credential", p.cfg.ClientID, p.maxTTL)
	}
	if p.cfg.Type == "tailscale" {
		return fmt.Sprintf("Tailscale auth key creation outcome is indeterminate; a key whose description starts with \"trstctl \" (the lease's digest follows) may exist for at most %s. Delete it in the admin console before issuing another credential", p.maxTTL)
	}
	if p.cfg.Type == "github-app" {
		return fmt.Sprintf("GitHub installation token request outcome is indeterminate; a token for installation %s may exist until one hour after the request (GitHub lists no installation tokens). Wait for that expiry, or suspend the installation, before issuing another credential", p.cfg.InstallationID)
	}
	return awsSTSIndeterminateIssue
}

// DynamicSecretRevocation is "confirmed" when revoking a lease ends its
// credential upstream before its native expiry, and "ttl_only" when the
// credential lapses only then. An OAuth provider is confirmed only with a
// revocation endpoint (A239).
func (p *configuredDynamicProvider) DynamicSecretRevocation() string {
	if (p.cfg.Type == "aws-sts" || p.cfg.Type == "aws-iam") && p.cfg.RevokeWithDenyPolicy {
		// N3: a revoked session is denied through its role before it expires.
		return dynsecret.RevocationMethodDenyPolicy
	}
	if p.cfg.Type == "oauth-client-credentials" {
		if p.cfg.RevocationEndpoint != "" {
			return "confirmed"
		}
		return "ttl_only"
	}
	return ""
}

// DynamicSecretEnvironment is the secrets environment the operator placed
// the provider in, "<project>/<environment>", or empty (A235-L2).
func (p *configuredDynamicProvider) DynamicSecretEnvironment() string {
	return strings.TrimSpace(p.cfg.SecretEnvironment)
}

// DynamicSecretAllowedRoles returns only operator-selectable role names.
// Provider-native bindings remain startup-owned and do not cross the API seam.
func (p *configuredDynamicProvider) DynamicSecretAllowedRoles() []string {
	roles := make([]string, 0, len(p.allowedRoles))
	for role := range p.allowedRoles {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	return roles
}

// DynamicSecretConfigurationRevision binds a review to this process's exact
// validated provider attachment without disclosing topology or authority refs.
func (p *configuredDynamicProvider) DynamicSecretConfigurationRevision() string {
	return p.configurationRevision
}

// DynamicSecretGatewayUpstream is where an access gateway reaches a
// provider's server for a session whose credential names no address (A256):
// ClickHouse's HTTP endpoint (verified against the system roots), or a
// cluster's API server with its CA and server name. Other types answer an
// empty endpoint.
func (p *configuredDynamicProvider) DynamicSecretGatewayUpstream(ctx context.Context) (string, []byte, string, error) {
	switch p.cfg.Type {
	case "aws-sts", "gcp-iam", "azure-entra":
		if p.cfg.Gateway == nil {
			return "", nil, "", errors.New("cloud provider has no gateway endpoint")
		}
		return p.cfg.Gateway.Endpoint, nil, "", nil
	case "clickhouse", "snowflake":
		return p.cfg.Endpoint, nil, "", nil
	case "kubernetes":
		var caPEM []byte
		if p.cfg.KubernetesTLSCARef != "" {
			var err error
			if caPEM, err = p.publicCredential(ctx, p.cfg.KubernetesTLSCARef); err != nil {
				return "", nil, "", fmt.Errorf("the cluster CA: %w", err)
			}
		}
		return p.cfg.Endpoint, caPEM, p.cfg.KubernetesTLSServerName, nil
	}
	return "", nil, "", nil
}

// DynamicSecretGatewayTLS is how an access gateway verifies a database
// target's TLS when it signs in for a session (A256-L1): the CA and the
// certificate name the provider itself trusts. A Redis provider names them
// (redis_tls_ca_ref, redis_tls_server_name); a PostgreSQL or MongoDB
// provider's administrator connection names its root file (sslrootcert,
// tlsCAFile), a path on the control plane's host that the gateway's host may
// not share, so the file is read here and carried with the session. A CA
// certificate is public. Nothing named: none, and the gateway verifies
// against what the session's credential names, or the system roots.
func (p *configuredDynamicProvider) DynamicSecretGatewayTLS(ctx context.Context) ([]byte, string, error) {
	switch p.cfg.Type {
	case "redis":
		if p.cfg.RedisTLSCARef == "" {
			return nil, p.cfg.RedisTLSServerName, nil
		}
		caPEM, err := p.publicCredential(ctx, p.cfg.RedisTLSCARef)
		if err != nil {
			return nil, "", fmt.Errorf("the Redis CA: %w", err)
		}
		return caPEM, p.cfg.RedisTLSServerName, nil
	case "postgresql", "mongodb":
		if p.cfg.AdminDSNRef == "" {
			return nil, "", nil
		}
		buf, err := p.credentials.resolve(ctx, p.tenantID, p.cfg.AdminDSNRef)
		if err != nil {
			return nil, "", fmt.Errorf("the administrator connection: %w", err)
		}
		defer buf.Destroy()
		var rootFile string
		err = buf.Use(func(dsn []byte) error {
			if p.cfg.Type == "postgresql" {
				target, err := pgsignin.ParseDSN(dsn)
				if err != nil {
					return nil // a DSN the sign-in can't read names no root file
				}
				defer target.Wipe()
				if target.SSLRootCert != "system" {
					rootFile = target.SSLRootCert
				}
				return nil
			}
			target, err := mongosignin.ParseURI(dsn)
			if err != nil {
				return nil
			}
			defer target.Wipe()
			rootFile = target.TLSCAFile
			return nil
		})
		if err != nil || rootFile == "" {
			return nil, "", err
		}
		caPEM, err := os.ReadFile(rootFile) // #nosec G304 -- the operator's own administrator DSN names this root file on the control plane's host (CWE-22)
		if err != nil {
			return nil, "", fmt.Errorf("the administrator connection's root file cannot be read")
		}
		return caPEM, "", nil
	}
	return nil, "", nil
}

// publicCredential resolves a reference to public material (a CA
// certificate), which may then leave its locked buffer as plain bytes.
func (p *configuredDynamicProvider) publicCredential(ctx context.Context, ref string) ([]byte, error) {
	buf, err := p.credentials.resolve(ctx, p.tenantID, ref)
	if err != nil {
		return nil, err
	}
	defer buf.Destroy()
	var out []byte
	err = buf.Use(func(b []byte) error {
		out = append([]byte(nil), b...)
		return nil
	})
	return out, err
}

// DynamicSecretDatabase is the database a provider grants its accounts on (a
// MongoDB session's console runs there unless a command names $db).
func (p *configuredDynamicProvider) DynamicSecretDatabase() string { return p.cfg.Database }

// DynamicSecretKubernetesScope is the namespace a kubernetes provider creates
// its ServiceAccounts in and the audience of their tokens, which the
// Vault-compatible API reports and checks.
func (p *configuredDynamicProvider) DynamicSecretKubernetesScope() (namespace, audience string) {
	namespace = p.cfg.Namespace
	if namespace == "" {
		namespace = "default"
	}
	return namespace, p.cfg.KubernetesAudience
}

// DynamicSecretBindsRole reports whether role binds exactly this
// provider-native authority (the IAM role ARN an AWS role assumes), without
// handing the binding across the API seam.
func (p *configuredDynamicProvider) DynamicSecretBindsRole(role, binding string) bool {
	configured, ok := p.cfg.RoleBindings[role]
	return ok && configured != "" && configured == binding
}

// MaximumTTL is the provider credential's hard native-validity bound. The
// durable lifecycle creates native credentials for this duration, then manages a
// shorter renewable control-plane lease within it.
func (p *configuredDynamicProvider) MaximumTTL() time.Duration { return p.maxTTL }

func (p *configuredDynamicProvider) Generate(ctx context.Context, req dynsecret.GenerateRequest) (dynsecret.Credential, error) {
	if p.reconcileMode {
		return dynsecret.Credential{}, errors.New("server: designated AD authority requires an exact sealed preparation")
	}
	return p.generate(ctx, req, nil)
}

func (p *configuredDynamicProvider) generate(ctx context.Context, req dynsecret.GenerateRequest, prepared []byte) (dynsecret.Credential, error) {
	if p.cfg.DirectoryMode == "active_directory" && !req.Static {
		return dynsecret.Credential{}, p.beforeDynamicReceiver(errors.New("active_directory is an existing vaulted-account profile; dynamic user issuance is not supported"))
	}

	if req.Role == dynsecret.DecoyRole && p.cfg.Type != "postgresql" {
		// Other backends would read the unknown role as read-write.
		return dynsecret.Credential{}, p.beforeDynamicReceiver(fmt.Errorf("dynamic-secret provider %q cannot mint decoy logins: only PostgreSQL providers can", p.id))
	}
	if !p.allowedRoles[req.Role] {
		return dynsecret.Credential{}, p.beforeDynamicReceiver(fmt.Errorf("dynamic-secret provider %q does not allow role %q", p.id, req.Role))
	}
	switch {
	case req.Static && !p.AllowsStaticRotation(req.Role):
		return dynsecret.Credential{}, p.beforeDynamicReceiver(fmt.Errorf("dynamic-secret provider %q does not allow static rotation", p.id))
	case req.Static:
		// A static credential carries no TTL: the static-rotation worker retires
		// it after its successor is live, so the lease ceiling does not apply.
	case req.TTL <= 0 || req.TTL > p.maxTTL:
		return dynsecret.Credential{}, p.beforeDynamicReceiver(fmt.Errorf("dynamic-secret provider %q TTL must be between 1s and %s", p.id, p.maxTTL))
	}
	backend, closeBackend, err := p.openBackend(ctx)
	if err != nil {
		return dynsecret.Credential{}, p.beforeDynamicReceiver(err)
	}
	defer closeBackend()
	var ref string
	var value []byte
	if len(prepared) > 0 {
		preparedBackend, ok := backend.(dynsecret.PreparedRequestBackend)
		if !ok {
			return dynsecret.Credential{}, fmt.Errorf("dynamic-secret provider %q does not accept its durable preparation", p.id)
		}
		ref, value, err = preparedBackend.CreatePreparedCredential(ctx, req, prepared)
	} else {
		ref, value, err = backend.CreateCredential(ctx, req)
	}
	if err != nil {
		return dynsecret.Credential{}, err
	}
	return dynsecret.Credential{
		BackendRef: ref,
		Secret:     value,
		Metadata:   map[string]string{"role": req.Role, "provider_type": p.cfg.Type},
	}, nil
}

func (p *configuredDynamicProvider) beforeDynamicReceiver(err error) error {
	if p.DynamicSecretNeedsAtMostOnceEffect() {
		return orchestrator.ConfirmedNoMutation(err)
	}
	return err
}

// configuredPreparedDynamicProvider is deliberately a separate concrete type:
// only GCP IAM implements dynsecret.PreparedProvider. Putting these methods on
// configuredDynamicProvider makes every database/cloud backend satisfy that
// interface and causes the worker to reject their intentionally empty
// preparation before it ever calls the real provider.
type configuredPreparedDynamicProvider struct{ *configuredDynamicProvider }

// Prepare creates the stable local key pair that GCP's upload API can find on a
// retry after an ambiguous response.
func (p *configuredPreparedDynamicProvider) Prepare(_ context.Context, req dynsecret.GenerateRequest) ([]byte, error) {
	return dynsecret.PrepareGCPIAMCredential(req)
}

func (p *configuredPreparedDynamicProvider) GeneratePrepared(ctx context.Context, req dynsecret.GenerateRequest, prepared []byte) (dynsecret.Credential, error) {
	return p.generate(ctx, req, prepared)
}

func (p *configuredDynamicProvider) Revoke(ctx context.Context, backendRef string) error {
	switch p.cfg.Type {
	case "aws-iam", "aws-sts", "oauth-client-credentials", "github-app":
		// The reference alone can't end these credentials: they lapse at their
		// native expiry (an OAuth or GitHub token is revoked by presenting it,
		// through RevokeCredential).
		return dynsecret.CheckNativeExpiration(backendRef, time.Now())
	}
	backend, closeBackend, err := p.openBackend(ctx)
	if err != nil {
		return err
	}
	defer closeBackend()
	return backend.Revoke(ctx, backendRef)
}

// RevokeMethod revokes like Revoke and, for an AWS STS lease, names how its
// session ended: denied through its role by an inline policy before its expiry
// when the provider has revoke_with_deny_policy (N3), else at its native
// expiry. A GitHub App or OAuth token revoked without its credential at hand
// lapses at its native expiry, and says so (OD-5). Other providers name no
// method.
func (p *configuredDynamicProvider) RevokeMethod(ctx context.Context, backendRef string) (string, error) {
	if p.cfg.Type == "github-app" || p.cfg.Type == "oauth-client-credentials" {
		if err := dynsecret.CheckNativeExpiration(backendRef, time.Now()); err != nil {
			return "", err
		}
		return dynsecret.RevocationMethodNativeExpiry, nil
	}
	if p.cfg.Type != "aws-sts" && p.cfg.Type != "aws-iam" {
		return "", p.Revoke(ctx, backendRef)
	}
	if !p.cfg.RevokeWithDenyPolicy {
		if err := dynsecret.CheckNativeExpiration(backendRef, time.Now()); err != nil {
			return "", err
		}
		return dynsecret.RevocationMethodNativeExpiry, nil
	}
	backend, closeBackend, err := p.openBackend(ctx)
	if err != nil {
		return "", err
	}
	defer closeBackend()
	revoker, ok := backend.(dynsecret.MethodRevoker)
	if !ok {
		return "", fmt.Errorf("server: dynamic-secret provider %q can't deny a session through its role", p.id)
	}
	return revoker.RevokeMethod(ctx, backendRef)
}

// RevokeCredentialMethod revokes like RevokeCredential and names how the
// token ended (OD-5): token_revoked when the provider confirmed it when it
// was presented (GitHub's DELETE /installation/token, an RFC 7009 revocation
// endpoint), native_expiry once an OAuth token without a revocation endpoint
// has lapsed.
func (p *configuredDynamicProvider) RevokeCredentialMethod(ctx context.Context, backendRef string, credential []byte) (string, error) {
	if !p.revocableByCredential() {
		return p.RevokeMethod(ctx, backendRef)
	}
	if err := p.RevokeCredential(ctx, backendRef, credential); err != nil {
		return "", err
	}
	return dynsecret.RevocationMethodTokenRevoked, nil
}

// revocableByCredential reports a provider whose token ends when presented:
// a GitHub App, or OAuth with a revocation endpoint.
func (p *configuredDynamicProvider) revocableByCredential() bool {
	return p.cfg.Type == "github-app" || (p.cfg.Type == "oauth-client-credentials" && p.cfg.RevocationEndpoint != "")
}

// RevokeCredential revokes a lease by presenting its credential (an OAuth access
// token at the RFC 7009 revocation endpoint). Without a revocation endpoint it
// is Revoke: the token lapses at its native expiry.
func (p *configuredDynamicProvider) RevokeCredential(ctx context.Context, backendRef string, credential []byte) error {
	if !p.revocableByCredential() {
		return p.Revoke(ctx, backendRef)
	}
	backend, closeBackend, err := p.openBackend(ctx)
	if err != nil {
		return err
	}
	defer closeBackend()
	revoker, ok := backend.(interface {
		RevokeCredential(context.Context, string, []byte) error
	})
	if !ok {
		return fmt.Errorf("server: dynamic-secret provider %q can't revoke by credential", p.id)
	}
	return revoker.RevokeCredential(ctx, backendRef, credential)
}

type requestDynamicBackend interface {
	CreateCredential(context.Context, dynsecret.GenerateRequest) (string, []byte, error)
	Revoke(context.Context, string) error
}

func (p *configuredDynamicProvider) openBackend(ctx context.Context) (requestDynamicBackend, func(), error) {
	if p.open == nil {
		return nil, func() {}, errors.New("server: dynamic-secret backend opener is not assembled")
	}
	return p.open(ctx)
}

func openConfiguredDynamicBackend(ctx context.Context, p *configuredDynamicProvider) (requestDynamicBackend, func(), error) {
	opener := &configuredDynamicBackendOpener{ctx: ctx, provider: p}
	switch p.cfg.Type {
	case "postgresql", "mysql", "mongodb", "redis", "ldap", "mssql", "azure-sql", "oracle", "hana":
		return openConfiguredDatabaseBackend(opener)
	case "kubernetes", "aws-iam", "aws-sts", "gcp-iam", "azure-entra":
		return openConfiguredCloudBackend(opener)
	case "totp":
		return openConfiguredTOTPBackend(opener)
	case "oauth-client-credentials":
		return openConfiguredOAuthBackend(opener)
	case "clickhouse":
		return openConfiguredClickHouseBackend(opener)
	case "elasticsearch":
		return openConfiguredElasticsearchBackend(opener)
	case "rabbitmq":
		return openConfiguredRabbitMQBackend(opener)
	case "kafka":
		return openConfiguredKafkaBackend(opener)
	case "github-app":
		return openConfiguredGitHubAppBackend(opener)
	case "snowflake":
		return openConfiguredSnowflakeBackend(opener)
	case "aws-elasticache", "aws-memorydb":
		return openConfiguredAWSCacheBackend(opener)
	case "ibm-api-connect":
		return openConfiguredAPIConnectBackend(opener)
	case "auth0":
		return openConfiguredAuth0Backend(opener)
	case "datadog":
		return openConfiguredDatadogBackend(opener)
	case "openai":
		return openConfiguredOpenAIBackend(opener)
	case "openrouter", "fireworks", "litellm", "supabase", "convex", "dbt", "cloudflare", "cloudflare-r2":
		return openConfiguredHostedKeyBackend(opener)
	case "okta", "databricks":
		return openConfiguredClientSecretBackend(opener)
	case "unix", "windows":
		return openConfiguredUnixBackend(opener)
	case "iosxe", "junos":
		return openConfiguredNetworkDeviceBackend(opener)
	case "eos", "fortigate", "bigip":
		return openConfiguredNetworkAPIBackend(opener)
	case "redfish":
		return openConfiguredRedfishBackend(opener)
	case "esxi":
		return openConfiguredESXiBackend(opener)
	case "vcenter-sso":
		return openConfiguredVCenterSSOBackend(opener)
	case "okta-user", "entra-user", "google-workspace-user":
		return openConfiguredIdPAdminBackend(opener)
	case "couchbase":
		return openConfiguredCouchbaseBackend(opener)
	case "milvus":
		return openConfiguredMilvusBackend(opener)
	case "tailscale":
		return openConfiguredTailscaleBackend(opener)
	case "mongodb-atlas":
		return openConfiguredMongoDBAtlasBackend(opener)
	case "cassandra":
		return openConfiguredCassandraBackend(opener)
	default:
		return opener.fail(fmt.Errorf("server: unsupported dynamic-secret backend type %q", p.cfg.Type))
	}
}

type configuredDynamicBackendOpener struct {
	ctx              context.Context
	provider         *configuredDynamicProvider
	credentialLeases []*secret.Buffer
}

func (o *configuredDynamicBackendOpener) resolve(ref string) ([]byte, error) {
	if strings.TrimSpace(ref) == "" {
		return nil, nil
	}
	value, err := o.provider.credentials.resolve(o.ctx, o.provider.tenantID, ref)
	if err != nil {
		return nil, err
	}
	o.credentialLeases = append(o.credentialLeases, value)
	return value.Bytes(), nil
}

func (o *configuredDynamicBackendOpener) destroyCredentials() {
	for _, value := range o.credentialLeases {
		value.Destroy()
	}
	o.credentialLeases = nil
}

func (o *configuredDynamicBackendOpener) closeWith(backend any, extra func()) func() {
	return func() {
		switch value := backend.(type) {
		case interface{ Close() }:
			value.Close()
		case interface{ Close() error }:
			_ = value.Close()
		}
		if extra != nil {
			extra()
		}
		o.destroyCredentials()
	}
}

func (o *configuredDynamicBackendOpener) fail(err error) (requestDynamicBackend, func(), error) {
	o.destroyCredentials()
	return nil, func() {}, err
}

func openConfiguredDatabaseBackend(o *configuredDynamicBackendOpener) (requestDynamicBackend, func(), error) {
	cfg := o.provider.cfg
	switch cfg.Type {
	case "postgresql":
		dsn, err := o.resolve(cfg.AdminDSNRef)
		if err != nil {
			return o.fail(err)
		}
		backend, err := dynsecret.NewPostgresBackend(dynsecret.PostgresConfig{
			DSN: dsn, Database: cfg.Database, Schema: cfg.Schema, UsernamePrefix: cfg.UsernamePrefix,
			RotationAccounts: o.provider.rotationAccountPairs(), DatabaseRoleAccess: o.provider.databaseRoleAccess(),
		})
		if err != nil {
			return o.fail(err)
		}
		return backend, o.closeWith(backend, nil), nil
	case "mysql":
		dsn, err := o.resolve(cfg.AdminDSNRef)
		if err != nil {
			return o.fail(err)
		}
		db, err := dynsecret.OpenMySQLExecutor(o.ctx, dsn)
		if err != nil {
			return o.fail(err)
		}
		backend, err := dynsecret.NewMySQLBackend(db, dynsecret.MySQLConfig{
			Database: cfg.Database, Addr: cfg.Addr, AccountHost: cfg.AccountHost,
			AllowWildcardAccountHost: cfg.AllowWildcardAccountHost, UsernamePrefix: cfg.UsernamePrefix,
			DatabaseRoleAccess: o.provider.databaseRoleAccess(),
		})
		if err != nil {
			_ = db.Close()
			return o.fail(err)
		}
		return backend, o.closeWith(backend, func() { _ = db.Close() }), nil
	case "mssql", "azure-sql", "oracle", "hana":
		return openConfiguredSQLDriverBackend(o)
	case "mongodb":
		uri, err := o.resolve(cfg.AdminDSNRef)
		if err != nil {
			return o.fail(err)
		}
		admin, err := dynsecret.OpenMongoAdmin(o.ctx, uri)
		if err != nil {
			return o.fail(err)
		}
		backend, err := dynsecret.NewMongoBackend(admin, dynsecret.MongoConfig{
			Database: cfg.Database, URI: uri, UsernamePrefix: cfg.UsernamePrefix,
			RotationAccounts: o.provider.rotationAccountPairs(), DatabaseRoleAccess: o.provider.databaseRoleAccess(),
		})
		if err != nil {
			_ = admin.Close(context.Background())
			return o.fail(err)
		}
		return backend, o.closeWith(backend, func() { _ = admin.Close(context.Background()) }), nil
	case "redis":
		password, err := o.resolve(cfg.PasswordRef)
		if err != nil {
			return o.fail(err)
		}
		var caPEM []byte
		if cfg.RedisTLSCARef != "" {
			caPEM, err = o.resolve(cfg.RedisTLSCARef)
			if err != nil {
				return o.fail(err)
			}
		}
		backend, err := dynsecret.NewRedisBackend(dynsecret.RedisConfig{
			Addr: cfg.Addr, Password: password, DB: cfg.DB, UsernamePrefix: cfg.UsernamePrefix,
			RolePolicies: cfg.RedisACLRoles, TLSCAPEM: caPEM,
			TLSServerName: cfg.RedisTLSServerName, AllowPlaintext: cfg.AllowPlaintextRedis,
		})
		if err != nil {
			return o.fail(err)
		}
		return backend, o.closeWith(backend, nil), nil
	case "ldap":
		password, err := o.resolve(cfg.PasswordRef)
		if err != nil {
			return o.fail(err)
		}
		caPEM, err := o.resolve(cfg.TLSCARef)
		if err != nil {
			return o.fail(err)
		}
		var reconcile *dynsecret.ADReconcileAuthority
		if o.provider.reconcileMode {
			if cfg.ADReconcile == nil {
				return o.fail(errors.New("server: designated AD authority is unavailable"))
			}
			reconcile = &dynsecret.ADReconcileAuthority{Principal: dynsecret.ADReconcilePrincipal{DN: cfg.BindDN, SID: cfg.ADReconcile.SID, GUID: cfg.ADReconcile.GUID}, RotationBindDN: o.provider.rotationBindDN}
		}
		backend, err := dynsecret.NewLDAPBackend(dynsecret.LDAPConfig{
			ADReconcile:   reconcile,
			DirectoryMode: cfg.DirectoryMode, Addr: cfg.Addr, TLSServerName: cfg.TLSServerName, TLSCAPEM: caPEM, AllowPlaintext: cfg.AllowPlaintext, StartTLS: cfg.StartTLS,
			BindDN: cfg.BindDN, BindPassword: password, UsersDN: cfg.UsersDN, RoleGroups: cfg.RoleBindings,
			UsernamePrefix: cfg.UsernamePrefix, RotationAccounts: o.provider.rotationAccountPairs(),
		})
		if err != nil {
			return o.fail(err)
		}
		return backend, o.closeWith(backend, nil), nil
	default:
		return o.fail(fmt.Errorf("server: unsupported database dynamic-secret backend type %q", cfg.Type))
	}
}

func openConfiguredCloudBackend(o *configuredDynamicBackendOpener) (requestDynamicBackend, func(), error) {
	cfg := o.provider.cfg
	switch cfg.Type {
	case "kubernetes":
		token, err := o.resolve(cfg.BearerTokenRef)
		if err != nil {
			return o.fail(err)
		}
		var caPEM []byte
		if cfg.KubernetesTLSCARef != "" {
			caPEM, err = o.resolve(cfg.KubernetesTLSCARef)
			if err != nil {
				return o.fail(err)
			}
		}
		client, err := secretIntegrationHTTPClientWithTLS(cfg.Endpoint, cfg.AllowPrivate, cfg.AllowInsecureLoopback, cfg.PrivateEgressCIDRs, caPEM, cfg.KubernetesTLSServerName, o.provider.guard)
		if err != nil {
			return o.fail(err)
		}
		backend, err := dynsecret.NewKubernetesBackend(dynsecret.KubernetesConfig{
			Endpoint: cfg.Endpoint, HTTPClient: client, Namespace: cfg.Namespace, Audience: cfg.KubernetesAudience,
			BearerToken: token, UsernamePrefix: cfg.UsernamePrefix, RoleBindings: cfg.RoleBindings,
		})
		if err != nil {
			return o.fail(err)
		}
		return backend, o.closeWith(backend, nil), nil
	case "aws-iam", "aws-sts":
		secretKey, err := o.resolve(cfg.SecretAccessRef)
		if err != nil {
			return o.fail(err)
		}
		session, err := o.resolve(cfg.SessionTokenRef)
		if err != nil {
			return o.fail(err)
		}
		client, err := secretIntegrationHTTPClient(cfg.Endpoint, cfg.AllowPrivate, cfg.AllowInsecureLoopback, cfg.PrivateEgressCIDRs, o.provider.guard)
		if err != nil {
			return o.fail(err)
		}
		iamEndpoint, _ := dynsecret.AWSIAMEndpointFor(cfg.Region, cfg.IAMEndpoint)
		iamClient, err := secretIntegrationHTTPClient(iamEndpoint, cfg.AllowPrivate, cfg.AllowInsecureLoopback, cfg.PrivateEgressCIDRs, o.provider.guard)
		if err != nil {
			return o.fail(err)
		}
		backend, err := dynsecret.NewAWSSTSBackend(dynsecret.AWSSTSConfig{
			Endpoint: cfg.Endpoint, HTTPClient: client, Region: cfg.Region,
			AccessKeyID: cfg.AccessKeyID, SecretAccessKey: secretKey, SessionToken: session,
			SessionPrefix: cfg.UsernamePrefix, RoleARNs: cfg.RoleBindings,
			IAMEndpoint: iamEndpoint, IAMHTTPClient: iamClient,
			RevokeWithDenyPolicy: cfg.RevokeWithDenyPolicy, AllowRoleChaining: cfg.AllowRoleChaining,
		})
		if err != nil {
			return o.fail(err)
		}
		return backend, o.closeWith(backend, nil), nil
	case "gcp-iam":
		token, err := o.resolve(cfg.BearerTokenRef)
		if err != nil {
			return o.fail(err)
		}
		client, err := secretIntegrationHTTPClient(cfg.Endpoint, cfg.AllowPrivate, cfg.AllowInsecureLoopback, cfg.PrivateEgressCIDRs, o.provider.guard)
		if err != nil {
			return o.fail(err)
		}
		policyEndpoint := cfg.IAMEndpoint
		if strings.TrimSpace(policyEndpoint) == "" {
			policyEndpoint = dynsecret.GCPPolicyEndpoint
		}
		policyClient, err := secretIntegrationHTTPClient(policyEndpoint, cfg.AllowPrivate, cfg.AllowInsecureLoopback, cfg.PrivateEgressCIDRs, o.provider.guard)
		if err != nil {
			return o.fail(err)
		}
		backend, err := dynsecret.NewGCPIAMBackend(dynsecret.GCPIAMConfig{
			Endpoint: cfg.Endpoint, HTTPClient: client, Project: cfg.Project,
			ServiceAccountEmail: cfg.ServiceAccount, BearerToken: token, UsernamePrefix: cfg.UsernamePrefix,
			PolicyEndpoint: policyEndpoint, PolicyHTTPClient: policyClient,
		})
		if err != nil {
			return o.fail(err)
		}
		return &requestBackendAdapter{Backend: backend}, o.closeWith(backend, nil), nil
	case "azure-entra":
		token, err := o.resolve(cfg.BearerTokenRef)
		if err != nil {
			return o.fail(err)
		}
		client, err := secretIntegrationHTTPClient(cfg.Endpoint, cfg.AllowPrivate, cfg.AllowInsecureLoopback, cfg.PrivateEgressCIDRs, o.provider.guard)
		if err != nil {
			return o.fail(err)
		}
		backend, err := dynsecret.NewAzureEntraBackend(dynsecret.AzureEntraConfig{
			Endpoint: cfg.Endpoint, HTTPClient: client, ApplicationObjectID: cfg.ApplicationObject,
			ApplicationClientID: cfg.ApplicationClient, TenantID: cfg.AzureTenant,
			BearerToken: token, UsernamePrefix: cfg.UsernamePrefix, AuthorityHost: cfg.AuthorityHost,
		})
		if err != nil {
			return o.fail(err)
		}
		return backend, o.closeWith(backend, nil), nil
	default:
		return o.fail(fmt.Errorf("server: unsupported cloud dynamic-secret backend type %q", cfg.Type))
	}
}

// requestBackendAdapter supplies CreateCredential for legacy concrete backends
// whose native service does not accept a requested lease duration.
type requestBackendAdapter struct{ dynsecret.Backend }

// ResolveAccess passes a lease access read to the backend when it can make
// one (G2-L2).
func (b *requestBackendAdapter) ResolveAccess(ctx context.Context, backendRef string) (dynsecret.Access, error) {
	resolver, ok := b.Backend.(dynsecret.AccessResolver)
	if !ok {
		return dynsecret.Access{}, dynsecret.ErrAccessUnsupported
	}
	return resolver.ResolveAccess(ctx, backendRef)
}

func (b *requestBackendAdapter) CreateCredential(ctx context.Context, req dynsecret.GenerateRequest) (string, []byte, error) {
	return b.Create(ctx, req.Role)
}

func (b *requestBackendAdapter) CreatePreparedCredential(ctx context.Context, req dynsecret.GenerateRequest, prepared []byte) (string, []byte, error) {
	backend, ok := b.Backend.(dynsecret.PreparedRequestBackend)
	if !ok {
		return "", nil, errors.New("server: dynamic-secret backend does not accept durable preparation")
	}
	return backend.CreatePreparedCredential(ctx, req, prepared)
}

// secretSyncTargetsFromConfig creates tenant-bound Targets whose pushers resolve
// credentials and construct one real vendor client for each outbox delivery.
func secretSyncTargetsFromConfig(
	_ context.Context,
	entries []config.SecretSyncTargetConfig,
	st *store.Store,
	kek seal.KeyWrapper,
	guard *egress.Guard,
	log *events.Log,
	tenantCrypto ...tenantseal.Access,
) (SecretSyncTargetRegistry, *cloudauth.Minter, error) {
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{SyncTargets: entries}, true); err != nil {
		return nil, nil, fmt.Errorf("server: invalid secret-sync target config: %w", err)
	}
	registry := SecretSyncTargetRegistry{}
	minter := cloudauth.NewMinter(2 * time.Minute)
	var access tenantseal.Access
	if len(tenantCrypto) > 0 {
		access = tenantCrypto[0]
	}
	resolver := integrationCredentialResolver{store: st, kek: kek, crypto: access}
	seen := map[string]bool{}
	for _, entry := range entries {
		// A hosted target without an endpoint uses its vendor's API base.
		if t, hosted := synctarget.Lookup(entry.Type); hosted && strings.TrimSpace(entry.Endpoint) == "" {
			entry.Endpoint = t.Endpoint
		}
		key := entry.TenantID + "\x00" + entry.ID
		if seen[key] {
			minter.Close()
			return nil, nil, fmt.Errorf("server: duplicate secret-sync target %s/%s", entry.TenantID, entry.ID)
		}
		seen[key] = true
		if entry.TenantID == "" || entry.ID == "" {
			minter.Close()
			return nil, nil, errors.New("server: secret-sync target requires tenant and id")
		}
		if (entry.AWSWorkloadIdentity || entry.GCPWorkloadIdentity || entry.AzureWorkloadIdentity) &&
			(st == nil || kek == nil || log == nil) {
			minter.Close()
			return nil, nil, fmt.Errorf("server: workload identity target %s/%s requires store, event log, and KEK", entry.TenantID, entry.ID)
		}
		if _, err := secretIntegrationHTTPClient(entry.Endpoint, entry.AllowPrivate, entry.AllowInsecureLoopback, entry.PrivateEgressCIDRs, guard); err != nil {
			minter.Close()
			return nil, nil, fmt.Errorf("server: secret-sync target %s/%s endpoint: %w", entry.TenantID, entry.ID, err)
		}
		if entry.AWSWorkloadIdentity {
			if _, err := secretIntegrationHTTPClient(awsWorkloadIdentityEndpoint(entry), entry.AllowPrivate, entry.AllowInsecureLoopback, entry.PrivateEgressCIDRs, guard); err != nil {
				minter.Close()
				return nil, nil, fmt.Errorf("server: secret-sync target %s/%s workload identity endpoint: %w", entry.TenantID, entry.ID, err)
			}
		}
		if entry.GCPWorkloadIdentity {
			if _, err := secretIntegrationHTTPClient(gcpWorkloadIdentityEndpoint(entry), entry.AllowPrivate, entry.AllowInsecureLoopback, entry.PrivateEgressCIDRs, guard); err != nil {
				minter.Close()
				return nil, nil, fmt.Errorf("server: secret-sync target %s/%s GCP workload identity endpoint: %w", entry.TenantID, entry.ID, err)
			}
			if endpoint := strings.TrimSpace(entry.WorkloadIdentityImpersonationEndpoint); endpoint != "" {
				if _, err := secretIntegrationHTTPClient(endpoint, entry.AllowPrivate, entry.AllowInsecureLoopback, entry.PrivateEgressCIDRs, guard); err != nil {
					minter.Close()
					return nil, nil, fmt.Errorf("server: secret-sync target %s/%s GCP impersonation endpoint: %w", entry.TenantID, entry.ID, err)
				}
			}
		}
		if entry.AzureWorkloadIdentity && strings.TrimSpace(entry.WorkloadIdentityEndpoint) != "" {
			if _, err := secretIntegrationHTTPClient(
				entry.WorkloadIdentityEndpoint, entry.AllowPrivate, entry.AllowInsecureLoopback,
				entry.PrivateEgressCIDRs, guard,
			); err != nil {
				minter.Close()
				return nil, nil, fmt.Errorf("server: secret-sync target %s/%s Azure workload identity endpoint: %w", entry.TenantID, entry.ID, err)
			}
		}
		if entry.Type == "webhook" {
			if err := secretsync.ValidateWebhookTemplate(entry.BodyTemplate); err != nil {
				minter.Close()
				return nil, nil, fmt.Errorf("server: secret-sync target %s/%s body_template: %w", entry.TenantID, entry.ID, err)
			}
		}
		if entry.Type == "netlify" {
			if err := secretsync.ValidateNetlifyTarget(entry.DeployContext, entry.Scopes); err != nil {
				minter.Close()
				return nil, nil, fmt.Errorf("server: secret-sync target %s/%s: %w", entry.TenantID, entry.ID, err)
			}
		}
		if _, ok := registry[entry.TenantID]; !ok {
			registry[entry.TenantID] = map[string]*secretsync.Target{}
		}
		pusher := newConfiguredSyncPusher(entry, resolver, guard, st, log, minter)
		registry[entry.TenantID][entry.ID] = secretsync.NewConfiguredTarget(
			entry.ID, entry.Type,
			entry.AWSWorkloadIdentity || entry.GCPWorkloadIdentity || entry.AzureWorkloadIdentity,
			pusher,
		).WithSignedPayload(entry.Type == "generic-ci-json" && strings.TrimSpace(entry.SigningKeyRef) != "")
	}
	return registry, minter, nil
}

func closeCloudTokenMinterOnError(err *error, minter *cloudauth.Minter) {
	if err != nil && *err != nil {
		minter.Close()
	}
}

// closeCloudTokenMinter releases a minter unconditionally. The outbound-dependency
// stage uses it when a constructor AFTER the minter fails: the caller's deferred
// close only sees what was returned, so a minter built and then abandoned inside
// the stage has to be released there.
func closeCloudTokenMinter(minter *cloudauth.Minter) { minter.Close() }

type configuredSyncPusher struct {
	tenantID    string
	cfg         config.SecretSyncTargetConfig
	credentials integrationCredentialResolver
	guard       *egress.Guard
	store       *store.Store
	log         *events.Log
	minter      *cloudauth.Minter
	push        func(context.Context, string, []byte) error
}

type secretSyncReceiverBoundaryKey struct{}

func (p *configuredSyncPusher) PushWithReceiverBoundary(ctx context.Context, key string, value []byte, begin func(context.Context) error) error {
	if begin == nil {
		return errors.New("server: secret-sync receiver begin callback is required")
	}
	return p.Push(context.WithValue(ctx, secretSyncReceiverBoundaryKey{}, begin), key, value)
}

func (p *configuredSyncPusher) Push(ctx context.Context, key string, value []byte) error {
	if p.push == nil {
		return errors.New("server: secret-sync pusher is not assembled")
	}
	return p.push(ctx, key, value)
}

// newConfiguredSyncPusher assembles a tenant-bound concrete-pusher factory in
// buildRunDeps. Tokens remain references until each outbox delivery, but every
// advertised constructor is now statically and operationally tied to the returned
// TenantSecretSyncTargets field.
func newConfiguredSyncPusher(cfg config.SecretSyncTargetConfig, credentials integrationCredentialResolver, guard *egress.Guard, st *store.Store, log *events.Log, minter *cloudauth.Minter) *configuredSyncPusher {
	pusher := &configuredSyncPusher{
		tenantID: cfg.TenantID, cfg: cfg, credentials: credentials, guard: guard,
		store: st, log: log, minter: minter,
	}
	pusher.push = func(ctx context.Context, key string, value []byte) error {
		return withConfiguredSecretSyncPusher(ctx, pusher, key, func(concrete secretsync.Pusher) error {
			return concrete.Push(ctx, key, value)
		})
	}
	return pusher
}

// ReconcilesReceiver reports, from the configured type alone, whether this
// target's receiver exposes state that a readback can compare. The catalog's
// receiver-reconcile capability and this answer come from the same list.
func (p *configuredSyncPusher) ReconcilesReceiver() bool {
	switch p.cfg.Type {
	case "vault-kv-v2", "terraform-cloud-opentofu", "gcp-secret-manager", "azure-key-vault", "kubernetes-secrets",
		"aws-parameter-store":
		return true
	default:
		readBack := secretsync.HostedReadBack(p.cfg.Type)
		return readBack != "" && readBack != secretsync.ReadBackReceiptOnly
	}
}

// ReconcileOperation resolves the target's credential for one readback, asks
// the concrete pusher to compare the receiver with this command's value under
// the same operation ID, and destroys the credential. It never writes.
func (p *configuredSyncPusher) ReconcileOperation(ctx context.Context, key string, value []byte) (secretsync.ReceiverReconciliation, error) {
	if !p.ReconcilesReceiver() {
		return secretsync.ReceiverStateUnknown, nil
	}
	state := secretsync.ReceiverStateUnknown
	err := withConfiguredSecretSyncPusher(ctx, p, key, func(concrete secretsync.Pusher) error {
		reconciler, ok := concrete.(secretsync.ReceiverReconciler)
		if !ok {
			return nil
		}
		var reconcileErr error
		state, reconcileErr = reconciler.ReconcileOperation(ctx, key, value)
		return reconcileErr
	})
	if err != nil {
		return secretsync.ReceiverStateUnknown, err
	}
	return state, nil
}

// ScopedKeys reports whether this target's receiver lists, reads back and
// deletes keys for a scoped sync (A237): KV v2 and the hosted targets (A241).
func (p *configuredSyncPusher) ScopedKeys() bool {
	_, hosted := synctarget.Lookup(p.cfg.Type)
	return p.cfg.Type == "vault-kv-v2" || p.cfg.Type == "aws-parameter-store" || hosted
}

// FlatKeys, ValidKey, ReadsBack and DigestOf answer a scoped sync's questions
// from the configured type, without a credential (A241).
func (p *configuredSyncPusher) FlatKeys() bool {
	t, hosted := synctarget.Lookup(p.cfg.Type)
	return hosted && t.Keys == synctarget.FlatKeys
}

func (p *configuredSyncPusher) ValidKey(key string) error {
	if t, hosted := synctarget.Lookup(p.cfg.Type); hosted {
		return t.ValidKey(key)
	}
	if p.cfg.Type == "aws-parameter-store" {
		return secretsync.ParameterStoreValidKey(p.cfg.PathPrefix, key) // A202-L1
	}
	return nil
}

func (p *configuredSyncPusher) ReadsBack() bool {
	return secretsync.HostedReadBack(p.cfg.Type) != secretsync.ReadBackReceiptOnly
}

func (p *configuredSyncPusher) DigestOf(value []byte) string {
	return secretsync.HostedDigestOf(p.cfg.Type, value)
}

// ListKeys, ReadDigest and Delete resolve the target's credential for one call
// and delegate to the concrete pusher, like a delivery.
func (p *configuredSyncPusher) ListKeys(ctx context.Context, prefix string, limit int) ([]string, error) {
	var keys []string
	err := p.withScoped(ctx, prefix, func(scoped secretsync.ScopedTarget) error {
		var err error
		keys, err = scoped.ListKeys(ctx, prefix, limit)
		return err
	})
	return keys, err
}

func (p *configuredSyncPusher) ReadDigest(ctx context.Context, key string) (bool, string, error) {
	var exists bool
	var digest string
	err := p.withScoped(ctx, key, func(scoped secretsync.ScopedTarget) error {
		var err error
		exists, digest, err = scoped.ReadDigest(ctx, key)
		return err
	})
	return exists, digest, err
}

func (p *configuredSyncPusher) Delete(ctx context.Context, key string) error {
	return p.withScoped(ctx, key, func(scoped secretsync.ScopedTarget) error { return scoped.Delete(ctx, key) })
}

func (p *configuredSyncPusher) withScoped(ctx context.Context, key string, use func(secretsync.ScopedTarget) error) error {
	if !p.ScopedKeys() {
		return errors.New("server: this secret-sync target does not support scoped sync")
	}
	return withConfiguredSecretSyncPusher(ctx, p, key, func(concrete secretsync.Pusher) error {
		scoped, ok := concrete.(secretsync.ScopedTarget)
		if !ok {
			return errors.New("server: this secret-sync target does not support scoped sync")
		}
		return use(scoped)
	})
}

func withConfiguredSecretSyncPusher(ctx context.Context, p *configuredSyncPusher, key string, use func(secretsync.Pusher) error) error {
	var values []*secret.Buffer
	destroy := func() {
		for _, item := range values {
			item.Destroy()
		}
	}
	defer destroy()
	resolve := func(ref string) ([]byte, error) {
		if strings.TrimSpace(ref) == "" {
			return nil, nil
		}
		item, err := p.credentials.resolve(ctx, p.tenantID, ref)
		if err == nil {
			values = append(values, item)
			return item.Bytes(), nil
		}
		return nil, err
	}
	begin, _ := ctx.Value(secretSyncReceiverBoundaryKey{}).(func(context.Context) error)
	client, err := secretIntegrationHTTPClientWithTLSAndBoundary(
		p.cfg.Endpoint, p.cfg.AllowPrivate, p.cfg.AllowInsecureLoopback,
		p.cfg.PrivateEgressCIDRs, nil, "", p.guard, begin)
	if err != nil {
		return err
	}
	var concrete secretsync.Pusher
	cfg := p.cfg
	switch cfg.Type {
	case "aws-secrets-manager":
		accessKeyID, secretKey, session, cleanup, credentialErr := p.awsSyncCredentials(ctx, key, resolve)
		if credentialErr != nil {
			return credentialErr
		}
		defer cleanup()
		concrete, err = secretsync.NewAWSSecretsManagerPusher(secretsync.AWSSecretsManagerConfig{
			Endpoint: cfg.Endpoint, HTTPClient: client, Region: cfg.Region,
			AccessKeyID: accessKeyID, SecretAccessKey: secretKey, SessionToken: session,
		})
	case "gcp-secret-manager":
		token, cleanup, credentialErr := p.gcpSyncCredentials(ctx, key, resolve)
		if credentialErr != nil {
			return credentialErr
		}
		defer cleanup()
		concrete, err = secretsync.NewGCPSecretManagerPusher(secretsync.GCPSecretManagerConfig{
			Endpoint: cfg.Endpoint, HTTPClient: client, Project: cfg.Project, BearerToken: token,
		})
	case "azure-key-vault":
		token, cleanup, credentialErr := p.azureSyncCredentials(ctx, key, resolve)
		if credentialErr != nil {
			return credentialErr
		}
		defer cleanup()
		concrete, err = secretsync.NewAzureKeyVaultPusher(secretsync.AzureKeyVaultConfig{
			Endpoint: cfg.Endpoint, HTTPClient: client, APIVersion: cfg.APIVersion, BearerToken: token,
		})
	case "github-actions":
		token, resolveErr := resolve(cfg.TokenRef)
		if resolveErr != nil {
			return resolveErr
		}
		concrete, err = secretsync.NewGitHubActionsPusher(secretsync.GitHubActionsConfig{
			Endpoint: cfg.Endpoint, HTTPClient: client, Owner: cfg.Owner, Repo: cfg.Repo, Token: token,
		})
	case "gitlab-ci":
		token, resolveErr := resolve(cfg.TokenRef)
		if resolveErr != nil {
			return resolveErr
		}
		concrete, err = secretsync.NewGitLabCIPusher(secretsync.GitLabCIConfig{
			Endpoint: cfg.Endpoint, HTTPClient: client, ProjectID: cfg.ProjectID,
			Token: token, EnvironmentScope: cfg.EnvironmentScope,
		})
	case "vercel":
		token, resolveErr := resolve(cfg.TokenRef)
		if resolveErr != nil {
			return resolveErr
		}
		concrete, err = secretsync.NewVercelPusher(secretsync.VercelConfig{
			Endpoint: cfg.Endpoint, HTTPClient: client, ProjectID: cfg.ProjectID,
			TeamID: cfg.TeamID, Token: token, Targets: cfg.Targets,
		})
	case "generic-ci-json":
		token, resolveErr := resolve(cfg.TokenRef)
		if resolveErr != nil {
			return resolveErr
		}
		var signingKey []byte
		if strings.TrimSpace(cfg.SigningKeyRef) != "" {
			// OD-12: sign the push like the signed webhook.
			if signingKey, resolveErr = resolve(cfg.SigningKeyRef); resolveErr != nil {
				return resolveErr
			}
			if len(signingKey) == 0 {
				return errors.New("server: generic CI signing key is empty")
			}
		}
		concrete, err = secretsync.NewCIPusher(secretsync.CIPusherConfig{
			Endpoint: cfg.Endpoint, HTTPClient: client, BearerToken: token, Provider: cfg.Provider, SigningKey: signingKey,
		})
	case "kubernetes-secrets":
		token, resolveErr := resolve(cfg.TokenRef)
		if resolveErr != nil {
			return resolveErr
		}
		concrete, err = secretsync.NewKubernetesPusher(secretsync.KubernetesConfig{
			Endpoint: cfg.Endpoint, HTTPClient: client, Namespace: cfg.Namespace, BearerToken: token,
		})
	case "terraform-cloud-opentofu":
		token, resolveErr := resolve(cfg.TokenRef)
		if resolveErr != nil {
			return resolveErr
		}
		concrete, err = secretsync.NewTerraformCloudOpenTofuPusher(secretsync.TerraformCloudOpenTofuConfig{
			Endpoint: cfg.Endpoint, HTTPClient: client, WorkspaceID: cfg.WorkspaceID,
			Token: token, Category: cfg.VariableCategory, HCL: cfg.HCL, Description: cfg.Description,
		})
	case "webhook", "aws-parameter-store", "netlify":
		concrete, err = newDeliverySyncPusher(cfg, client, resolve)
	case "vault-kv-v2":
		token, resolveErr := resolve(cfg.TokenRef)
		if resolveErr != nil {
			return resolveErr
		}
		concrete, err = secretsync.NewVaultKVV2Pusher(secretsync.VaultKVV2Config{
			Endpoint: cfg.Endpoint, HTTPClient: client, Token: token, Mount: cfg.Mount,
			PathPrefix: cfg.PathPrefix, Field: cfg.Field, Namespace: cfg.VaultNamespace,
		})
	default:
		if _, hosted := synctarget.Lookup(cfg.Type); !hosted {
			return fmt.Errorf("server: unsupported secret-sync target type %q", cfg.Type)
		}
		token, resolveErr := resolve(cfg.TokenRef)
		if resolveErr != nil {
			return resolveErr
		}
		concrete, err = secretsync.NewHostedSyncPusher(secretsync.HostedSyncConfig{
			Type: cfg.Type, Endpoint: cfg.Endpoint, HTTPClient: client, Token: token,
			Username: cfg.Username, Binding: cfg.Binding,
		})
	}
	if err != nil {
		return err
	}
	if closer, ok := concrete.(interface{ Close() }); ok {
		defer closer.Close()
	}
	return use(concrete)
}

// newDeliverySyncPusher builds the signed webhook, Parameter Store and Netlify
// pushers (A202) with credentials resolved for this one delivery.
func newDeliverySyncPusher(cfg config.SecretSyncTargetConfig, client *http.Client, resolve func(string) ([]byte, error)) (secretsync.Pusher, error) {
	switch cfg.Type {
	case "webhook":
		signingKey, resolveErr := resolve(cfg.SigningKeyRef)
		if resolveErr != nil {
			return nil, resolveErr
		}
		var token []byte
		if strings.TrimSpace(cfg.TokenRef) != "" {
			if token, resolveErr = resolve(cfg.TokenRef); resolveErr != nil {
				return nil, resolveErr
			}
		}
		return secretsync.NewWebhookPusher(secretsync.WebhookConfig{
			Endpoint: cfg.Endpoint, HTTPClient: client, SigningKey: signingKey, BearerToken: token, BodyTemplate: cfg.BodyTemplate,
		})
	case "aws-parameter-store":
		secretKey, resolveErr := resolve(cfg.SecretAccessRef)
		if resolveErr != nil {
			return nil, resolveErr
		}
		var session []byte
		if strings.TrimSpace(cfg.SessionTokenRef) != "" {
			if session, resolveErr = resolve(cfg.SessionTokenRef); resolveErr != nil {
				return nil, resolveErr
			}
		}
		return secretsync.NewAWSParameterStorePusher(secretsync.AWSParameterStoreConfig{
			Endpoint: cfg.Endpoint, HTTPClient: client, Region: cfg.Region, AccessKeyID: cfg.AccessKeyID,
			SecretAccessKey: secretKey, SessionToken: session, PathPrefix: cfg.PathPrefix, KMSKeyID: cfg.KMSKeyID,
		})
	case "netlify":
		token, resolveErr := resolve(cfg.TokenRef)
		if resolveErr != nil {
			return nil, resolveErr
		}
		return secretsync.NewNetlifyPusher(secretsync.NetlifyConfig{
			Endpoint: cfg.Endpoint, HTTPClient: client, Token: token, AccountID: cfg.AccountID,
			SiteID: cfg.SiteID, Context: cfg.DeployContext, Scopes: cfg.Scopes,
		})
	default:
		return nil, fmt.Errorf("server: %q is not a signed webhook, Parameter Store or Netlify target", cfg.Type)
	}
}

func (p *configuredSyncPusher) awsSyncCredentials(
	ctx context.Context,
	remoteKey string,
	resolve func(string) ([]byte, error),
) (string, []byte, []byte, func(), error) {
	if !p.cfg.AWSWorkloadIdentity {
		secretKey, err := resolve(p.cfg.SecretAccessRef)
		if err != nil {
			return "", nil, nil, func() {}, err
		}
		session, err := resolve(p.cfg.SessionTokenRef)
		if err != nil {
			return "", nil, nil, func() {}, err
		}
		return p.cfg.AccessKeyID, secretKey, session, func() {}, nil
	}
	credential, err := p.mintAWSWorkloadIdentity(ctx, remoteKey)
	if err != nil {
		return "", nil, nil, func() {}, err
	}
	var session []byte
	if credential.Secondary != nil {
		session = credential.Secondary.Bytes()
	}
	return credential.Identifier, credential.Primary.Bytes(), session, credential.Destroy, nil
}

const defaultAWSWorkloadIdentityEndpoint = "https://sts.amazonaws.com"

func awsWorkloadIdentityEndpoint(cfg config.SecretSyncTargetConfig) string {
	if endpoint := strings.TrimSpace(cfg.WorkloadIdentityEndpoint); endpoint != "" {
		return endpoint
	}
	return defaultAWSWorkloadIdentityEndpoint
}

func (p *configuredSyncPusher) mintAWSWorkloadIdentity(ctx context.Context, remoteKey string) (*cloudauth.Credential, error) {
	if p.store == nil || p.log == nil || p.minter == nil {
		return nil, errors.New("server: AWS workload identity is not fully assembled")
	}
	source, err := p.store.FindSecretSyncWorkloadIdentitySourceForTarget(ctx, p.tenantID, "aws", p.cfg.ID, remoteKey)
	if err != nil {
		if errors.Is(err, store.ErrSecretSyncWorkloadIdentitySourceNotFound) {
			return nil, errors.New("server: no enabled AWS workload identity source authorizes this target and remote key")
		}
		return nil, fmt.Errorf("server: load AWS workload identity source: %w", err)
	}
	operationID := secretsync.OperationID(ctx)
	if operationID == "" {
		return nil, errors.New("server: AWS workload identity exchange requires a durable outbox operation id")
	}
	if p.guard != nil && p.guard.Enabled() {
		if err := p.recordWorkloadIdentityStatus(ctx, source.ID, operationID,
			store.SecretSyncWorkloadIdentityOfflineDisabled, "air_gap_enabled", nil); err != nil {
			return nil, fmt.Errorf("server: record AWS workload identity offline state: %w", err)
		}
		return nil, cloudauth.OfflineDisabled("AWS")
	}
	trust, err := p.store.GetWorkloadAttesterTrustSource(ctx, p.tenantID, source.TrustSourceID)
	if err != nil || !trust.Enabled || trust.RevokedAt != nil || trust.Audience != source.Audience {
		if statusErr := p.recordWorkloadIdentityStatus(ctx, source.ID, operationID,
			store.SecretSyncWorkloadIdentityExchangeFailed, "trust_source_invalid", nil); statusErr != nil {
			return nil, fmt.Errorf("server: record AWS workload identity trust failure: %w", statusErr)
		}
		return nil, errors.New("server: AWS workload identity trust source is unavailable")
	}
	// Configuration updated_at changes only on operator upsert, not on runtime
	// status. Trust rotation/version changes likewise force a fresh exchange.
	cacheKey := fmt.Sprintf("%s\x00%s\x00%d\x00%d\x00%d",
		p.tenantID, source.ID, source.UpdatedAt.UnixNano(), trust.RotationVersion, trust.UpdatedAt.UnixNano())
	credential, cacheHit, err := p.minter.Mint(ctx, cacheKey, func(exchangeCtx context.Context) (cloudauth.Material, error) {
		proof, resolveErr := p.credentials.resolve(exchangeCtx, p.tenantID, source.WorkloadProofRef)
		if resolveErr != nil {
			return cloudauth.Material{}, errors.New("cloudauth: workload proof reference could not be resolved")
		}
		defer proof.Destroy()
		if validateErr := cloudauth.ValidateOIDCProof(
			proof.Bytes(), trust.JWKS, trust.Issuer, source.Audience, source.Subject, time.Now().UTC(),
		); validateErr != nil {
			return cloudauth.Material{}, validateErr
		}
		client, clientErr := secretIntegrationHTTPClient(
			awsWorkloadIdentityEndpoint(p.cfg), p.cfg.AllowPrivate, p.cfg.AllowInsecureLoopback,
			p.cfg.PrivateEgressCIDRs, p.guard,
		)
		if clientErr != nil {
			return cloudauth.Material{}, errors.New("cloudauth: AWS STS client is unavailable")
		}
		return cloudauth.ExchangeAWSWebIdentity(exchangeCtx, client, cloudauth.AWSExchangeRequest{
			Endpoint: awsWorkloadIdentityEndpoint(p.cfg), RoleARN: source.RoleARN,
			RoleSessionName:  awsWorkloadIdentitySessionName(operationID),
			WebIdentityToken: proof.Bytes(), DurationSeconds: 900,
		})
	})
	if err != nil {
		reason := "exchange_failed"
		if errors.Is(err, cloudauth.ErrInvalidWorkloadProof) {
			reason = "proof_invalid"
		}
		if statusErr := p.recordWorkloadIdentityStatus(ctx, source.ID, operationID,
			store.SecretSyncWorkloadIdentityExchangeFailed, reason, nil); statusErr != nil {
			return nil, fmt.Errorf("server: record AWS workload identity failure: %w", statusErr)
		}
		return nil, fmt.Errorf("server: AWS workload identity exchange failed: %w", err)
	}
	reason := "credential_exchanged"
	if cacheHit {
		reason = "credential_cache_hit"
	}
	expiresAt := credential.ExpiresAt
	if err := p.recordWorkloadIdentityStatus(ctx, source.ID, operationID,
		store.SecretSyncWorkloadIdentityActive, reason, &expiresAt); err != nil {
		credential.Destroy()
		return nil, fmt.Errorf("server: record AWS workload identity active state: %w", err)
	}
	return credential, nil
}

func awsWorkloadIdentitySessionName(operationID string) string {
	const prefix = "trstctl-"
	var out strings.Builder
	out.Grow(64)
	out.WriteString(prefix)
	for _, r := range operationID {
		if out.Len() >= 64 {
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '_', r == '+', r == '=', r == ',', r == '.', r == '@', r == '-':
			out.WriteRune(r)
		default:
			out.WriteByte('-')
		}
	}
	return strings.TrimRight(out.String(), "-")
}

func (p *configuredSyncPusher) gcpSyncCredentials(
	ctx context.Context,
	remoteKey string,
	resolve func(string) ([]byte, error),
) ([]byte, func(), error) {
	if !p.cfg.GCPWorkloadIdentity {
		token, err := resolve(p.cfg.TokenRef)
		return token, func() {}, err
	}
	credential, err := p.mintGCPWorkloadIdentity(ctx, remoteKey)
	if err != nil {
		return nil, func() {}, err
	}
	return credential.Primary.Bytes(), credential.Destroy, nil
}

const defaultGCPWorkloadIdentityEndpoint = "https://sts.googleapis.com/v1/token" // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)

func gcpWorkloadIdentityEndpoint(cfg config.SecretSyncTargetConfig) string {
	if endpoint := strings.TrimSpace(cfg.WorkloadIdentityEndpoint); endpoint != "" {
		return endpoint
	}
	return defaultGCPWorkloadIdentityEndpoint
}

func gcpWorkloadIdentityImpersonationEndpoint(cfg config.SecretSyncTargetConfig, serviceAccount string) string {
	if endpoint := strings.TrimSpace(cfg.WorkloadIdentityImpersonationEndpoint); endpoint != "" {
		return endpoint
	}
	if serviceAccount == "" {
		return ""
	}
	return "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" +
		url.PathEscape(serviceAccount) + ":generateAccessToken"
}

func (p *configuredSyncPusher) mintGCPWorkloadIdentity(ctx context.Context, remoteKey string) (*cloudauth.Credential, error) {
	if p.store == nil || p.log == nil || p.minter == nil {
		return nil, errors.New("server: GCP workload identity is not fully assembled")
	}
	source, err := p.store.FindSecretSyncWorkloadIdentitySourceForTarget(ctx, p.tenantID, "gcp", p.cfg.ID, remoteKey)
	if err != nil {
		if errors.Is(err, store.ErrSecretSyncWorkloadIdentitySourceNotFound) {
			return nil, errors.New("server: no enabled GCP workload identity source authorizes this target and remote key")
		}
		return nil, fmt.Errorf("server: load GCP workload identity source: %w", err)
	}
	operationID := secretsync.OperationID(ctx)
	if operationID == "" {
		return nil, errors.New("server: GCP workload identity exchange requires a durable outbox operation id")
	}
	if p.guard != nil && p.guard.Enabled() {
		if err := p.recordWorkloadIdentityStatus(ctx, source.ID, operationID,
			store.SecretSyncWorkloadIdentityOfflineDisabled, "air_gap_enabled", nil); err != nil {
			return nil, fmt.Errorf("server: record GCP workload identity offline state: %w", err)
		}
		return nil, cloudauth.OfflineDisabled("GCP")
	}
	trust, err := p.store.GetWorkloadAttesterTrustSource(ctx, p.tenantID, source.TrustSourceID)
	if err != nil || !trust.Enabled || trust.RevokedAt != nil || trust.Audience != source.Audience {
		if statusErr := p.recordWorkloadIdentityStatus(ctx, source.ID, operationID,
			store.SecretSyncWorkloadIdentityExchangeFailed, "trust_source_invalid", nil); statusErr != nil {
			return nil, fmt.Errorf("server: record GCP workload identity trust failure: %w", statusErr)
		}
		return nil, errors.New("server: GCP workload identity trust source is unavailable")
	}
	cacheKey := fmt.Sprintf("%s\x00%s\x00%d\x00%d\x00%d",
		p.tenantID, source.ID, source.UpdatedAt.UnixNano(), trust.RotationVersion, trust.UpdatedAt.UnixNano())
	credential, cacheHit, err := p.minter.Mint(ctx, cacheKey, func(exchangeCtx context.Context) (cloudauth.Material, error) {
		proof, resolveErr := p.credentials.resolve(exchangeCtx, p.tenantID, source.WorkloadProofRef)
		if resolveErr != nil {
			return cloudauth.Material{}, errors.New("cloudauth: workload proof reference could not be resolved")
		}
		defer proof.Destroy()
		if validateErr := cloudauth.ValidateOIDCProof(
			proof.Bytes(), trust.JWKS, trust.Issuer, source.Audience, source.Subject, time.Now().UTC(),
		); validateErr != nil {
			return cloudauth.Material{}, validateErr
		}
		client, clientErr := secretIntegrationHTTPClient(
			gcpWorkloadIdentityEndpoint(p.cfg), p.cfg.AllowPrivate, p.cfg.AllowInsecureLoopback,
			p.cfg.PrivateEgressCIDRs, p.guard,
		)
		if clientErr != nil {
			return cloudauth.Material{}, errors.New("cloudauth: GCP STS client is unavailable")
		}
		impersonationEndpoint := gcpWorkloadIdentityImpersonationEndpoint(p.cfg, source.ServiceAccount)
		var impersonationClient cloudhttp.Doer
		if impersonationEndpoint != "" {
			impersonationClient, clientErr = secretIntegrationHTTPClient(
				impersonationEndpoint, p.cfg.AllowPrivate, p.cfg.AllowInsecureLoopback,
				p.cfg.PrivateEgressCIDRs, p.guard,
			)
			if clientErr != nil {
				return cloudauth.Material{}, errors.New("cloudauth: GCP impersonation client is unavailable")
			}
		}
		return cloudauth.ExchangeGCPWorkloadIdentity(exchangeCtx, client, cloudauth.GCPExchangeRequest{
			STSEndpoint: gcpWorkloadIdentityEndpoint(p.cfg), Audience: source.Audience,
			SubjectToken: proof.Bytes(), ServiceAccount: source.ServiceAccount,
			ImpersonationEndpoint: impersonationEndpoint, ImpersonationDoer: impersonationClient,
		})
	})
	if err != nil {
		reason := "exchange_failed"
		if errors.Is(err, cloudauth.ErrInvalidWorkloadProof) {
			reason = "proof_invalid"
		}
		if statusErr := p.recordWorkloadIdentityStatus(ctx, source.ID, operationID,
			store.SecretSyncWorkloadIdentityExchangeFailed, reason, nil); statusErr != nil {
			return nil, fmt.Errorf("server: record GCP workload identity failure: %w", statusErr)
		}
		return nil, fmt.Errorf("server: GCP workload identity exchange failed: %w", err)
	}
	reason := "credential_exchanged"
	if cacheHit {
		reason = "credential_cache_hit"
	}
	expiresAt := credential.ExpiresAt
	if err := p.recordWorkloadIdentityStatus(ctx, source.ID, operationID,
		store.SecretSyncWorkloadIdentityActive, reason, &expiresAt); err != nil {
		credential.Destroy()
		return nil, fmt.Errorf("server: record GCP workload identity active state: %w", err)
	}
	return credential, nil
}

func (p *configuredSyncPusher) azureSyncCredentials(
	ctx context.Context,
	remoteKey string,
	resolve func(string) ([]byte, error),
) ([]byte, func(), error) {
	if !p.cfg.AzureWorkloadIdentity {
		token, err := resolve(p.cfg.TokenRef)
		return token, func() {}, err
	}
	credential, err := p.mintAzureWorkloadIdentity(ctx, remoteKey)
	if err != nil {
		return nil, func() {}, err
	}
	return credential.Primary.Bytes(), credential.Destroy, nil
}

func azureWorkloadIdentityEndpoint(cfg config.SecretSyncTargetConfig, tenantID string) string {
	if endpoint := strings.TrimSpace(cfg.WorkloadIdentityEndpoint); endpoint != "" {
		return endpoint
	}
	return "https://login.microsoftonline.com/" + url.PathEscape(tenantID) + "/oauth2/v2.0/token"
}

func (p *configuredSyncPusher) mintAzureWorkloadIdentity(ctx context.Context, remoteKey string) (*cloudauth.Credential, error) {
	if p.store == nil || p.log == nil || p.minter == nil {
		return nil, errors.New("server: Azure workload identity is not fully assembled")
	}
	source, err := p.store.FindSecretSyncWorkloadIdentitySourceForTarget(ctx, p.tenantID, "azure", p.cfg.ID, remoteKey)
	if err != nil {
		if errors.Is(err, store.ErrSecretSyncWorkloadIdentitySourceNotFound) {
			return nil, errors.New("server: no enabled Azure workload identity source authorizes this target and remote key")
		}
		return nil, fmt.Errorf("server: load Azure workload identity source: %w", err)
	}
	operationID := secretsync.OperationID(ctx)
	if operationID == "" {
		return nil, errors.New("server: Azure workload identity exchange requires a durable outbox operation id")
	}
	if p.guard != nil && p.guard.Enabled() {
		if err := p.recordWorkloadIdentityStatus(ctx, source.ID, operationID,
			store.SecretSyncWorkloadIdentityOfflineDisabled, "air_gap_enabled", nil); err != nil {
			return nil, fmt.Errorf("server: record Azure workload identity offline state: %w", err)
		}
		return nil, cloudauth.OfflineDisabled("Azure")
	}
	trust, err := p.store.GetWorkloadAttesterTrustSource(ctx, p.tenantID, source.TrustSourceID)
	if err != nil || !trust.Enabled || trust.RevokedAt != nil || trust.Audience != source.Audience {
		if statusErr := p.recordWorkloadIdentityStatus(ctx, source.ID, operationID,
			store.SecretSyncWorkloadIdentityExchangeFailed, "trust_source_invalid", nil); statusErr != nil {
			return nil, fmt.Errorf("server: record Azure workload identity trust failure: %w", statusErr)
		}
		return nil, errors.New("server: Azure workload identity trust source is unavailable")
	}
	cacheKey := fmt.Sprintf("%s\x00%s\x00%d\x00%d\x00%d",
		p.tenantID, source.ID, source.UpdatedAt.UnixNano(), trust.RotationVersion, trust.UpdatedAt.UnixNano())
	credential, cacheHit, err := p.minter.Mint(ctx, cacheKey, func(exchangeCtx context.Context) (cloudauth.Material, error) {
		proof, resolveErr := p.credentials.resolve(exchangeCtx, p.tenantID, source.WorkloadProofRef)
		if resolveErr != nil {
			return cloudauth.Material{}, errors.New("cloudauth: workload proof reference could not be resolved")
		}
		defer proof.Destroy()
		if validateErr := cloudauth.ValidateOIDCProof(
			proof.Bytes(), trust.JWKS, trust.Issuer, source.Audience, source.Subject, time.Now().UTC(),
		); validateErr != nil {
			return cloudauth.Material{}, validateErr
		}
		endpoint := azureWorkloadIdentityEndpoint(p.cfg, source.AzureTenantID)
		client, clientErr := secretIntegrationHTTPClient(
			endpoint, p.cfg.AllowPrivate, p.cfg.AllowInsecureLoopback,
			p.cfg.PrivateEgressCIDRs, p.guard,
		)
		if clientErr != nil {
			return cloudauth.Material{}, errors.New("cloudauth: Azure token client is unavailable")
		}
		return cloudauth.ExchangeAzureFederatedCredential(exchangeCtx, client, cloudauth.AzureExchangeRequest{
			Endpoint: endpoint, ClientID: source.ClientID, Scope: source.TargetScope,
			SubjectToken: proof.Bytes(),
		})
	})
	if err != nil {
		reason := "exchange_failed"
		if errors.Is(err, cloudauth.ErrInvalidWorkloadProof) {
			reason = "proof_invalid"
		}
		if statusErr := p.recordWorkloadIdentityStatus(ctx, source.ID, operationID,
			store.SecretSyncWorkloadIdentityExchangeFailed, reason, nil); statusErr != nil {
			return nil, fmt.Errorf("server: record Azure workload identity failure: %w", statusErr)
		}
		return nil, fmt.Errorf("server: Azure workload identity exchange failed: %w", err)
	}
	reason := "credential_exchanged"
	if cacheHit {
		reason = "credential_cache_hit"
	}
	expiresAt := credential.ExpiresAt
	if err := p.recordWorkloadIdentityStatus(ctx, source.ID, operationID,
		store.SecretSyncWorkloadIdentityActive, reason, &expiresAt); err != nil {
		credential.Destroy()
		return nil, fmt.Errorf("server: record Azure workload identity active state: %w", err)
	}
	return credential, nil
}

var secretSyncWorkloadIdentityEventNamespace = uuid.MustParse("cf6b81b1-8665-5ca2-b31b-b807d1070172")

func (p *configuredSyncPusher) recordWorkloadIdentityStatus(ctx context.Context, sourceID, operationID, status, reason string, expiresAt *time.Time) error {
	data, err := json.Marshal(projections.SecretSyncWorkloadIdentitySourceStatus{
		ID: sourceID, Status: status, Reason: reason, ExpiresAt: expiresAt,
	})
	if err != nil {
		return err
	}
	eventID := "secret-sync-wif-status-" + uuid.NewSHA1(
		secretSyncWorkloadIdentityEventNamespace,
		[]byte(p.tenantID+"\x00"+sourceID+"\x00"+operationID+"\x00"+status+"\x00"+reason),
	).String()
	event, err := p.log.Append(ctx, events.Event{
		ID: eventID, Type: projections.EventSecretSyncWorkloadIdentityStatus,
		TenantID: p.tenantID, Data: data,
	})
	if err != nil {
		return err
	}
	return projections.New(p.store).Apply(ctx, event)
}

func secretIntegrationHTTPClient(endpoint string, allowPrivate, allowInsecureLoopback bool, privateCIDRs []string, guard *egress.Guard) (*http.Client, error) {
	return secretIntegrationHTTPClientWithTLS(endpoint, allowPrivate, allowInsecureLoopback, privateCIDRs, nil, "", guard)
}

func secretIntegrationHTTPClientWithTLS(endpoint string, allowPrivate, allowInsecureLoopback bool, privateCIDRs []string, caPEM []byte, serverName string, guard *egress.Guard) (*http.Client, error) {
	return secretIntegrationHTTPClientWithTLSAndBoundary(endpoint, allowPrivate, allowInsecureLoopback,
		privateCIDRs, caPEM, serverName, guard, nil)
}

func secretIntegrationHTTPClientWithTLSAndBoundary(endpoint string, allowPrivate, allowInsecureLoopback bool, privateCIDRs []string, caPEM []byte, serverName string, guard *egress.Guard, begin func(context.Context) error) (*http.Client, error) {
	if err := netsec.ValidateHTTPSOrInsecureLoopbackURL(endpoint, allowInsecureLoopback); err != nil {
		return nil, err
	}
	if len(caPEM) > 0 && netsec.IsInsecureLoopbackHTTPURL(endpoint) {
		return nil, errors.New("server: pinned Kubernetes CA requires HTTPS")
	}
	var client *http.Client
	var err error
	if netsec.IsInsecureLoopbackHTTPURL(endpoint) {
		client = netsec.InsecureLoopbackClient(30 * time.Second)
	} else {
		client, err = cloudHTTPClient(endpoint, allowPrivate, privateCIDRs)
		if err != nil {
			return nil, err
		}
	}
	if len(caPEM) > 0 {
		pinned, err := mtls.HTTPTransportForServerName(caPEM, serverName)
		if err != nil {
			return nil, err
		}
		base, ok := client.Transport.(*http.Transport)
		if !ok {
			return nil, errors.New("server: safe HTTPS transport is unavailable")
		}
		copy := base.Clone()
		copy.TLSClientConfig = pinned.TLSClientConfig
		client.Transport = copy
	}
	if begin != nil {
		base, ok := client.Transport.(*http.Transport)
		if !ok || base.DialContext == nil || !base.DisableKeepAlives {
			return nil, errors.New("server: receiver boundary requires a dedicated non-reusing HTTP transport")
		}
		transport := base.Clone()
		dial := transport.DialContext
		var once sync.Once
		var beginErr error
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			connection, err := dial(ctx, network, address)
			if err != nil {
				// No connected socket exists and no receiver request bytes can
				// have been sent. Keep the durable receiver-start count at zero.
				return nil, err
			}
			once.Do(func() { beginErr = begin(ctx) })
			if beginErr != nil {
				_ = connection.Close()
				return nil, beginErr
			}
			return connection, nil
		}
		client.Transport = transport
	}
	clone := *client
	clone.Transport = guard.WrapTransport(client.Transport)
	previousRedirect := client.CheckRedirect
	clone.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req == nil || req.URL == nil {
			return errors.New("server: secret-integration redirect is missing a URL")
		}
		if err := netsec.ValidateHTTPSOrInsecureLoopbackURL(req.URL.String(), allowInsecureLoopback); err != nil {
			return err
		}
		if previousRedirect != nil {
			return previousRedirect(req, via)
		}
		return nil
	}
	return &clone, nil
}

// AllowsStaticRotation implements dynsecret.StaticRotationProvider: the operator
// opted this provider in and the role is one it may mint for.
func (p *configuredDynamicProvider) AllowsStaticRotation(role string) bool {
	return p != nil && p.cfg.AllowStaticRotation && config.StaticRotationProviderTypes[strings.TrimSpace(p.cfg.Type)] && p.allowedRoles[role]
}

// RotationAccounts implements dynsecret.TwoUserRotationProvider: a role with
// rotation_accounts on a provider that allows its static rotation alternates
// between those two accounts (A240).
func (p *configuredDynamicProvider) RotationAccounts(role string) ([2]string, bool) {
	accounts := p.cfg.RotationAccounts[role]
	if !p.AllowsStaticRotation(role) || !config.TwoUserRotationProviderTypes[strings.TrimSpace(p.cfg.Type)] || len(accounts) != 2 {
		return [2]string{}, false
	}
	return [2]string{accounts[0], accounts[1]}, true
}

// TwoUserRetirement implements dynsecret.TwoUserRetirer: what retiring one
// account of a pair does at this provider type (A240).
func (p *configuredDynamicProvider) TwoUserRetirement() string {
	switch strings.TrimSpace(p.cfg.Type) {
	case "ldap":
		return "replacing its password; binds already open last until they bind again"
	case "unix", "windows":
		return "replacing its password; sessions already open last until they end"
	case "mongodb":
		return "replacing its password; connections already authenticated last until they reconnect"
	}
	return "replacing its password and ending its sessions"
}

// RotationPhase implements dynsecret.RotationPhaser: a provider type whose
// rotation invalidates the current credential when it issues the next is
// single-phase (A240).
func (p *configuredDynamicProvider) RotationPhase(role string) string {
	if p.cfg.Type == "ldap" && p.cfg.DirectoryMode == "active_directory" {
		if _, paired := p.RotationAccounts(role); !paired {
			return dynsecret.RotationSinglePhase
		}
	}

	if config.SinglePhaseRotationProviderTypes[strings.TrimSpace(p.cfg.Type)] {
		return dynsecret.RotationSinglePhase
	}
	// A unix or windows role without a pair changes its one account's
	// password in place.
	if providerType := strings.TrimSpace(p.cfg.Type); providerType == "unix" || providerType == "windows" {
		if _, paired := p.RotationAccounts(role); !paired {
			return dynsecret.RotationSinglePhase
		}
	}
	return dynsecret.RotationTwoPhase
}

// rotationAccountPairs returns every role's two-user pair for the backend.
// databaseRoleAccess is the access class role_access gives each role of a
// PostgreSQL, MySQL or MongoDB provider (A239-L1). Configuration validation
// already refused a class that is neither read nor readwrite; a role without
// one is granted the class its name states or refused by the backend.
func (p *configuredDynamicProvider) databaseRoleAccess() dynsecret.DatabaseRoleAccess {
	bound := make(map[string]dbaccess.Access, len(p.cfg.RoleAccess))
	for role, class := range p.cfg.RoleAccess {
		if access, ok := dbaccess.ParseBinding(class); ok {
			bound[role] = access
		}
	}
	return dynsecret.DatabaseRoleAccess{RoleAccess: bound}
}

func (p *configuredDynamicProvider) rotationAccountPairs() map[string][2]string {
	pairs := map[string][2]string{}
	for role := range p.cfg.RotationAccounts {
		if pair, ok := p.RotationAccounts(role); ok {
			pairs[role] = pair
		}
	}
	return pairs
}

// VerifyLeaseCredential implements dynsecret.LeaseCredentialVerifier for
// dynamic-lease rotation: database providers open a session with the lease's
// credential, Redis authenticates as the lease's user against the configured
// server and runs PING, and a Datadog API key validates at the site (A240).
// Other types have no proof here.
func (p *configuredDynamicProvider) VerifyLeaseCredential(ctx context.Context, credential []byte) (string, error) {
	switch strings.TrimSpace(p.cfg.Type) {
	case "aws-sts":
		return p.verifySTSLeaseCredential(ctx, credential)
	case "postgresql":
		return "connected", rotation.VerifyPostgresCredential(ctx, credential, "SELECT 1")
	case "mysql":
		return "connected", rotation.VerifyMySQLCredential(ctx, credential)
	case "redis", "datadog", "openai", "azure-entra", "openrouter", "fireworks", "litellm", "supabase", "convex", "dbt", "cloudflare", "cloudflare-r2":
		return p.verifyWithBackend(ctx, credential)
	case "oracle", "mssql", "azure-sql":
		return p.verifyDatabaseWithBackend(ctx, credential)
	default:
		return "not_available", nil
	}
}

// VerifyStaticCredential implements dynsecret.StaticRotationProvider. Database
// providers prove the staged credential by opening a session with it; AWS IAM
// access keys have no side-effect-free proof the control plane can sign with the
// new key, so the mode is reported as not available and the worker records it.
func (p *configuredDynamicProvider) VerifyStaticCredential(ctx context.Context, _ string, credential []byte) (string, error) {
	switch strings.TrimSpace(p.cfg.Type) {
	case "postgresql":
		return "connected", rotation.VerifyPostgresCredential(ctx, credential, "SELECT 1")
	case "mysql":
		return "connected", rotation.VerifyMySQLCredential(ctx, credential)
	case "mongodb":
		// A MongoDB credential is a URI: connect with it and ping (A240).
		return "connected", dynsecret.VerifyMongoCredential(ctx, credential)
	case "oracle", "mssql", "azure-sql":
		// An Oracle or SQL Server credential connects at the administrator's
		// address (Oracle's service, SQL Server's database) and runs a
		// trivial query (A240).
		return p.verifyDatabaseWithBackend(ctx, credential)
	case "auth0", "datadog", "openai", "azure-entra", "okta", "databricks", "snowflake", "ldap", "unix", "windows", "iosxe", "junos", "eos", "fortigate", "bigip", "redfish", "esxi", "vcenter-sso", "okta-user", "entra-user", "google-workspace-user", "openrouter", "fireworks", "litellm", "supabase", "convex", "dbt", "cloudflare", "cloudflare-r2":
		// The rotated secret authenticates its application at the token
		// endpoint; a Datadog API key validates at the site, an OpenAI key
		// lists models, a directory entry binds, and a hosted API key passes
		// its vendor's own check where the vendor offers one (A240).
		return p.verifyWithBackend(ctx, credential)
	default:
		return "not_available", nil
	}
}

// verifyDatabaseWithBackend proves a database credential by opening a session
// with it through its backend ("connected").
func (p *configuredDynamicProvider) verifyDatabaseWithBackend(ctx context.Context, credential []byte) (string, error) {
	if _, err := p.verifyWithBackend(ctx, credential); err != nil {
		return "", err
	}
	return "connected", nil
}

// verifyWithBackend proves a credential with its backend's own check
// ("authenticated"); a credential the backend cannot prove without side
// effects (dynsecret.ErrNoSelfProof) is "not_available".
func (p *configuredDynamicProvider) verifyWithBackend(ctx context.Context, credential []byte) (string, error) {
	backend, closeBackend, err := p.open(ctx)
	if err != nil {
		return "", err
	}
	defer closeBackend()
	verifier, ok := backend.(interface {
		VerifyCredential(context.Context, []byte) error
	})
	if !ok {
		return "", fmt.Errorf("server: the %s backend cannot verify a credential", strings.TrimSpace(p.cfg.Type))
	}
	err = verifier.VerifyCredential(ctx, credential)
	if errors.Is(err, dynsecret.ErrNoSelfProof) {
		return "not_available", nil
	}
	return "authenticated", err
}

// DynamicSecretGatewayAWS is the public signing scope frozen in a session job.
func (p *configuredDynamicProvider) DynamicSecretGatewayAWS() (string, string, error) {
	if p.cfg.Type != "aws-sts" || p.cfg.Gateway == nil {
		return "", "", errors.New("provider has no AWS gateway binding")
	}
	return p.cfg.Gateway.Service, p.cfg.Gateway.Region, nil
}

// DynamicSecretGatewayOAuth returns only reviewed public routing and authority.
func (p *configuredDynamicProvider) DynamicSecretGatewayOAuth() (string, []string, string, error) {
	if (p.cfg.Type != "gcp-iam" && p.cfg.Type != "azure-entra") || p.cfg.Gateway == nil {
		return "", nil, "", errors.New("provider has no cloud OAuth gateway binding")
	}
	subject := p.cfg.ServiceAccount
	if p.cfg.Type == "azure-entra" {
		subject = p.cfg.ApplicationClient
	}
	return p.cfg.Gateway.TokenEndpoint, append([]string(nil), p.cfg.Gateway.Scopes...), subject, nil
}

// DynamicSecretGatewayAzureTenant is public authority, frozen beside the client ID.
func (p *configuredDynamicProvider) DynamicSecretGatewayAzureTenant() string {
	if p.cfg.Type != "azure-entra" {
		return ""
	}
	return p.cfg.AzureTenant
}

// DynamicSecretGatewayConsole returns a copy of the reviewed public destinations.
func (p *configuredDynamicProvider) DynamicSecretGatewayConsole() (accessconsole.Binding, error) {
	if p.cfg.Type != "aws-sts" || p.cfg.Console == nil {
		return accessconsole.Binding{}, errors.New("provider has no native console binding")
	}
	return *p.cfg.Console, nil
}

// DynamicSecretGatewayDesktop returns the reviewed route by value.
func (p *configuredDynamicProvider) DynamicSecretGatewayDesktop(role string) (accessdesktop.Binding, error) {
	if p.cfg.Desktop == nil || (p.cfg.Type != "unix" && p.cfg.Type != "windows" && p.cfg.Type != "ldap") || !p.cfg.AllowStaticRotation {
		return accessdesktop.Binding{}, errors.New("provider needs a reviewed static desktop account binding")
	}
	binding := *p.cfg.Desktop
	binding.Accounts = append([]accessdesktop.BoundAccount(nil), binding.Accounts...)
	if p.cfg.DirectoryMode == "active_directory" {
		if !p.allowedRoles[role] {
			return accessdesktop.Binding{}, errors.New("desktop role is not allowed")
		}
		refs := []string{p.cfg.RoleBindings[role]}
		if pair, ok := p.cfg.RotationAccounts[role]; ok {
			refs = append([]string(nil), pair...)
		}
		binding.AccountKind = "active_directory"
		binding.Accounts = nil
		for _, ref := range refs {
			binding.Accounts = append(binding.Accounts, accessdesktop.BoundAccount{Reference: ref, Username: p.cfg.ADLogonNames[ref]})
		}
	}
	return binding, binding.Validate()
}
