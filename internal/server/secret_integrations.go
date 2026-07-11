// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/egress"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/secretsync"
	"trstctl.com/trstctl/internal/store"
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
	store *store.Store
	kek   seal.KeyWrapper
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
		rec, err := r.store.GetSecret(ctx, tenantID, name)
		if err != nil {
			return nil, fmt.Errorf("load tenant credential %q: %w", name, err)
		}
		value, err := seal.Open(r.kek, rec.Sealed, secretIntegrationStoreAAD(tenantID, name))
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
) (DynamicSecretProviderRegistry, error) {
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: entries}, true); err != nil {
		return nil, fmt.Errorf("server: invalid dynamic-secret provider config: %w", err)
	}
	registry := DynamicSecretProviderRegistry{}
	resolver := integrationCredentialResolver{store: st, kek: kek}
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
	id           string
	tenantID     string
	cfg          config.DynamicSecretProviderConfig
	allowedRoles map[string]bool
	maxTTL       time.Duration
	credentials  integrationCredentialResolver
	guard        *egress.Guard
	open         func(context.Context) (requestDynamicBackend, func(), error)
}

// newConfiguredDynamicProvider assembles the concrete backend opener now, while
// retaining credential resolution until the outbox worker performs one operation.
// This keeps authority-bearing bytes short-lived and makes every shipped backend
// constructor part of buildRunDeps' production call graph.
func newConfiguredDynamicProvider(cfg config.DynamicSecretProviderConfig, allowed map[string]bool, maxTTL time.Duration, credentials integrationCredentialResolver, guard *egress.Guard) dynsecret.Provider {
	provider := &configuredDynamicProvider{
		id: cfg.ID, tenantID: cfg.TenantID, cfg: cfg,
		allowedRoles: allowed, maxTTL: maxTTL, credentials: credentials, guard: guard,
	}
	provider.open = func(ctx context.Context) (requestDynamicBackend, func(), error) {
		return openConfiguredDynamicBackend(ctx, provider)
	}
	if cfg.Type == "gcp-iam" {
		return &configuredPreparedDynamicProvider{configuredDynamicProvider: provider}
	}
	return provider
}

func (p *configuredDynamicProvider) Name() string { return p.id }

// MaximumTTL is the provider credential's hard native-validity bound. The
// durable lifecycle creates native credentials for this duration, then manages a
// shorter renewable control-plane lease within it.
func (p *configuredDynamicProvider) MaximumTTL() time.Duration { return p.maxTTL }

func (p *configuredDynamicProvider) Generate(ctx context.Context, req dynsecret.GenerateRequest) (dynsecret.Credential, error) {
	return p.generate(ctx, req, nil)
}

func (p *configuredDynamicProvider) generate(ctx context.Context, req dynsecret.GenerateRequest, prepared []byte) (dynsecret.Credential, error) {
	if !p.allowedRoles[req.Role] {
		return dynsecret.Credential{}, fmt.Errorf("dynamic-secret provider %q does not allow role %q", p.id, req.Role)
	}
	if req.TTL <= 0 || req.TTL > p.maxTTL {
		return dynsecret.Credential{}, fmt.Errorf("dynamic-secret provider %q TTL must be between 1s and %s", p.id, p.maxTTL)
	}
	backend, closeBackend, err := p.openBackend(ctx)
	if err != nil {
		return dynsecret.Credential{}, err
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
	backend, closeBackend, err := p.openBackend(ctx)
	if err != nil {
		return err
	}
	defer closeBackend()
	return backend.Revoke(ctx, backendRef)
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
	case "postgresql", "mysql", "mongodb", "redis":
		return openConfiguredDatabaseBackend(opener)
	case "kubernetes", "aws-iam", "gcp-iam", "azure-entra":
		return openConfiguredCloudBackend(opener)
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
			Database: cfg.Database, Addr: cfg.Addr, AccountHost: cfg.AccountHost, UsernamePrefix: cfg.UsernamePrefix,
		})
		if err != nil {
			_ = db.Close()
			return o.fail(err)
		}
		return backend, o.closeWith(backend, func() { _ = db.Close() }), nil
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
		backend, err := dynsecret.NewRedisBackend(dynsecret.RedisConfig{
			Addr: cfg.Addr, Password: password, DB: cfg.DB, UsernamePrefix: cfg.UsernamePrefix,
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
		client, err := secretIntegrationHTTPClient(cfg.Endpoint, cfg.AllowPrivate, cfg.AllowInsecureLoopback, cfg.PrivateEgressCIDRs, o.provider.guard)
		if err != nil {
			return o.fail(err)
		}
		backend, err := dynsecret.NewKubernetesBackend(dynsecret.KubernetesConfig{
			Endpoint: cfg.Endpoint, HTTPClient: client, Namespace: cfg.Namespace,
			BearerToken: token, UsernamePrefix: cfg.UsernamePrefix, RoleBindings: cfg.RoleBindings,
		})
		if err != nil {
			return o.fail(err)
		}
		return backend, o.closeWith(backend, nil), nil
	case "aws-iam":
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
		backend, err := dynsecret.NewAWSIAMBackend(dynsecret.AWSIAMConfig{
			Endpoint: cfg.Endpoint, HTTPClient: client, Region: cfg.Region,
			AccessKeyID: cfg.AccessKeyID, SecretAccessKey: secretKey, SessionToken: session,
			UsernamePrefix: cfg.UsernamePrefix, PolicyARNs: cfg.RoleBindings,
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
		backend, err := dynsecret.NewGCPIAMBackend(dynsecret.GCPIAMConfig{
			Endpoint: cfg.Endpoint, HTTPClient: client, Project: cfg.Project,
			ServiceAccountEmail: cfg.ServiceAccount, BearerToken: token, UsernamePrefix: cfg.UsernamePrefix,
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
			BearerToken: token, UsernamePrefix: cfg.UsernamePrefix,
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
) (SecretSyncTargetRegistry, error) {
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{SyncTargets: entries}, true); err != nil {
		return nil, fmt.Errorf("server: invalid secret-sync target config: %w", err)
	}
	registry := SecretSyncTargetRegistry{}
	resolver := integrationCredentialResolver{store: st, kek: kek}
	seen := map[string]bool{}
	for _, entry := range entries {
		key := entry.TenantID + "\x00" + entry.ID
		if seen[key] {
			return nil, fmt.Errorf("server: duplicate secret-sync target %s/%s", entry.TenantID, entry.ID)
		}
		seen[key] = true
		if entry.TenantID == "" || entry.ID == "" {
			return nil, errors.New("server: secret-sync target requires tenant and id")
		}
		if _, err := secretIntegrationHTTPClient(entry.Endpoint, entry.AllowPrivate, entry.AllowInsecureLoopback, entry.PrivateEgressCIDRs, guard); err != nil {
			return nil, fmt.Errorf("server: secret-sync target %s/%s endpoint: %w", entry.TenantID, entry.ID, err)
		}
		if _, ok := registry[entry.TenantID]; !ok {
			registry[entry.TenantID] = map[string]*secretsync.Target{}
		}
		pusher := newConfiguredSyncPusher(entry, resolver, guard)
		registry[entry.TenantID][entry.ID] = secretsync.NewTarget(entry.ID, pusher)
	}
	return registry, nil
}

type configuredSyncPusher struct {
	tenantID    string
	cfg         config.SecretSyncTargetConfig
	credentials integrationCredentialResolver
	guard       *egress.Guard
	push        func(context.Context, string, []byte) error
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
func newConfiguredSyncPusher(cfg config.SecretSyncTargetConfig, credentials integrationCredentialResolver, guard *egress.Guard) *configuredSyncPusher {
	pusher := &configuredSyncPusher{tenantID: cfg.TenantID, cfg: cfg, credentials: credentials, guard: guard}
	pusher.push = func(ctx context.Context, key string, value []byte) error {
		return pushConfiguredSecretSync(ctx, pusher, key, value)
	}
	return pusher
}

func pushConfiguredSecretSync(ctx context.Context, p *configuredSyncPusher, key string, value []byte) error {
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
	client, err := secretIntegrationHTTPClient(p.cfg.Endpoint, p.cfg.AllowPrivate, p.cfg.AllowInsecureLoopback, p.cfg.PrivateEgressCIDRs, p.guard)
	if err != nil {
		return err
	}
	var concrete secretsync.Pusher
	cfg := p.cfg
	switch cfg.Type {
	case "aws-secrets-manager":
		secretKey, resolveErr := resolve(cfg.SecretAccessRef)
		if resolveErr != nil {
			return resolveErr
		}
		session, resolveErr := resolve(cfg.SessionTokenRef)
		if resolveErr != nil {
			return resolveErr
		}
		concrete, err = secretsync.NewAWSSecretsManagerPusher(secretsync.AWSSecretsManagerConfig{
			Endpoint: cfg.Endpoint, HTTPClient: client, Region: cfg.Region,
			AccessKeyID: cfg.AccessKeyID, SecretAccessKey: secretKey, SessionToken: session,
		})
	case "gcp-secret-manager":
		token, resolveErr := resolve(cfg.TokenRef)
		if resolveErr != nil {
			return resolveErr
		}
		concrete, err = secretsync.NewGCPSecretManagerPusher(secretsync.GCPSecretManagerConfig{
			Endpoint: cfg.Endpoint, HTTPClient: client, Project: cfg.Project, BearerToken: token,
		})
	case "azure-key-vault":
		token, resolveErr := resolve(cfg.TokenRef)
		if resolveErr != nil {
			return resolveErr
		}
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
		concrete, err = secretsync.NewCIPusher(secretsync.CIPusherConfig{
			Endpoint: cfg.Endpoint, HTTPClient: client, BearerToken: token, Provider: cfg.Provider,
		})
	case "kubernetes-secrets":
		token, resolveErr := resolve(cfg.TokenRef)
		if resolveErr != nil {
			return resolveErr
		}
		concrete, err = secretsync.NewKubernetesPusher(secretsync.KubernetesConfig{
			Endpoint: cfg.Endpoint, HTTPClient: client, Namespace: cfg.Namespace, BearerToken: token,
		})
	default:
		return fmt.Errorf("server: unsupported secret-sync target type %q", cfg.Type)
	}
	if err != nil {
		return err
	}
	if closer, ok := concrete.(interface{ Close() }); ok {
		defer closer.Close()
	}
	return concrete.Push(ctx, key, value)
}

func secretIntegrationHTTPClient(endpoint string, allowPrivate, allowInsecureLoopback bool, privateCIDRs []string, guard *egress.Guard) (*http.Client, error) {
	if err := netsec.ValidateHTTPSOrInsecureLoopbackURL(endpoint, allowInsecureLoopback); err != nil {
		return nil, err
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
