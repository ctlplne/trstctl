// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/cloudauth"
	"trstctl.com/trstctl/internal/cloudhttp"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/egress"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/projections"
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
	log *events.Log,
) (SecretSyncTargetRegistry, *cloudauth.Minter, error) {
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{SyncTargets: entries}, true); err != nil {
		return nil, nil, fmt.Errorf("server: invalid secret-sync target config: %w", err)
	}
	registry := SecretSyncTargetRegistry{}
	minter := cloudauth.NewMinter(2 * time.Minute)
	resolver := integrationCredentialResolver{store: st, kek: kek}
	seen := map[string]bool{}
	for _, entry := range entries {
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
		if _, ok := registry[entry.TenantID]; !ok {
			registry[entry.TenantID] = map[string]*secretsync.Target{}
		}
		pusher := newConfiguredSyncPusher(entry, resolver, guard, st, log, minter)
		registry[entry.TenantID][entry.ID] = secretsync.NewTarget(entry.ID, pusher)
	}
	return registry, minter, nil
}

func closeCloudTokenMinterOnError(err *error, minter *cloudauth.Minter) {
	if err != nil && *err != nil {
		minter.Close()
	}
}

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
	case "terraform-cloud-opentofu":
		token, resolveErr := resolve(cfg.TokenRef)
		if resolveErr != nil {
			return resolveErr
		}
		concrete, err = secretsync.NewTerraformCloudOpenTofuPusher(secretsync.TerraformCloudOpenTofuConfig{
			Endpoint: cfg.Endpoint, HTTPClient: client, WorkspaceID: cfg.WorkspaceID,
			Token: token, Category: cfg.VariableCategory, HCL: cfg.HCL, Description: cfg.Description,
		})
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

const defaultGCPWorkloadIdentityEndpoint = "https://sts.googleapis.com/v1/token"

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
