// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
	"trstctl.com/trstctl/internal/lifecycle"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/buildinfo"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/cloudauth"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/egress"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/leader"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/logging"
	"trstctl.com/trstctl/internal/notify"
	notifyemail "trstctl.com/trstctl/internal/notify/email"
	"trstctl.com/trstctl/internal/notify/siem"
	"trstctl.com/trstctl/internal/notify/slack"
	"trstctl.com/trstctl/internal/notify/sms"
	"trstctl.com/trstctl/internal/notify/teams"
	"trstctl.com/trstctl/internal/observ"
	"trstctl.com/trstctl/internal/observ/otlp"
	"trstctl.com/trstctl/internal/pluginhost"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/ratelimit"
	"trstctl.com/trstctl/internal/secrets"
	"trstctl.com/trstctl/internal/secrettext"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/telemetry"
	"trstctl.com/trstctl/internal/tenantseal"
)

// EditionAttach is the single open-core seam. The default cmd/trstctl build
// passes the tagged attachEE implementation; the trstctl_core build passes the
// no-op twin. S-E0 uses it only to prove the seam exists. Later edition cards
// may mutate Deps here before Build wires the API and background workers.
type EditionAttach func(context.Context, *config.Config, *slog.Logger, *license.Manager, *Deps) error

// Run opens the datastore and event log, supervises the signer as a child
// process (AN-4), assembles the control plane, and serves until ctx is
// cancelled — then shuts down in order (stop accepting → drain the outbox →
// close the event log and datastore). It is the production composition the
// trstctl binary calls.
func Run(ctx context.Context, cfg *config.Config, attachers ...EditionAttach) error {
	return RunWithExtraMigrations(ctx, cfg, nil, attachers...)
}

// RunWithExtraMigrations is the production composition with optional extension
// migration sources registered before the store migrates. It is feature-neutral:
// the core-only binary passes none, while a tagged edition binary may pass its
// own fs.FS migration bundles without importing edition code into core.
func RunWithExtraMigrations(ctx context.Context, cfg *config.Config, extraMigrations []fs.FS, attachers ...EditionAttach) error {
	logger, err := logging.New(logging.Options{Level: cfg.Log.Level, Format: cfg.Log.Format, Service: "trstctl"}, os.Stderr)
	if err != nil {
		return fmt.Errorf("build logger: %w", err)
	}
	lic, err := license.Load(cfg.License.File, license.TrustedKeys())
	if err != nil {
		return fmt.Errorf("license: %w", err)
	}
	logger.Info("editions initialized",
		slog.String("tier", string(lic.Tier())),
		slog.String("state", string(lic.State())))
	egressGuard, err := egressGuardFromConfig(cfg.AirGap)
	if err != nil {
		return err
	}

	st, stopPG, err := openMigratedStore(ctx, cfg, logger, extraMigrations)
	if err != nil {
		return err
	}
	defer func() {
		if stopPG != nil {
			_ = stopPG()
		}
	}()
	serverOwnsStore := false
	defer func() {
		if !serverOwnsStore {
			st.Close()
		}
	}()

	runSecrets, err := loadRunSecrets(cfg)
	if err != nil {
		return err
	}
	defer runSecrets.Close()

	auditKey, err := audit.LoadOrCreateSigningKey(cfg.Audit.SigningKeyFile, "audit-export")
	if err != nil {
		return fmt.Errorf("audit signing key: %w", err)
	}

	log, err := openHistoryAwareEventLog(ctx, cfg.NATS, st, auditKey)
	if err != nil {
		return fmt.Errorf("open event log: %w", err)
	}
	serverOwnsLog := false
	defer func() {
		if !serverOwnsLog {
			_ = log.Close()
		}
	}()

	runSigner, err := openRunSigner(ctx, cfg)
	if err != nil {
		return err
	}
	defer runSigner.Close()

	deps, err := buildRunDeps(ctx, cfg, st, log, runSigner, runSecrets, logger, egressGuard, auditKey)
	if err != nil {
		return err
	}
	notificationOwner := ensureNotificationChannelOwnership(&deps)
	// Until Build transfers the channels to its Dispatcher, Run owns their
	// credential buffers. This catches edition-attach and any other pre-Build
	// failure. After transfer this is intentionally a no-op.
	defer notificationOwner.closeUntransferred()
	deps.License = lic
	if err := applyEditionAttachers(ctx, cfg, logger, lic, &deps, attachers...); err != nil {
		return err
	}
	srv, err := Build(ctx, deps)
	if err != nil {
		return err
	}
	serverOwnsStore = true
	serverOwnsLog = true
	logger.Info("control plane assembled",
		slog.String("addr", cfg.Server.Addr), slog.String("tls_mode", cfg.Server.TLS.Mode))

	if err := configureSnapshotCadence(srv, cfg); err != nil {
		_ = srv.Shutdown(ctx)
		return err
	}
	stopBackground, err := startBackgroundRuntime(ctx, cfg, srv, st, logger)
	if err != nil {
		_ = srv.Shutdown(ctx)
		return err
	}
	return serveRuntime(ctx, cfg, srv, logger, stopBackground)
}

func applyEditionAttachers(ctx context.Context, cfg *config.Config, logger *slog.Logger, lic *license.Manager, deps *Deps, attachers ...EditionAttach) (err error) {
	owner := ensureNotificationChannelOwnership(deps)
	defer func() {
		if err != nil {
			// Adopt channels appended by an attacher before it failed, then close
			// both the original and newly attached credentials through one token.
			ensureNotificationChannelOwnership(deps).closeUntransferred()
		}
	}()
	for _, attach := range attachers {
		if attach == nil {
			continue
		}
		if err := attach(ctx, cfg, logger, lic, deps); err != nil {
			return err
		}
		deps.NotificationChannels = owner.adopt(deps.NotificationChannels)
	}
	return nil
}

func openMigratedStore(ctx context.Context, cfg *config.Config, logger *slog.Logger, extraMigrations []fs.FS) (*store.Store, func() error, error) {
	dsn, stopPG, err := openDatastore(cfg.Postgres, logger)
	if err != nil {
		return nil, nil, err
	}
	stmtTimeout, err := cfg.Postgres.StatementTimeoutDuration()
	if err != nil {
		return nil, nil, fmt.Errorf("postgres statement timeout: %w", err)
	}
	acquireTimeout, err := cfg.Postgres.AcquireTimeoutDuration()
	if err != nil {
		return nil, nil, fmt.Errorf("postgres acquire timeout: %w", err)
	}
	st, err := store.Open(ctx, dsn, store.WithStatementTimeout(stmtTimeout), store.WithAcquireTimeout(acquireTimeout))
	if err != nil {
		if stopPG != nil {
			_ = stopPG()
		}
		return nil, nil, fmt.Errorf("open store: %w", err)
	}
	registerExtraMigrations(st, extraMigrations)
	pending, err := st.PendingMigrations(ctx)
	if err != nil {
		st.Close()
		if stopPG != nil {
			_ = stopPG()
		}
		return nil, nil, fmt.Errorf("inspect migrations: %w", err)
	}
	if len(pending) > 0 {
		if !cfg.Migrate.Auto {
			st.Close()
			if stopPG != nil {
				_ = stopPG()
			}
			return nil, nil, fmt.Errorf("%d pending database migration(s) and automatic migration is disabled (TRSTCTL_MIGRATE_AUTO=false): take a backup (trstctl --backup), then apply them with 'trstctl --migrate'; pending: %v", len(pending), pending)
		}
		logger.Info("applying pending database migrations", "count", len(pending))
	}
	if err := st.Migrate(ctx); err != nil {
		st.Close()
		if stopPG != nil {
			_ = stopPG()
		}
		return nil, nil, fmt.Errorf("migrate: %w", err)
	}
	return st, stopPG, nil
}

func registerExtraMigrations(st *store.Store, sources []fs.FS) {
	for _, src := range sources {
		if src != nil {
			st.WithExtraMigrations(src)
		}
	}
}

type runSecrets struct {
	kek        sealKeyWrapper
	authSecret []byte
	destroy    func()
}

func (s runSecrets) Close() {
	if s.destroy != nil {
		s.destroy()
	}
}

func loadRunSecrets(cfg *config.Config) (runSecrets, error) {
	kek, err := secrets.LoadOrCreateKEK(cfg.Secrets.KEKFile)
	if err != nil {
		return runSecrets{}, fmt.Errorf("provision credential KEK: %w", err)
	}
	out := runSecrets{kek: kek, destroy: kek.Destroy}
	if cfg.Secrets.EnableAPI && cfg.Secrets.AuthSecretFile != "" {
		out.authSecret, err = secrets.LoadOrCreateAuthSecret(cfg.Secrets.AuthSecretFile)
		if err != nil {
			out.Close()
			return runSecrets{}, fmt.Errorf("provision machine-login secret: %w", err)
		}
	}
	return out, nil
}

type runSigner struct {
	signer        SignerProvider
	tokenProvider signing.SignTokenProvider
	close         func()
}

func (r runSigner) Close() {
	if r.close != nil {
		r.close()
	}
	if destroyer, ok := r.tokenProvider.(interface{ Destroy() }); ok {
		destroyer.Destroy()
	}
}

func openRunSigner(ctx context.Context, cfg *config.Config) (runSigner, error) {
	out := runSigner{}
	var signerErr error
	switch cfg.Signer.Mode {
	case config.SignerExternal:
		out.signer, out.close, signerErr = connectExternalSigner(ctx, cfg.Signer)
	default:
		out.signer, out.close, signerErr = startChildSigner(ctx, cfg)
	}
	if signerErr != nil {
		out.Close()
		return runSigner{}, signerErr
	}
	tokenProvider, err := buildSignTokenProvider(cfg)
	if err != nil {
		out.Close()
		return runSigner{}, err
	}
	out.tokenProvider = tokenProvider
	return out, nil
}

func buildSignTokenProvider(cfg *config.Config) (signing.SignTokenProvider, error) {
	if cfg.Signer.AuthTokenCommand != "" {
		return newSignTokenCommand(cfg.Signer.AuthTokenCommand), nil
	}
	if cfg.Signer.AllowCoResidentAuthorizer {
		authz, err := signing.LoadOrCreateAuthorizer(cfg.Signer.AuthSecretFile)
		if err != nil {
			return nil, fmt.Errorf("eval signer content authorizer: %w", err)
		}
		return authz, nil
	}
	return nil, nil
}

func connectExternalSigner(ctx context.Context, cfg config.Signer) (SignerProvider, func(), error) {
	if err := applySignerCallTimeout(cfg); err != nil {
		return nil, nil, err
	}
	var c *signing.Client
	var err error
	if cfg.MTLSEnabled() {
		c, err = signing.DialReadyMTLS(ctx, cfg.MTLSAddress, mtls.SignerPeerConfig{
			CertFile: cfg.MTLSCertFile, KeyFile: cfg.MTLSKeyFile,
			PeerCAFile: cfg.MTLSPeerCAFile, PeerPinHex: cfg.MTLSPeerPin,
		}, cfg.MTLSServerName, 10*time.Second)
		if err != nil {
			return nil, nil, fmt.Errorf("connect external signer over mTLS at %s: %w", cfg.MTLSAddress, err)
		}
	} else {
		c, err = signing.DialReady(ctx, cfg.Socket, 30*time.Second)
		if err != nil {
			return nil, nil, fmt.Errorf("connect external signer at %s: %w", cfg.Socket, err)
		}
	}
	return signing.StaticProvider{C: c}, func() { _ = c.Close() }, nil
}

// applySignerCallTimeout binds the validated per-call signer deadline before
// any signer RPC can hang an issuance (OPS-TIMEOUTS-001).
func applySignerCallTimeout(cfg config.Signer) error {
	if cfg.CallTimeout == "" {
		return nil
	}
	d, err := time.ParseDuration(cfg.CallTimeout)
	if err != nil {
		return fmt.Errorf("signer call timeout: %w", err)
	}
	if err := signing.SetSignerCallTimeout(d); err != nil {
		return fmt.Errorf("signer call timeout: %w", err)
	}
	return nil
}

func startChildSigner(ctx context.Context, cfg *config.Config) (SignerProvider, func(), error) {
	if err := applySignerCallTimeout(cfg.Signer); err != nil {
		return nil, nil, err
	}
	signerBin, err := siblingBinary("trstctl-signer")
	if err != nil {
		return nil, nil, err
	}
	socket := cfg.Signer.Socket
	if socket == "" {
		socket = filepath.Join(os.TempDir(), "trstctl-signer.sock")
	}
	args := []string{
		"--keystore", cfg.Signer.KeyStoreDir,
		"--kek", cfg.Secrets.KEKFile,
		"--auth-secret", cfg.Signer.AuthSecretFile,
	}
	managedKeysCleanup := func() {}
	if cfg.ManagedKeys.Enabled {
		managedKeysConfig, cleanup, err := prepareManagedKeySignerConfig(cfg.ManagedKeys)
		if err != nil {
			return nil, nil, fmt.Errorf("prepare signer managed-key config: %w", err)
		}
		managedKeysCleanup = cleanup
		args = append(args, "--managed-keys-config", managedKeysConfig)
	}
	if cfg.License.File != "" {
		args = append(args, "--license", cfg.License.File)
	}
	if cfg.Signer.AllowInsecureDevNonLinux {
		args = append(args, "--allow-insecure-dev-nonlinux")
	}
	sup, err := signing.Supervise(ctx, signerBin, socket, args...)
	if err != nil {
		managedKeysCleanup()
		return nil, nil, fmt.Errorf("start signer: %w", err)
	}
	return sup, func() {
		sup.Close()
		managedKeysCleanup()
	}, nil
}

func buildRunDeps(ctx context.Context, cfg *config.Config, st *store.Store, log *events.Log, signer runSigner, sec runSecrets, logger *slog.Logger, egressGuard *egress.Guard, suppliedAuditKey ...*jose.SigningKey) (_ Deps, err error) {
	auditKey, err := loadRunAuditSigningKey(cfg, suppliedAuditKey)
	if err != nil {
		return Deps{}, err
	}
	rateLimiter, err := buildRateLimiter(cfg, st)
	if err != nil {
		return Deps{}, err
	}
	retention, privacyRetentionEnabled, privacyRetentionInterval, privacyRetentionPolicy, renewBefore, alertBefore, err := runRetentionAndLifecycleWindows(cfg)
	// D6: parsed at startup, not at sweep time. A malformed window REFUSES to
	// start rather than being silently ignored — an operator who wrote a change
	// freeze this could not read would believe production was protected while
	// the scheduler renewed straight through it.
	maintenanceWindows, windowErr := parseMaintenanceWindows(cfg.Lifecycle.MaintenanceWindows)
	if windowErr != nil {
		return Deps{}, windowErr
	}
	if err != nil {
		return Deps{}, err
	}
	leafValidity, err := cfg.Lifecycle.LeafValidityDuration()
	if err != nil {
		return Deps{}, fmt.Errorf("lifecycle leaf validity: %w", err)
	}
	pluginCfg, err := buildPluginConfig(cfg.Plugins)
	if err != nil {
		return Deps{}, fmt.Errorf("plugins: %w", err)
	}
	aiModel, aiModelStatus, err := aiModelFromConfig(cfg.AI.Model, egressGuard)
	if err != nil {
		return Deps{}, fmt.Errorf("ai model: %w", err)
	}
	machineAuthMethods, err := machineAuthMethodsFromConfig(cfg.Secrets.MachineAuth)
	if err != nil {
		return Deps{}, fmt.Errorf("secrets machine auth: %w", err)
	}
	resultProtector, resultMigrator, tenantKeyDomains, tenantCrypto, err := runTenantCustodyFromConfig(
		cfg.Secrets, st, log, sec.kek, auditKey,
	)
	if err != nil {
		return Deps{}, err
	}
	breakglassCACertDER, breakglassPublicKeyDER, err := breakglassVerifierMaterialFromConfig(cfg.Breakglass)
	if err != nil {
		return Deps{}, fmt.Errorf("break-glass verifier material: %w", err)
	}
	breakglassRuntime, err := breakglassRotationFromConfig(ctx, cfg.Breakglass, st, log, signer.signer, signer.tokenProvider, breakglassCACertDER, breakglassPublicKeyDER)
	if err != nil {
		return Deps{}, fmt.Errorf("break-glass online lifecycle: %w", err)
	}
	notificationChannels, notificationOwner, err := runNotifications(cfg.Notifications, egressGuard)
	if err != nil {
		return Deps{}, err
	}
	// From this point until the returned Deps is successfully transferred to
	// Build, buildRunDeps owns every channel credential. Any later constructor
	// failure must wipe that authority rather than abandoning locked buffers.
	defer func() {
		if err != nil {
			notificationOwner.closeUntransferred()
		}
	}()
	codeSigning, err := codeSigningConfigFromConfig(ctx, cfg.CodeSigning, signer.signer, signer.tokenProvider, egressGuard)
	if err != nil {
		return Deps{}, fmt.Errorf("code-signing: %w", err)
	}
	outbound, err := buildRunOutboundDeps(ctx, cfg, st, log, signer, sec, egressGuard, tenantCrypto)
	if err != nil {
		return Deps{}, err
	}
	defer closeCloudTokenMinterOnError(&err, outbound.cloudTokenMinter)
	protocols, err := evalProtocolProfileFromConfig(cfg)
	if err != nil {
		return Deps{}, err
	}
	return Deps{
		Store: st, Log: log, Signer: signer.signer, SignTokenProvider: signer.tokenProvider,
		SignerKeyStoreDir:         cfg.Signer.KeyStoreDir,
		EgressGuard:               egressGuard,
		ServiceNowBindings:        serviceNowBindingsFromConfig(cfg.ITSM.ServiceNow),
		OutboundEnvCredentialRefs: append([]string(nil), cfg.OutboundEnvCredentialRefs...),
		TelemetryReporter:         outbound.telemetryReporter,
		APIOptions:                []api.Option{kubernetesCSRPostureFromConfig(st), kubernetesTrustBundlePostureFromConfig(st)},
		CACertFile:                cfg.CA.CertFile, LeafProfile: leafProfileFromConfig(cfg), DefaultProfile: cfg.CA.DefaultProfile,
		PolicyModule: cfg.CA.Policy.Module, EnablePolicyGate: cfg.CA.Policy.Enabled,
		ABACModule: cfg.Auth.ABAC.Module, EnableABAC: cfg.Auth.ABAC.Enabled, ABACEnvironment: cfg.Auth.ABAC.Environment,
		BreakglassCACertDER: breakglassCACertDER, BreakglassPublicKeyDER: breakglassPublicKeyDER,
		BreakglassIssuer: breakglassRuntime, BreakglassCeremonies: breakglassRuntime,
		BreakglassRotation: breakglassRuntime, BreakglassReconciler: breakglassRuntime,
		RequireApproval: cfg.CA.Policy.RequireApproval, RequiredApprovals: cfg.CA.Policy.RequiredApprovals,
		AuditSigningKey: auditKey, AuditRetention: retention, AuditArchiveDir: cfg.Audit.ArchiveDir,
		PrivacyRetentionEnabled: privacyRetentionEnabled, PrivacyRetentionInterval: privacyRetentionInterval,
		PrivacyRetentionPolicy:       privacyRetentionPolicy,
		LifecycleRenewBefore:         renewBefore,
		MaintenanceWindows:           maintenanceWindows,
		LifecycleAlertBefore:         alertBefore,
		LifecycleLeafValidity:        leafValidity,
		NotificationChannels:         notificationChannels,
		notificationChannelOwner:     notificationOwner,
		CodeSigning:                  codeSigning,
		ConnectorRegistry:            outbound.connectorRegistry,
		ConnectorRightSize:           outbound.connectorRightSize,
		ExternalCAs:                  outbound.externalCAs,
		UpstreamDV:                   outbound.upstreamDV,
		TenantDynamicSecretProviders: outbound.dynamicSecretProviders,
		TenantSecretSyncTargets:      outbound.secretSyncTargets,
		CloudTokenMinter:             outbound.cloudTokenMinter,
		Logger:                       logger, RateLimiter: rateLimiter,
		OTLPExporter:    outbound.otlpExporter,
		Bulkhead:        bulkhead.NewSet(cfg.Bulkheads.Configs()...),
		SecurityHeaders: SecurityHeaders{TLS: cfg.Server.TLS.Mode != config.TLSDisabled, AllowedOrigins: cfg.Server.CORSAllowedOrigins},
		Protocols:       protocols, Plugins: pluginCfg,
		OIDC: cfg.Auth.OIDC, SAML: cfg.Auth.SAML, LDAP: cfg.Auth.LDAP, SCIM: cfg.Auth.SCIM,
		EnableSecretsAPI: vaultCompatRuntimeFromConfig(cfg), KEK: sec.kek,
		TenantCrypto:                tenantCrypto,
		IdempotencyResultProtector:  resultProtector,
		IdempotencyResultMigrator:   resultMigrator,
		IdempotencyResultFleetReady: cfg.Secrets.IdempotencyResultFleetReady,
		TenantKeyDomains:            tenantKeyDomains,
		SecretsAuthSecret:           sec.authSecret,
		MachineAuthMethods:          machineAuthMethods,
		SecretScanGitleaksBin:       cfg.Secrets.GitleaksBin,
		EnableAISurface:             cfg.AI.EnableAPI, AIModel: aiModel, AIModelStatus: aiModelStatus,
		AIMCPIdentity: cfg.AI.MCPIdentity, EnableMCPWriteTools: cfg.AI.MCPWriteTools, AIRateMax: cfg.AI.RateMax, AIRateWindow: cfg.AI.RateWindow(),
		EnableAgentChannel: cfg.AgentChannel.Enabled, AgentChannelAddr: cfg.AgentChannel.Addr, AgentHTTPRenewalAddr: cfg.AgentChannel.HTTPRenewalAddr,
		AgentClaimableJobKinds: cfg.AgentChannel.ClaimableJobKinds,
		AgentCACertFile:        agentCACertFile(cfg), AgentHeartbeatInterval: agentHeartbeatInterval(cfg),
		AgentChannelServerName: cfg.AgentChannel.ServerName,
	}, nil
}

// runOutboundDeps is everything the control plane builds that will eventually
// reach OUTSIDE this process: connectors that deploy to an estate, external CAs,
// dynamic secret providers, secret-sync targets, and the two telemetry exporters.
// They are grouped because they share a property that matters — each one takes the
// egress guard, and each is a place where a misconfiguration becomes an outbound
// call to somewhere it should not go (AN-6).
type runOutboundDeps struct {
	connectorRegistry      *connector.Registry
	connectorRightSize     RightSizeMutator
	externalCAs            []ExternalCA
	upstreamDV             *upstreamDVHolder
	dynamicSecretProviders DynamicSecretProviderRegistry
	secretSyncTargets      SecretSyncTargetRegistry
	cloudTokenMinter       *cloudauth.Minter
	telemetryReporter      *telemetry.Reporter
	otlpExporter           *otlp.Exporter
}

// buildRunOutboundDeps constructs the outbound-integration stage. Split out of
// buildRunDeps so that function stays under the startup-hotspot limit and so this
// stage — the one where every external effect originates — is named and readable
// on its own.
//
// The caller owns closing cloudTokenMinter on a later failure: this returns it
// live, exactly as the inline code did.
func buildRunOutboundDeps(
	ctx context.Context,
	cfg *config.Config,
	st *store.Store,
	log *events.Log,
	signer runSigner,
	sec runSecrets,
	egressGuard *egress.Guard,
	tenantCrypto tenantseal.Access,
) (runOutboundDeps, error) {
	var out runOutboundDeps
	var err error
	if out.connectorRegistry, err = connectorRegistryFromConfig(cfg.Connectors, st, sec.kek, egressGuard, tenantCrypto); err != nil {
		return runOutboundDeps{}, fmt.Errorf("connectors: %w", err)
	}
	if out.connectorRightSize, err = connectorRightSizeHandler(cfg.Connectors, st, sec.kek, egressGuard, tenantCrypto); err != nil {
		return runOutboundDeps{}, fmt.Errorf("connector right-size: %w", err)
	}
	// Built here and filled by the Server once the DNS-01 automation exists;
	// the ACME factories below capture it now (epic B7).
	out.upstreamDV = &upstreamDVHolder{}
	if out.externalCAs, err = externalCAsFromConfig(ctx, cfg.ExternalCAs, signer.signer, signer.tokenProvider, egressGuard, out.upstreamDV); err != nil {
		return runOutboundDeps{}, fmt.Errorf("external CAs: %w", err)
	}
	if out.dynamicSecretProviders, err = dynamicSecretProvidersFromConfig(ctx, cfg.SecretIntegrations.DynamicProviders, st, sec.kek, egressGuard, tenantCrypto); err != nil {
		return runOutboundDeps{}, fmt.Errorf("dynamic-secret providers: %w", err)
	}
	if out.secretSyncTargets, out.cloudTokenMinter, err = secretSyncTargetsFromConfig(ctx, cfg.SecretIntegrations.SyncTargets, st, sec.kek, egressGuard, log, tenantCrypto); err != nil {
		return runOutboundDeps{}, fmt.Errorf("secret-sync targets: %w", err)
	}
	if out.telemetryReporter, err = telemetryReporterFromConfig(cfg.Telemetry, st, egressGuard); err != nil {
		// A minter built above must not leak when a later constructor in this
		// stage fails; the caller's deferred close only sees what is returned.
		closeCloudTokenMinter(out.cloudTokenMinter)
		return runOutboundDeps{}, fmt.Errorf("telemetry: %w", err)
	}
	if out.otlpExporter, err = otlpExporterFromConfig(cfg.OTLP, egressGuard); err != nil {
		closeCloudTokenMinter(out.cloudTokenMinter)
		return runOutboundDeps{}, err
	}
	return out, nil
}

func runNotifications(cfg config.Notifications, guard *egress.Guard) ([]notify.Notifier, *notificationChannelOwnership, error) {
	channels, err := notificationChannelsFromConfig(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("notifications: %w", err)
	}
	channels, owner, err := completeRunNotificationChannels(channels, func() ([]notify.Notifier, error) {
		return incidentNotificationChannelsFromConfig(cfg, guard)
	})
	if err != nil {
		return nil, nil, fmt.Errorf("incident notifications: %w", err)
	}
	return channels, owner, nil
}

// runTenantCustodyFromConfig composes the two mutually dependent custody
// services as one startup stage. Result protection and tenant lifecycle must
// share the exact registry and access resolver; constructing either through a
// parallel path would make a sealed tenant readable through the other.
func runTenantCustodyFromConfig(
	cfg config.Secrets,
	st *store.Store,
	log *events.Log,
	deployment sealKeyWrapper,
	auditKey *jose.SigningKey,
) (*tenantseal.ResultProtector, *tenantseal.ResultMigrator, *tenantseal.Lifecycle, tenantseal.Access, error) {
	if st == nil {
		return nil, nil, nil, nil, nil
	}
	protector, migrator, registry, access, err := idempotencyResultProtectionFromConfig(cfg, st, deployment)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("tenant result protection: %w", err)
	}
	if log == nil {
		return protector, migrator, nil, access, nil
	}
	lifecycle, err := tenantseal.NewLifecycle(
		st, log, deployment, registry,
		historyRewriteProofOptions(st, auditKey)...,
	)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("tenant key-domain lifecycle: %w", err)
	}
	return protector, migrator, lifecycle, access, nil
}

func idempotencyResultProtectionFromConfig(
	cfg config.Secrets,
	st *store.Store,
	deployment sealKeyWrapper,
) (*tenantseal.ResultProtector, *tenantseal.ResultMigrator, *tenantseal.LocalWrapperRegistry, tenantseal.Access, error) {
	wrappers := make([]tenantseal.LocalWrapper, 0, len(cfg.TenantSealLocalWrappers))
	for _, wrapper := range cfg.TenantSealLocalWrappers {
		wrappers = append(wrappers, tenantseal.LocalWrapper{
			ID: wrapper.ID, Path: wrapper.File,
		})
	}
	registry, err := tenantseal.NewLocalWrapperRegistry(wrappers)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	access, err := tenantseal.NewAccess(st, deployment, registry)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	protector, err := tenantseal.NewResultProtector(access)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	migrator, err := tenantseal.NewResultMigrator(
		st, protector, 0, cfg.IdempotencyResultFleetReady,
	)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return protector, migrator, registry, access, nil
}

func loadRunAuditSigningKey(
	cfg *config.Config,
	supplied []*jose.SigningKey,
) (*jose.SigningKey, error) {
	if len(supplied) > 1 {
		return nil, errors.New("audit signing key: multiple supplied keys")
	}
	if len(supplied) == 1 {
		if supplied[0] == nil {
			return nil, errors.New("audit signing key: supplied key is nil")
		}
		return supplied[0], nil
	}
	key, err := audit.LoadOrCreateSigningKey(cfg.Audit.SigningKeyFile, "audit-export")
	if err != nil {
		return nil, fmt.Errorf("audit signing key: %w", err)
	}
	return key, nil
}

// vaultCompatRuntimeFromConfig binds Vault/OpenBao compatibility to the same
// production switch as the native secrets API. The explicit assembly seam lets
// the DoD census prove that compatibility routes are reachable from the shipped
// binary instead of accepting a registry assembled only by a test.
func vaultCompatRuntimeFromConfig(cfg *config.Config) bool {
	return cfg != nil && cfg.Secrets.EnableAPI
}

// kubernetesCSRPostureFromConfig deliberately returns an API option instead of
// relying on API.New's generic store argument. The shipped binary therefore has
// an auditable production edge from buildRunDeps to the real projected
// CertificateSigningRequest controller state.
func kubernetesCSRPostureFromConfig(st *store.Store) api.Option {
	if st == nil {
		return api.WithKubernetesCSRPosture(nil)
	}
	return api.WithKubernetesCSRPosture(st)
}

// kubernetesTrustBundlePostureFromConfig is the equivalent explicit production
// edge for the TrustBundle controller-state route.
func kubernetesTrustBundlePostureFromConfig(st *store.Store) api.Option {
	if st == nil {
		return api.WithKubernetesTrustBundlePosture(nil)
	}
	return api.WithKubernetesTrustBundlePosture(st)
}

// evalProtocolProfileFromConfig resolves the explicit shipped eval preset at the
// production assembly boundary. Keeping the call in buildRunDeps makes the named
// profile part of cmd/trstctl's real dependency graph; tests cannot green the
// capability by constructing a protocol registry on their own. The config package
// keeps production default-off and binds the eval profile to one explicit tenant.
func evalProtocolProfileFromConfig(cfg *config.Config) (config.Protocols, error) {
	if cfg == nil {
		return config.Protocols{}, errors.New("protocols: nil config")
	}
	protocols, err := cfg.Protocols.Effective()
	if err != nil {
		return config.Protocols{}, fmt.Errorf("protocols: resolve profile: %w", err)
	}
	if err := errors.Join(protocols.ValidateTenantBindings("")...); err != nil {
		return config.Protocols{}, fmt.Errorf("protocols: validate profile: %w", err)
	}
	return protocols, nil
}

func serviceNowBindingsFromConfig(sn config.ServiceNowITSM) []api.ServiceNowBinding {
	if len(sn.Bindings) == 0 {
		return nil
	}
	out := make([]api.ServiceNowBinding, 0, len(sn.Bindings))
	for _, b := range sn.Bindings {
		out = append(out, api.ServiceNowBinding{
			InstanceURL:          b.InstanceURL,
			TokenRef:             b.TokenRef,
			AllowPrivateEndpoint: b.AllowPrivateEndpoint,
			PrivateEgressCIDRs:   append([]string(nil), b.PrivateEgressCIDRs...),
		})
	}
	return out
}

func buildRateLimiter(cfg *config.Config, st *store.Store) (api.RateLimiter, error) {
	if !cfg.RateLimit.Enabled {
		return nil, nil
	}
	window, err := cfg.RateLimit.WindowDuration()
	if err != nil {
		return nil, fmt.Errorf("rate limit window: %w", err)
	}
	return ratelimit.FromRate(st, cfg.RateLimit.Requests, window), nil
}

func egressGuardFromConfig(cfg config.AirGap) (*egress.Guard, error) {
	return egress.NewGuard(egress.Config{
		Enabled:      cfg.Enabled,
		AllowPrivate: cfg.AllowPrivate,
		AllowHosts:   cfg.AllowHosts,
		AllowCIDRs:   cfg.AllowCIDRs,
	})
}

func telemetryReporterFromConfig(cfg config.Telemetry, st *store.Store, guard *egress.Guard) (*telemetry.Reporter, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	interval, err := cfg.IntervalDuration()
	if err != nil {
		return nil, fmt.Errorf("telemetry interval: %w", err)
	}
	instanceID, err := telemetry.LoadOrCreateInstanceID(cfg.InstanceIDFile)
	if err != nil {
		return nil, fmt.Errorf("telemetry instance id: %w", err)
	}
	var client *http.Client
	if guard != nil && guard.Enabled() {
		client = guard.Client(10 * time.Second)
	}
	return &telemetry.Reporter{
		Enabled:    true,
		Endpoint:   cfg.Endpoint,
		Interval:   interval,
		InstanceID: instanceID,
		Version:    buildinfo.Version(),
		Counter:    storeTelemetryCounter{store: st},
		Post:       telemetry.HTTPPoster(client),
	}, nil
}

func otlpExporterFromConfig(cfg config.OTLP, guard *egress.Guard) (*otlp.Exporter, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	timeout, err := cfg.TimeoutDuration()
	if err != nil {
		return nil, fmt.Errorf("otlp timeout: %w", err)
	}
	token := append([]byte(nil), cfg.Token...)
	if cfg.TokenFile != "" {
		data, err := os.ReadFile(cfg.TokenFile)
		if err != nil {
			return nil, fmt.Errorf("read otlp bearer token file: %w", err)
		}
		defer zeroBytes(data)
		token = append(token[:0], bytes.TrimSpace(data)...)
	}
	defer zeroBytes(token)
	var client *http.Client
	if guard != nil && guard.Enabled() {
		client = guard.Client(timeout)
	}
	exp, err := otlp.NewHTTPExporter(otlp.Config{
		Endpoint:    cfg.Endpoint,
		Token:       token,
		Insecure:    cfg.Insecure,
		ServiceName: cfg.ServiceName,
		Timeout:     timeout,
		QueueSize:   cfg.QueueSize,
		Client:      client,
	})
	if err != nil {
		return nil, err
	}
	return exp, nil
}

func notificationChannelsFromConfig(cfg config.Notifications) ([]notify.Notifier, error) {
	var channels []notify.Notifier
	if cfg.Slack.Enabled {
		channels = append(channels, slack.New(cfg.Slack.WebhookURL))
	}
	if cfg.Teams.Enabled {
		channels = append(channels, teams.New(cfg.Teams.WebhookURL))
	}
	if cfg.Email.Enabled {
		opts := []notifyemail.Option{}
		if cfg.Email.Username != "" {
			password, err := notificationSecret(cfg.Email.Password, cfg.Email.PasswordFile, "email password")
			if err != nil {
				return nil, err
			}
			defer zeroBytes(password)
			opts = append(opts, notifyemail.WithAuth(cfg.Email.Username, secrettext.String(bytes.TrimSpace(password))))
		}
		channels = append(channels, notifyemail.New(cfg.Email.SMTPAddr, cfg.Email.From, cfg.Email.To, opts...))
	}
	if cfg.SMS.Enabled {
		token, err := notificationSecret(cfg.SMS.Token, cfg.SMS.TokenFile, "sms token")
		if err != nil {
			return nil, err
		}
		defer zeroBytes(token)
		channels = append(channels, sms.New(cfg.SMS.Endpoint, cfg.SMS.From, cfg.SMS.To, token))
	}
	if cfg.SIEM.Enabled {
		token, err := notificationSecret(cfg.SIEM.Token, cfg.SIEM.TokenFile, "siem token")
		if err != nil {
			return nil, err
		}
		defer zeroBytes(token)
		opts := []siem.Option{}
		if cfg.SIEM.Source != "" {
			opts = append(opts, siem.WithSource(cfg.SIEM.Source))
		}
		channels = append(channels, siem.New(cfg.SIEM.Endpoint, token, opts...))
	}
	return channels, nil
}

func notificationSecret(inline []byte, file, label string) ([]byte, error) {
	out := append([]byte(nil), inline...)
	if file == "" {
		return bytes.TrimSpace(out), nil
	}
	data, err := os.ReadFile(file) // #nosec G304 -- operator-configured local file path from deployment config (CWE-22)
	if err != nil {
		return nil, fmt.Errorf("read notification %s file: %w", label, err)
	}
	defer zeroBytes(data)
	out = append(out[:0], bytes.TrimSpace(data)...)
	return out, nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// runRetentionAndLifecycleWindows is a named startup stage: it derives the
// audit-retention, privacy-retention, and lifecycle renew/alert windows from
// static configuration before any credential-owning constructor runs.
func runRetentionAndLifecycleWindows(cfg *config.Config) (retention time.Duration, privacyEnabled bool, privacyInterval time.Duration, privacyPolicy privacy.RetentionPolicy, renewBefore, alertBefore time.Duration, err error) {
	if retention, err = cfg.Audit.RetentionDuration(); err != nil {
		return 0, false, 0, privacyPolicy, 0, 0, fmt.Errorf("audit retention: %w", err)
	}
	if privacyEnabled, privacyInterval, privacyPolicy, err = privacyRetentionFromConfig(cfg.Privacy.Retention); err != nil {
		return 0, false, 0, privacyPolicy, 0, 0, err
	}
	if renewBefore, err = cfg.Lifecycle.RenewBeforeDuration(); err != nil {
		return 0, false, 0, privacyPolicy, 0, 0, fmt.Errorf("lifecycle renew before: %w", err)
	}
	if alertBefore, err = cfg.Lifecycle.AlertBeforeDuration(); err != nil {
		return 0, false, 0, privacyPolicy, 0, 0, fmt.Errorf("lifecycle alert before: %w", err)
	}
	notBeforeSkew, err := cfg.Lifecycle.NotBeforeSkewDuration()
	if err != nil {
		return 0, false, 0, privacyPolicy, 0, 0, fmt.Errorf("lifecycle not-before skew: %w", err)
	}
	if err := crypto.SetIssuanceBackdateSkew(notBeforeSkew); err != nil {
		return 0, false, 0, privacyPolicy, 0, 0, fmt.Errorf("lifecycle not-before skew: %w", err)
	}
	return retention, privacyEnabled, privacyInterval, privacyPolicy, renewBefore, alertBefore, nil
}

func privacyRetentionFromConfig(cfg config.PrivacyRetention) (bool, time.Duration, privacy.RetentionPolicy, error) {
	policy := privacy.DefaultRetentionPolicy()
	if !cfg.Enabled {
		return false, 0, policy, nil
	}
	interval, err := cfg.IntervalDuration()
	if err != nil {
		return false, 0, policy, fmt.Errorf("privacy retention interval: %w", err)
	}
	if interval <= 0 {
		interval = privacy.DefaultRetentionInterval
	}
	for _, f := range []struct {
		name  string
		value string
		set   func(time.Duration)
	}{
		{"owners", cfg.Owners, func(d time.Duration) { policy.OwnerInactiveAfter = d }},
		{"identities", cfg.Identities, func(d time.Duration) { policy.IdentityTerminalAfter = d }},
		{"certificates", cfg.Certificates, func(d time.Duration) { policy.CertificateTerminalAfter = d }},
		{"ssh_keys", cfg.SSHKeys, func(d time.Duration) { policy.SSHStaleAfter = d }},
		{"access", cfg.Access, func(d time.Duration) { policy.AccessTerminalAfter = d }},
		{"approvals", cfg.Approvals, func(d time.Duration) { policy.ApprovalActorAfter = d }},
		{"profiles", cfg.Profiles, func(d time.Duration) { policy.ProfileActorAfter = d }},
		{"attestations", cfg.Attestations, func(d time.Duration) { policy.AttestationEvidenceAfter = d }},
		{"agents", cfg.Agents, func(d time.Duration) { policy.AgentStaleAfter = d }},
	} {
		if f.value == "" {
			continue
		}
		d, err := time.ParseDuration(f.value)
		if err != nil {
			return false, 0, policy, fmt.Errorf("privacy retention %s: %w", f.name, err)
		}
		f.set(d)
	}
	return true, interval, policy.WithDefaults(), nil
}

func leafProfileFromConfig(cfg *config.Config) crypto.LeafProfile {
	return crypto.LeafProfile{
		CRLDistributionPoints: cfg.CA.CRLDistributionPoints,
		OCSPServers:           cfg.CA.OCSPServers,
		IssuingCertificateURL: cfg.CA.IssuerURLs,
		CertificatePolicyOIDs: cfg.CA.CertificatePolicyOIDs,
	}
}

func configureSnapshotCadence(srv *Server, cfg *config.Config) error {
	snapshotInterval, err := cfg.HA.SnapshotIntervalDuration()
	if err != nil {
		return fmt.Errorf("ha snapshot interval: %w", err)
	}
	srv.SetSnapshotInterval(snapshotInterval)
	return nil
}

type runtimeWorker struct {
	stop context.CancelFunc
	done chan struct{}
}

func startRuntimeWorker(parent context.Context, run func(context.Context)) runtimeWorker {
	ctx, stop := context.WithCancel(parent)
	done := make(chan struct{})
	go func() { defer close(done); run(ctx) }()
	return runtimeWorker{stop: stop, done: done}
}

func (w runtimeWorker) Stop() {
	w.stop()
	<-w.done
}

func leaderRuntimeWork(srv *Server) func(context.Context) {
	return func(workCtx context.Context) {
		workers := []runtimeWorker{
			startRuntimeWorker(workCtx, srv.RunDispatcher),
			startRuntimeWorker(workCtx, srv.RunRetention),
			startRuntimeWorker(workCtx, srv.RunPrivacyRetention),
			startRuntimeWorker(workCtx, srv.RunIdempotencyGC),
			startRuntimeWorker(workCtx, srv.RunOutboxGC),
			startRuntimeWorker(workCtx, srv.RunProjectionTail),
			startRuntimeWorker(workCtx, srv.RunFederation),
			startRuntimeWorker(workCtx, srv.RunOTLPAuditStream),
			startRuntimeWorker(workCtx, srv.RunTelemetry),
			startRuntimeWorker(workCtx, srv.RunDynamicLeaseWorker),
			startRuntimeWorker(workCtx, srv.RunPAMSessionExpiry),
			startRuntimeWorker(workCtx, srv.RunCRLScheduler),
			startRuntimeWorker(workCtx, srv.RunLifecycleScheduler),
			startRuntimeWorker(workCtx, srv.RunDiscoveryScheduler),
			startRuntimeWorker(workCtx, srv.RunSnapshotWorker),
			startRuntimeWorker(workCtx, srv.RunLicensedBackgroundWorkers),
		}
		<-workCtx.Done()
		for _, worker := range workers {
			worker.Stop()
		}
	}
}

func (s *Server) RunLicensedBackgroundWorkers(ctx context.Context) {
	if len(s.licensedBackgroundWorkers) == 0 {
		<-ctx.Done()
		return
	}
	workers := make([]runtimeWorker, 0, len(s.licensedBackgroundWorkers))
	for _, worker := range s.licensedBackgroundWorkers {
		w := worker
		workers = append(workers, startRuntimeWorker(ctx, func(workerCtx context.Context) {
			for workerCtx.Err() == nil {
				start := time.Now()
				err := w.Run(workerCtx)
				if workerCtx.Err() != nil {
					return
				}
				s.observeLicensedBackgroundWorker(w.Name(), start, err)
				if err != nil && s.logger != nil {
					s.logger.Error("licensed background worker stopped; restarting",
						slog.String("worker", w.Name()), slog.String("error", err.Error()))
				}
				select {
				case <-workerCtx.Done():
					return
				case <-time.After(time.Second):
				}
			}
		}))
	}
	<-ctx.Done()
	for _, worker := range workers {
		worker.Stop()
	}
}

func (s *Server) observeLicensedBackgroundWorker(name string, start time.Time, err error) {
	feature, action, ok := licensedWorkerTelemetry(name)
	if !ok || s.featureMetrics == nil {
		return
	}
	outcome := observ.OutcomeSuccess
	if err != nil {
		outcome = observ.OutcomeError
	}
	s.featureMetrics.Observe(feature, action, outcome, time.Since(start).Seconds())
}

func licensedWorkerTelemetry(name string) (feature, action string, ok bool) {
	switch name {
	case "pcas.checkpoints":
		return "pcas_checkpoint", "worker", true
	case "pcas.misissuance":
		return "pcas_monitor", "worker", true
	case "pcas.retirement":
		return "pcas_retirement", "worker", true
	default:
		return "", "", false
	}
}

func startBackgroundRuntime(ctx context.Context, cfg *config.Config, srv *Server, st *store.Store, logger *slog.Logger) (func(), error) {
	leaderCtx, stopLeader := context.WithCancel(ctx)
	leaderDone := make(chan struct{})
	if cfg.HA.LeaderElectionEnabled() {
		campaign, err := cfg.HA.LeaderCampaignIntervalDuration()
		if err != nil {
			stopLeader()
			return nil, fmt.Errorf("ha leader campaign interval: %w", err)
		}
		elector := leader.New(st, leaderRuntimeWork(srv), leader.WithLogger(logger), leader.WithInterval(campaign))
		go func() { defer close(leaderDone); elector.Run(leaderCtx) }()
		logger.Info("leader election enabled; continuous background workers run on the elected leader only (RESIL-004)")
	} else {
		go func() { defer close(leaderDone); leaderRuntimeWork(srv)(leaderCtx) }()
		logger.Info("leader election disabled; running continuous background workers on this single replica")
	}
	signerW := startRuntimeWorker(ctx, srv.RunSignerMonitor)
	fleetW := startRuntimeWorker(ctx, srv.RunAgentFleetMonitor)
	spiffeW := startRuntimeWorker(ctx, srv.RunSPIFFE)
	agentW := startRuntimeWorker(ctx, srv.RunAgentChannel)
	agentHTTPRenewalW := startRuntimeWorker(ctx, srv.RunAgentHTTPRenewal)
	kmipW := startRuntimeWorker(ctx, srv.RunKMIP)
	logMountedSurfaces(srv, logger)
	return func() {
		stopLeader()
		<-leaderDone
		signerW.Stop()
		fleetW.Stop()
		spiffeW.Stop()
		agentW.Stop()
		agentHTTPRenewalW.Stop()
		kmipW.Stop()
	}, nil
}

func logMountedSurfaces(srv *Server, logger *slog.Logger) {
	if served := srv.ServedProtocols(); len(served) > 0 {
		logger.Info("served issuance protocols mounted", slog.Any("protocols", served))
	}
	if addr := srv.AgentChannelAddr(); addr != "" {
		logger.Info("served agent steady-state mTLS gRPC channel mounted",
			slog.String("addr", addr), slog.Bool("agent_ca_in_signer", srv.OutOfProcessAgentCA()))
	}
	if addr := srv.AgentHTTPRenewalAddr(); addr != "" {
		logger.Info("served embedded-agent HTTP renewal mTLS listener mounted",
			slog.String("addr", addr), slog.Bool("agent_ca_in_signer", srv.OutOfProcessAgentCA()))
	}
	if addr := srv.KMIPAddr(); addr != "" {
		logger.Info("served KMIP mTLS listener mounted", slog.String("addr", addr))
	}
	if srv.apiAISurfaceServed() {
		logger.Info("served AI/RCA/NL-query/MCP surface mounted (read-only, tenant-scoped)")
	}
	for _, worker := range srv.licensedBackgroundWorkers {
		logger.Info("licensed background worker mounted", slog.String("worker", worker.Name()))
	}
}

func serveRuntime(ctx context.Context, cfg *config.Config, srv *Server, logger *slog.Logger, stopBackground func()) error {
	httpSrv := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	ln, err := net.Listen("tcp", cfg.Server.Addr)
	if err != nil {
		stopBackground()
		_ = srv.Shutdown(ctx)
		return fmt.Errorf("listen %s: %w", cfg.Server.Addr, err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- serveControlPlane(httpSrv, ln, cfg.Server.TLS, os.Stderr) }()
	select {
	case <-ctx.Done():
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			stopBackground()
			_ = srv.Shutdown(context.Background())
			return fmt.Errorf("serve: %w", err)
		}
	}
	logger.Info("control plane shutting down")
	stopBackground()
	shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutCtx)
	return srv.Shutdown(shutCtx)
}

// agentCACertFile resolves where the agent CA certificate is persisted (WIRE-004), so
// the agent CA (key in the signer) is stable across restarts. An unset config value
// defaults under the data directory, alongside the issuing CA cert.
func agentCACertFile(cfg *config.Config) string {
	if cfg.AgentChannel.CACertFile != "" {
		return cfg.AgentChannel.CACertFile
	}
	return "data/ca/agent-ca.crt"
}

// agentHeartbeatInterval resolves the agent channel's next-beat hint (already
// validated to parse), defaulting to zero (the server applies its own default) when
// unset.
func agentHeartbeatInterval(cfg *config.Config) time.Duration {
	d, _ := cfg.AgentChannel.HeartbeatIntervalDuration()
	return d
}

func siblingBinary(name string) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate executable: %w", err)
	}
	return filepath.Join(filepath.Dir(exe), name), nil
}

// openDatastore resolves the PostgreSQL datastore per config (R4.5). External mode
// connects to a deployed cluster by DSN. Bundled mode starts the embedded
// single-node Postgres for evaluation and returns a stop function (nil for
// external). An invalid mode fails fast — there is no default that silently cannot
// serve.
func openDatastore(pg config.Postgres, logger *slog.Logger) (dsn string, stop func() error, err error) {
	switch pg.Mode {
	case config.PostgresExternal:
		if pg.DSN == "" {
			return "", nil, errors.New("server: external Postgres requires a DSN (set TRSTCTL_POSTGRES_DSN), or use TRSTCTL_POSTGRES_MODE=bundled for single-node evaluation")
		}
		return pg.DSN, nil, nil
	case config.PostgresBundled:
		logger.Info("starting bundled single-node PostgreSQL for evaluation",
			slog.String("data_dir", pg.DataDir),
			slog.String("note", "production should run TRSTCTL_POSTGRES_MODE=external against a managed cluster"))
		dsn, stop, err := startBundledPostgres(pg)
		if err != nil {
			return "", nil, err
		}
		logger.Info("bundled PostgreSQL ready", slog.Int("port", bundledPort(pg)))
		return dsn, stop, nil
	default:
		return "", nil, fmt.Errorf("server: invalid postgres.mode %q (want %q or %q)", pg.Mode, config.PostgresExternal, config.PostgresBundled)
	}
}

// buildPluginConfig turns the operator's config.Plugins block into a server
// PluginConfig (EXC-WIRE-05; ARCH-007/SUPPLY-004): it reads each trusted Ed25519
// public-key PEM file and assembles the capability grant the loaded connector
// plugins run under. Disabled config yields the zero PluginConfig, leaving the
// served plugin surface off. It fails closed on an unreadable key file, so a
// misconfigured trust set is a startup error rather than a silently-unverified
// plugin path; the per-key PEM parse itself happens inside the plugin host when
// the trust policy is built.
func buildPluginConfig(p config.Plugins) (PluginConfig, error) {
	if !p.Enabled {
		return PluginConfig{}, nil
	}
	var keys [][]byte
	for _, f := range p.TrustedKeyFiles {
		pem, err := os.ReadFile(f) // #nosec G304 -- operator-configured local file path from deployment config (CWE-22)
		if err != nil {
			return PluginConfig{}, fmt.Errorf("read trusted plugin key %q: %w", f, err)
		}
		keys = append(keys, pem)
	}
	grant := pluginhost.NewGrant(toCapabilities(p.Capabilities)...)
	for _, prefix := range p.PathPrefixes {
		// Constrain both filesystem capabilities to the configured prefixes
		// (defense-in-depth; ignored for a capability that is not granted).
		grant = grant.WithPathPrefix(pluginhost.CapFSRead, prefix).WithPathPrefix(pluginhost.CapFSWrite, prefix)
	}
	return PluginConfig{
		Dir:              p.Dir,
		CADir:            p.CADir,
		DNSDir:           p.DNSDir,
		ConnectorDir:     p.ConnectorDir,
		TrustedKeyPEMs:   keys,
		PinnedDigestsHex: p.PinnedDigests,
		Grant:            grant,
		CAGrant:          grant,
		DNSGrant:         grant,
		ConnectorGrant:   grant,
	}, nil
}

// toCapabilities maps configured capability names to the plugin host's typed
// capabilities. Unknown names are dropped here (config.Validate already rejects
// them, so this never silently widens a grant).
func toCapabilities(names []string) []pluginhost.Capability {
	out := make([]pluginhost.Capability, 0, len(names))
	for _, n := range names {
		switch n {
		case "fs.read":
			out = append(out, pluginhost.CapFSRead)
		case "fs.write":
			out = append(out, pluginhost.CapFSWrite)
		case "net.dial":
			out = append(out, pluginhost.CapNetDial)
		case "process.exec":
			out = append(out, "process.exec") // connector.CapExec value
		}
	}
	return out
}

// parseMaintenanceWindows turns the configured specs into a window set.
//
// An empty configuration yields an empty set, which ALLOWS everything: an
// operator who configured no windows has not asked for a freeze, and defaulting
// to closed would turn an upgrade into a fleet-wide expiry event.
func parseMaintenanceWindows(specs []string) (lifecycle.WindowSet, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	out := make(lifecycle.WindowSet, 0, len(specs))
	for _, spec := range specs {
		w, err := lifecycle.ParseWindow(spec)
		if err != nil {
			return nil, fmt.Errorf("lifecycle.maintenance_windows %q: %w", spec, err)
		}
		out = append(out, w)
	}
	return out, nil
}
