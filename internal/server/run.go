package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/buildinfo"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
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
	"trstctl.com/trstctl/internal/pluginhost"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/ratelimit"
	"trstctl.com/trstctl/internal/secrets"
	"trstctl.com/trstctl/internal/secrettext"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/telemetry"
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

	st, stopPG, err := openMigratedStore(ctx, cfg, logger)
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

	log, err := events.Open(ctx, cfg.NATS)
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

	deps, err := buildRunDeps(ctx, cfg, st, log, runSigner, runSecrets, logger, egressGuard)
	if err != nil {
		return err
	}
	deps.License = lic
	for _, attach := range attachers {
		if attach == nil {
			continue
		}
		if err := attach(ctx, cfg, logger, lic, &deps); err != nil {
			return err
		}
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

func openMigratedStore(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*store.Store, func() error, error) {
	dsn, stopPG, err := openDatastore(cfg.Postgres, logger)
	if err != nil {
		return nil, nil, err
	}
	st, err := store.Open(ctx, dsn)
	if err != nil {
		if stopPG != nil {
			_ = stopPG()
		}
		return nil, nil, fmt.Errorf("open store: %w", err)
	}
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

func startChildSigner(ctx context.Context, cfg *config.Config) (SignerProvider, func(), error) {
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
	if cfg.Signer.AllowInsecureDevNonLinux {
		args = append(args, "--allow-insecure-dev-nonlinux")
	}
	sup, err := signing.Supervise(ctx, signerBin, socket, args...)
	if err != nil {
		return nil, nil, fmt.Errorf("start signer: %w", err)
	}
	return sup, sup.Close, nil
}

func buildRunDeps(ctx context.Context, cfg *config.Config, st *store.Store, log *events.Log, signer runSigner, sec runSecrets, logger *slog.Logger, egressGuard *egress.Guard) (Deps, error) {
	auditKey, err := audit.LoadOrCreateSigningKey(cfg.Audit.SigningKeyFile, "audit-export")
	if err != nil {
		return Deps{}, fmt.Errorf("audit signing key: %w", err)
	}
	rateLimiter, err := buildRateLimiter(cfg, st)
	if err != nil {
		return Deps{}, err
	}
	retention, err := cfg.Audit.RetentionDuration()
	if err != nil {
		return Deps{}, fmt.Errorf("audit retention: %w", err)
	}
	privacyRetentionEnabled, privacyRetentionInterval, privacyRetentionPolicy, err := privacyRetentionFromConfig(cfg.Privacy.Retention)
	if err != nil {
		return Deps{}, err
	}
	renewBefore, err := cfg.Lifecycle.RenewBeforeDuration()
	if err != nil {
		return Deps{}, fmt.Errorf("lifecycle renew before: %w", err)
	}
	alertBefore, err := cfg.Lifecycle.AlertBeforeDuration()
	if err != nil {
		return Deps{}, fmt.Errorf("lifecycle alert before: %w", err)
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
	breakglassCACertDER, breakglassPublicKeyDER, err := breakglassVerifierMaterialFromConfig(cfg.Breakglass)
	if err != nil {
		return Deps{}, fmt.Errorf("break-glass verifier material: %w", err)
	}
	notificationChannels, err := notificationChannelsFromConfig(cfg.Notifications)
	if err != nil {
		return Deps{}, fmt.Errorf("notifications: %w", err)
	}
	telemetryReporter, err := telemetryReporterFromConfig(cfg.Telemetry, st, egressGuard)
	if err != nil {
		return Deps{}, fmt.Errorf("telemetry: %w", err)
	}
	otlpExporter, err := otlpExporterFromConfig(cfg.OTLP, egressGuard)
	if err != nil {
		return Deps{}, err
	}
	return Deps{
		Store: st, Log: log, Signer: signer.signer, SignTokenProvider: signer.tokenProvider,
		EgressGuard:               egressGuard,
		ServiceNowBindings:        serviceNowBindingsFromConfig(cfg.ITSM.ServiceNow),
		OutboundEnvCredentialRefs: append([]string(nil), cfg.OutboundEnvCredentialRefs...),
		TelemetryReporter:         telemetryReporter,
		CACertFile:                cfg.CA.CertFile, LeafProfile: leafProfileFromConfig(cfg), DefaultProfile: cfg.CA.DefaultProfile,
		PolicyModule: cfg.CA.Policy.Module, EnablePolicyGate: cfg.CA.Policy.Enabled,
		ABACModule: cfg.Auth.ABAC.Module, EnableABAC: cfg.Auth.ABAC.Enabled, ABACEnvironment: cfg.Auth.ABAC.Environment,
		BreakglassCACertDER: breakglassCACertDER, BreakglassPublicKeyDER: breakglassPublicKeyDER,
		RequireApproval: cfg.CA.Policy.RequireApproval, RequiredApprovals: cfg.CA.Policy.RequiredApprovals,
		AuditSigningKey: auditKey, AuditRetention: retention, AuditArchiveDir: cfg.Audit.ArchiveDir,
		PrivacyRetentionEnabled: privacyRetentionEnabled, PrivacyRetentionInterval: privacyRetentionInterval,
		PrivacyRetentionPolicy: privacyRetentionPolicy,
		LifecycleRenewBefore:   renewBefore,
		LifecycleAlertBefore:   alertBefore,
		NotificationChannels:   notificationChannels,
		Logger:                 logger, RateLimiter: rateLimiter,
		OTLPExporter:    otlpExporter,
		Bulkhead:        bulkhead.NewSet(cfg.Bulkheads.Configs()...),
		SecurityHeaders: SecurityHeaders{TLS: cfg.Server.TLS.Mode != config.TLSDisabled, AllowedOrigins: cfg.Server.CORSAllowedOrigins},
		Protocols:       cfg.Protocols, Plugins: pluginCfg,
		OIDC: cfg.Auth.OIDC, SAML: cfg.Auth.SAML, LDAP: cfg.Auth.LDAP, SCIM: cfg.Auth.SCIM,
		EnableSecretsAPI: cfg.Secrets.EnableAPI, KEK: sec.kek, SecretsAuthSecret: sec.authSecret, MachineAuthMethods: machineAuthMethods,
		SecretScanGitleaksBin: cfg.Secrets.GitleaksBin,
		EnableAISurface:       cfg.AI.EnableAPI, AIModel: aiModel, AIModelStatus: aiModelStatus,
		AIMCPIdentity: cfg.AI.MCPIdentity, EnableMCPWriteTools: cfg.AI.MCPWriteTools, AIRateMax: cfg.AI.RateMax, AIRateWindow: cfg.AI.RateWindow(),
		EnableAgentChannel: cfg.AgentChannel.Enabled, AgentChannelAddr: cfg.AgentChannel.Addr,
		AgentCACertFile: agentCACertFile(cfg), AgentHeartbeatInterval: agentHeartbeatInterval(cfg),
		AgentChannelServerName: cfg.AgentChannel.ServerName,
	}, nil
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

func otlpExporterFromConfig(cfg config.OTLP, guard *egress.Guard) (*observ.OTLPExporter, error) {
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
	exp, err := observ.NewOTLPHTTPExporter(observ.OTLPConfig{
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
	data, err := os.ReadFile(file)
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
			startRuntimeWorker(workCtx, srv.RunSnapshotWorker),
		}
		<-workCtx.Done()
		for _, worker := range workers {
			worker.Stop()
		}
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
	kmipW := startRuntimeWorker(ctx, srv.RunKMIP)
	logMountedSurfaces(srv, logger)
	return func() {
		stopLeader()
		<-leaderDone
		signerW.Stop()
		fleetW.Stop()
		spiffeW.Stop()
		agentW.Stop()
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
	if addr := srv.KMIPAddr(); addr != "" {
		logger.Info("served KMIP mTLS listener mounted", slog.String("addr", addr))
	}
	if srv.apiAISurfaceServed() {
		logger.Info("served AI/RCA/NL-query/MCP surface mounted (read-only, tenant-scoped)")
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
		pem, err := os.ReadFile(f)
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
		ConnectorDir:     p.ConnectorDir,
		TrustedKeyPEMs:   keys,
		PinnedDigestsHex: p.PinnedDigests,
		Grant:            grant,
		CAGrant:          grant,
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
