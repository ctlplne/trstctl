package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"trustctl.io/trustctl/internal/api"
	"trustctl.io/trustctl/internal/audit"
	"trustctl.io/trustctl/internal/config"
	"trustctl.io/trustctl/internal/crypto"
	"trustctl.io/trustctl/internal/crypto/mtls"
	"trustctl.io/trustctl/internal/events"
	"trustctl.io/trustctl/internal/leader"
	"trustctl.io/trustctl/internal/logging"
	"trustctl.io/trustctl/internal/pluginhost"
	"trustctl.io/trustctl/internal/ratelimit"
	"trustctl.io/trustctl/internal/secrets"
	"trustctl.io/trustctl/internal/signing"
	"trustctl.io/trustctl/internal/store"
)

// Run opens the datastore and event log, supervises the signer as a child
// process (AN-4), assembles the control plane, and serves until ctx is
// cancelled — then shuts down in order (stop accepting → drain the outbox →
// close the event log and datastore). It is the production composition the
// trustctl binary calls.
func Run(ctx context.Context, cfg *config.Config) error {
	// Build the structured logger first (R2.2 / B6): it backs the request access log
	// and lifecycle events, and the bundled-datastore startup logs through it.
	logger, err := logging.New(logging.Options{Level: cfg.Log.Level, Format: cfg.Log.Format, Service: "trustctl"}, os.Stderr)
	if err != nil {
		return fmt.Errorf("build logger: %w", err)
	}

	// Resolve the datastore per config (R4.5): external connects to a managed
	// cluster by DSN; bundled starts the embedded single-node Postgres for
	// evaluation and is stopped on exit. The stop runs after the store closes
	// (deferred LIFO), so connections drain before the database stops.
	dsn, stopPG, err := openDatastore(cfg.Postgres, logger)
	if err != nil {
		return err
	}
	defer func() {
		if stopPG != nil {
			_ = stopPG()
		}
	}()

	st, err := store.Open(ctx, dsn)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	// Migration gate (R2.5): inspect the plan first. When migrations are pending
	// and automatic migration is disabled, fail fast with guidance instead of
	// migrating silently — the pre-migration backup gate. Migrate itself takes an
	// advisory lock, so concurrent instances cannot double-apply.
	pending, err := st.PendingMigrations(ctx)
	if err != nil {
		st.Close()
		return fmt.Errorf("inspect migrations: %w", err)
	}
	if len(pending) > 0 {
		if !cfg.Migrate.Auto {
			st.Close()
			return fmt.Errorf("%d pending database migration(s) and automatic migration is disabled (TRUSTCTL_MIGRATE_AUTO=false): take a backup (trustctl --backup), then apply them with 'trustctl --migrate'; pending: %v", len(pending), pending)
		}
		logger.Info("applying pending database migrations", "count", len(pending))
	}
	if err := st.Migrate(ctx); err != nil {
		st.Close()
		return fmt.Errorf("migrate: %w", err)
	}

	// Provision and validate the credential KEK (R3.1): create it (0600) on first
	// boot and fail fast on a malformed key, so credentials-at-rest is ready before
	// serving. When the served secrets surface is OFF (the default) it is held only
	// transiently here; when ON, it is RETAINED for the process lifetime so the served
	// secret store can seal/open values under it (envelope encryption at rest, AN-8),
	// and destroyed on shutdown.
	kek, err := secrets.LoadOrCreateKEK(cfg.Secrets.KEKFile)
	if err != nil {
		st.Close()
		return fmt.Errorf("provision credential KEK: %w", err)
	}
	var secretsKEK sealKeyWrapper
	if cfg.Secrets.EnableAPI {
		secretsKEK = kek    // retain for the served secret store
		defer kek.Destroy() // zeroize on shutdown
	} else {
		kek.Destroy() // not needed past validation
	}

	// When the served secrets surface is on, derive the machine-login HMAC key
	// (authmethod/F58): created (random, 0600) on first boot like the KEK, held as
	// []byte and never logged (AN-8). It is optional — an unset path leaves machine
	// login unconfigured while the secret store / share / pki sub-features still work.
	var secretsAuthSecret []byte
	if cfg.Secrets.EnableAPI && cfg.Secrets.AuthSecretFile != "" {
		secretsAuthSecret, err = secrets.LoadOrCreateAuthSecret(cfg.Secrets.AuthSecretFile)
		if err != nil {
			if secretsKEK != nil {
				kek.Destroy()
			}
			st.Close()
			return fmt.Errorf("provision machine-login secret: %w", err)
		}
	}

	log, err := events.Open(ctx, cfg.NATS)
	if err != nil {
		st.Close()
		return fmt.Errorf("open event log: %w", err)
	}

	// The signer is an isolated process (AN-4). In "child" mode the control plane
	// supervises it as a child (single binary), passing the sealed key store and
	// KEK so the issuing CA key persists and a restart preserves the CA (R3.2). In
	// "external" mode it connects to a separately deployed signer service — over a
	// co-located UDS, or, across nodes, a mutually-authenticated and mutually-pinned
	// mTLS channel (SIGNER-005, signer.mtls_address).
	var signer SignerProvider
	var signerClose func()
	switch cfg.Signer.Mode {
	case config.SignerExternal:
		var c *signing.Client
		var derr error
		if cfg.Signer.MTLSEnabled() {
			// Cross-node mTLS: dial the signer pod over TLS 1.3 mutual auth, pinning
			// its key both ways. Validate() guarantees the mTLS material is complete.
			c, derr = signing.DialReadyMTLS(ctx, cfg.Signer.MTLSAddress, mtls.SignerPeerConfig{
				CertFile:   cfg.Signer.MTLSCertFile,
				KeyFile:    cfg.Signer.MTLSKeyFile,
				PeerCAFile: cfg.Signer.MTLSPeerCAFile,
				PeerPinHex: cfg.Signer.MTLSPeerPin,
			}, cfg.Signer.MTLSServerName, 10*time.Second)
			if derr != nil {
				_ = log.Close()
				st.Close()
				return fmt.Errorf("connect external signer over mTLS at %s: %w", cfg.Signer.MTLSAddress, derr)
			}
		} else {
			c, derr = signing.DialReady(ctx, cfg.Signer.Socket, 10*time.Second)
			if derr != nil {
				_ = log.Close()
				st.Close()
				return fmt.Errorf("connect external signer at %s: %w", cfg.Signer.Socket, derr)
			}
		}
		signer = signing.StaticProvider{C: c}
		signerClose = func() { _ = c.Close() }
	default: // child
		signerBin, berr := siblingBinary("trustctl-signer")
		if berr != nil {
			_ = log.Close()
			st.Close()
			return berr
		}
		socket := cfg.Signer.Socket
		if socket == "" {
			socket = filepath.Join(os.TempDir(), "trustctl-signer.sock")
		}
		sup, serr := signing.Supervise(ctx, signerBin, socket, "--keystore", cfg.Signer.KeyStoreDir, "--kek", cfg.Secrets.KEKFile)
		if serr != nil {
			_ = log.Close()
			st.Close()
			return fmt.Errorf("start signer: %w", serr)
		}
		signer = sup
		signerClose = sup.Close
	}
	defer signerClose()

	// Load (or create) the persistent audit export key so the audit subsystem is
	// wired into the serving path and signed evidence bundles verify across
	// restarts (R2.1 / B5).
	auditKey, err := audit.LoadOrCreateSigningKey(cfg.Audit.SigningKeyFile, "audit-export")
	if err != nil {
		_ = log.Close()
		st.Close()
		return fmt.Errorf("audit signing key: %w", err)
	}

	// Build the per-tenant rate limiter from config (R2.3). Disabled config leaves
	// it nil (no limiting); the bulkheads default inside Build (always on, AN-7).
	var rateLimiter api.RateLimiter
	if cfg.RateLimit.Enabled {
		window, werr := cfg.RateLimit.WindowDuration()
		if werr != nil {
			_ = log.Close()
			st.Close()
			return fmt.Errorf("rate limit window: %w", werr)
		}
		rateLimiter = ratelimit.FromRate(st, cfg.RateLimit.Requests, window)
	}

	// Parse the audit retention window (R4.4). Empty means indefinite (the worker
	// stays off); a positive window plus an archive directory enables it.
	retention, err := cfg.Audit.RetentionDuration()
	if err != nil {
		_ = log.Close()
		st.Close()
		return fmt.Errorf("audit retention: %w", err)
	}

	// The served-leaf issuance profile (PKIGOV-001): CDP/AIA/policy pointers from
	// config are stamped on every leaf the served path mints (the SKI is always
	// set inside the crypto boundary). DefaultProfile, when set, binds the served
	// mint to a tenant profile and rejects out-of-profile requests (PKIGOV-002).
	leafProfile := crypto.LeafProfile{
		CRLDistributionPoints: cfg.CA.CRLDistributionPoints,
		OCSPServers:           cfg.CA.OCSPServers,
		IssuingCertificateURL: cfg.CA.IssuerURLs,
		CertificatePolicyOIDs: cfg.CA.CertificatePolicyOIDs,
	}

	// Resolve the served plugin surface (EXC-WIRE-05): read the trusted-key PEM files
	// and assemble the capability grant from config, so an unreadable key fails closed
	// here rather than at first deploy. Disabled config yields the zero PluginConfig
	// (the surface stays off).
	pluginCfg, err := buildPluginConfig(cfg.Plugins)
	if err != nil {
		_ = log.Close()
		st.Close()
		return fmt.Errorf("plugins: %w", err)
	}

	srv, err := Build(ctx, Deps{Store: st, Log: log, Signer: signer, CACertFile: cfg.CA.CertFile,
		LeafProfile: leafProfile, DefaultProfile: cfg.CA.DefaultProfile,
		// EXC-WIRE-03: wire the served policy / RA-separation / dual-control gate onto
		// the mutating issue/deploy/revoke path from config (closes SEC-002/SEC-005/
		// CORRECT-003; the served half of RED-004). Off by default so an upgrade does
		// not silently start denying; the RA scope split is always enforced.
		PolicyModule:      cfg.CA.Policy.Module,
		EnablePolicyGate:  cfg.CA.Policy.Enabled,
		RequireApproval:   cfg.CA.Policy.RequireApproval,
		RequiredApprovals: cfg.CA.Policy.RequiredApprovals,
		AuditSigningKey:   auditKey, AuditRetention: retention, AuditArchiveDir: cfg.Audit.ArchiveDir,
		Logger: logger, RateLimiter: rateLimiter,
		// Web hardening (SEC-003/WIRE-005): emit HSTS only when the control plane is
		// served over TLS (internal or file mode), and apply the operator's CORS
		// allow-list (empty = same-origin only).
		SecurityHeaders: SecurityHeaders{
			TLS:            cfg.Server.TLS.Mode != config.TLSDisabled,
			AllowedOrigins: cfg.Server.CORSAllowedOrigins,
		},
		// Served issuance protocols (EXC-WIRE-02): mount the enabled RFC protocol
		// servers (ACME/EST/SCEP/CMP/SPIFFE/SSH) on the running binary, each minting
		// through the signer-backed, tenant-scoped, event-sourced, idempotent issuance
		// path. A protocol with no configured tenant fails closed at issuance (it must
		// not mint into a blank tenant — AN-1). They are served only when an issuing CA
		// is provisioned.
		Protocols: cfg.Protocols,
		// Served WASM-plugin surface (EXC-WIRE-05; ARCH-007/SUPPLY-004): when
		// plugins.enabled, the running binary loads operator-supplied connector plugins
		// from plugins.dir and PROVENANCE-VERIFIES each against the trusted Ed25519 keys
		// before it will instantiate one — an unsigned/wrong-key/tampered/unpinned module
		// makes Build fail closed. A verified plugin is then run capability-sandboxed on
		// the served connector.deploy path. Disabled (the default) leaves the deploy path
		// acknowledging unrouted, as before. buildPluginConfig reads the key files now so
		// a missing/garbled key fails closed at startup, not first deploy.
		Plugins: pluginCfg,
		// Served OIDC browser login + session + per-user → tenant mapping (EXC-WIRE-01):
		// when auth.oidc.enabled, the running binary serves /auth/login, /auth/callback,
		// /auth/me, /auth/logout and a session cookie authorizes API calls under the same
		// RBAC + RLS tenant scoping as an API token (closes SEC-001/WIRE-001/SURFACE-002/
		// TENANT-004). Cookies are Secure whenever the control plane serves TLS. Disabled
		// (the default) keeps token-only auth; enabled-but-misconfigured fails closed in
		// Build.
		OIDC: cfg.Auth.OIDC,
		// Served secrets/identity surface (GAP-006): when secrets.enable_api is on, the
		// running binary mounts the secret store (CRUD + rotation), one-time secret
		// sharing, the dynamic PKI secret, and machine login under /api/v1/secrets/*,
		// sealing stored values under the retained KEK (AN-8). Off by default (fail
		// closed). The machine-login HMAC key is wired from secrets.auth_secret_file when
		// set. Build fails closed if enabled without a KEK.
		EnableSecretsAPI: cfg.Secrets.EnableAPI, KEK: secretsKEK, SecretsAuthSecret: secretsAuthSecret,
		// Served AI / RCA / NL-query / MCP surface (SURFACE-003): when ai.enable_api is
		// on, the running binary mounts the tenant-scoped, read-only, rate-limited
		// AI/RCA/NL-query answerer and MCP tool server under /api/v1/ai/* and
		// /api/v1/mcp/*. Off by default (fail closed). The AI MODEL is air-gapped/opt-in:
		// aiModelFromConfig returns the no-model adapter today (grounding + citations work,
		// nothing phones home); when an operator opts into a provider, every prompt still
		// crosses the boundary redactor + residual-entropy refuse-gate (AN-8).
		EnableAISurface: cfg.AI.EnableAPI, AIModel: aiModelFromConfig(),
		AIMCPIdentity: cfg.AI.MCPIdentity, AIRateMax: cfg.AI.RateMax, AIRateWindow: cfg.AI.RateWindow()})
	if err != nil {
		_ = log.Close()
		st.Close()
		return err
	}
	logger.Info("control plane assembled",
		slog.String("addr", cfg.Server.Addr), slog.String("tls_mode", cfg.Server.TLS.Mode))

	// Resolve the read-model snapshot cadence (SPINE-007 / EXC-SCALE-01) before
	// starting the leader-only workers; a malformed value was rejected by Validate.
	snapshotInterval, err := cfg.HA.SnapshotIntervalDuration()
	if err != nil {
		_ = log.Close()
		st.Close()
		return fmt.Errorf("ha snapshot interval: %w", err)
	}
	srv.SetSnapshotInterval(snapshotInterval)

	// ---- Leader-only continuous workers (RESIL-004 / EXC-RESIL-01) ----
	//
	// These workers MUTATE shared state (the read model, the outbox, the hot log, the
	// CRL, the read-model snapshots) on a continuous cadence. On a multi-replica
	// deployment they must run on exactly ONE replica or N replicas would double-apply
	// — the projector tailer in particular has no other coordination once it is past
	// the boot catch-up's advisory lock. leaderWork starts them together under a
	// leadership-scoped context and stops+waits for them when that context is cancelled
	// (leadership lost or shutdown), so a follower can take over cleanly. The set:
	//   - the outbox dispatcher (AN-6): external effects happen while live, not only at
	//     shutdown. (Its own claims are FOR UPDATE SKIP LOCKED, but only the leader runs
	//     the sweep so a saturated pool on one replica cannot duplicate work.)
	//   - the audit retention worker (R4.4): archive-then-prune the hot log.
	//   - the idempotency-key GC (SPINE-002) and the outbox delivered-row purge
	//     (SPINE-003): keep those tables (and their backups) bounded.
	//   - the projection tailer (SPINE-009): apply out-of-band events + the lag gauge.
	//   - the CRL freshness scheduler (EXC-REVOKE-01): keep the served CRL fresh.
	//   - the read-model snapshot worker (SPINE-007): periodic snapshots for fast boot.
	leaderWork := func(workCtx context.Context) {
		dispCtx, stopDispatcher := context.WithCancel(workCtx)
		dispatcherDone := make(chan struct{})
		go func() { defer close(dispatcherDone); srv.RunDispatcher(dispCtx) }()

		retCtx, stopRetention := context.WithCancel(workCtx)
		retentionDone := make(chan struct{})
		go func() { defer close(retentionDone); srv.RunRetention(retCtx) }()

		idemCtx, stopIdemGC := context.WithCancel(workCtx)
		idemGCDone := make(chan struct{})
		go func() { defer close(idemGCDone); srv.RunIdempotencyGC(idemCtx) }()

		outboxGCCtx, stopOutboxGC := context.WithCancel(workCtx)
		outboxGCDone := make(chan struct{})
		go func() { defer close(outboxGCDone); srv.RunOutboxGC(outboxGCCtx) }()

		tailCtx, stopTail := context.WithCancel(workCtx)
		tailDone := make(chan struct{})
		go func() { defer close(tailDone); srv.RunProjectionTail(tailCtx) }()

		crlCtx, stopCRL := context.WithCancel(workCtx)
		crlDone := make(chan struct{})
		go func() { defer close(crlDone); srv.RunCRLScheduler(crlCtx) }()

		snapCtx, stopSnap := context.WithCancel(workCtx)
		snapDone := make(chan struct{})
		go func() { defer close(snapDone); srv.RunSnapshotWorker(snapCtx) }()

		<-workCtx.Done()
		// Stop the dispatcher first so the rest of the drain/teardown never races it on
		// an outbox row, then the others; wait for each so leadership is fully quiesced
		// before this replica relinquishes the lock (no two leaders' workers overlap).
		stopDispatcher()
		<-dispatcherDone
		stopRetention()
		<-retentionDone
		stopIdemGC()
		<-idemGCDone
		stopOutboxGC()
		<-outboxGCDone
		stopTail()
		<-tailDone
		stopCRL()
		<-crlDone
		stopSnap()
		<-snapDone
	}

	// Start the leader-only workers, gated by leadership when leader election is on
	// (the default). With it on, the leader.Elector campaigns for the PostgreSQL
	// advisory-lock leadership and runs leaderWork only while this replica is the
	// leader, stepping down (and stopping the workers) on lock loss so a follower takes
	// over — so >1 replica is safe (RESIL-004). With it off (an operator running
	// exactly one replica who wants to skip the lock), leaderWork runs unconditionally,
	// preserving the prior single-replica behavior.
	leaderCtx, stopLeader := context.WithCancel(ctx)
	leaderDone := make(chan struct{})
	if cfg.HA.LeaderElectionEnabled() {
		campaign, cerr := cfg.HA.LeaderCampaignIntervalDuration()
		if cerr != nil { // already validated; defensive
			stopLeader()
			_ = log.Close()
			st.Close()
			return fmt.Errorf("ha leader campaign interval: %w", cerr)
		}
		elector := leader.New(st, leaderWork, leader.WithLogger(logger), leader.WithInterval(campaign))
		go func() { defer close(leaderDone); elector.Run(leaderCtx) }()
		logger.Info("leader election enabled; continuous background workers run on the elected leader only (RESIL-004)")
	} else {
		go func() { defer close(leaderDone); leaderWork(leaderCtx) }()
		logger.Info("leader election disabled; running continuous background workers on this single replica")
	}

	// Sample the out-of-process signer's health/restarts into the metrics registry on
	// a fixed cadence (SF.3). This is LOCAL telemetry — each replica supervises its own
	// signer — so it runs on every replica, not just the leader.
	sigCtx, stopSigner := context.WithCancel(ctx)
	signerDone := make(chan struct{})
	go func() { defer close(signerDone); srv.RunSignerMonitor(sigCtx) }()

	// Serve the SPIFFE Workload API over its UDS (EXC-WIRE-02 / INTEROP-004): a stock
	// go-spiffe / spiffe-helper / Envoy SDS client dials the socket to FetchX509SVID,
	// signed through the out-of-process signer (AN-4). Issuance is per-replica (each
	// replica has its own signer client), so this runs on every replica that serves
	// protocols, not only the leader. A no-op unless protocols.spiffe is enabled and an
	// issuing CA is provisioned. Stopped with the other workers.
	spiffeCtx, stopSPIFFE := context.WithCancel(ctx)
	spiffeDone := make(chan struct{})
	go func() { defer close(spiffeDone); srv.RunSPIFFE(spiffeCtx) }()
	if served := srv.ServedProtocols(); len(served) > 0 {
		logger.Info("served issuance protocols mounted", slog.Any("protocols", served))
	}
	// SURFACE-003: log when the AI/RCA/NL-query/MCP surface is served (read-only,
	// tenant-scoped, rate-limited). The model stays air-gapped/opt-in regardless.
	if srv.apiAISurfaceServed() {
		logger.Info("served AI/RCA/NL-query/MCP surface mounted (read-only, tenant-scoped, air-gapped model by default)")
	}

	// stopBackground halts the background workers and waits for them to exit, so the
	// final drain in Shutdown owns the outbox exclusively and no worker is mid-run
	// when the event log closes. Stopping the leader first quiesces the leader-only
	// workers (incl. the dispatcher) and releases the leadership lock before the drain.
	stopBackground := func() {
		stopLeader()
		<-leaderDone
		stopSigner()
		<-signerDone
		stopSPIFFE()
		<-spiffeDone
	}

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

	// Graceful shutdown: stop accepting connections, stop the dispatcher, then
	// drain + close in order. Stopping the dispatcher first means Shutdown's final
	// drain has exclusive ownership of the outbox.
	logger.Info("control plane shutting down")
	stopBackground()
	shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutCtx)
	return srv.Shutdown(shutCtx)
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
			return "", nil, errors.New("server: external Postgres requires a DSN (set TRUSTCTL_POSTGRES_DSN), or use TRUSTCTL_POSTGRES_MODE=bundled for single-node evaluation")
		}
		return pg.DSN, nil, nil
	case config.PostgresBundled:
		logger.Info("starting bundled single-node PostgreSQL for evaluation",
			slog.String("data_dir", pg.DataDir),
			slog.String("note", "production should run TRUSTCTL_POSTGRES_MODE=external against a managed cluster"))
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
		TrustedKeyPEMs:   keys,
		PinnedDigestsHex: p.PinnedDigests,
		Grant:            grant,
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
