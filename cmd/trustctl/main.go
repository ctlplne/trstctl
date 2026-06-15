// Command trustctl is the trustctl control-plane binary.
//
// It assembles and serves the control plane via server.Run (internal/server):
// the event spine, projections, orchestrator, and REST API, with the isolated
// signing service supervised as a separate out-of-process child in single-node
// mode (AN-4). It reports its version via --version, resolves and validates its
// configuration — including the bundled-vs-external Postgres/NATS switches used by
// the container image and Compose stack (S7.4) — prints it with --check-config,
// exposes the operational flags (--migrate / --migrate-status, --backup /
// --restore, --health-check), and shuts down cleanly on SIGINT/SIGTERM.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"trustctl.io/trustctl/internal/buildinfo"
	"trustctl.io/trustctl/internal/config"
	"trustctl.io/trustctl/internal/crypto/mtls"
	"trustctl.io/trustctl/internal/server"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "trustctl: %v\n", err)
		os.Exit(1)
	}
}

// run is the testable program entry point. It parses args, resolves the
// effective configuration from getenv (injected for testability), and then
// either prints version/config information and returns, or boots the control
// plane and blocks until ctx is cancelled (as it is on SIGINT/SIGTERM), then
// returns nil to signal a clean shutdown. A misconfiguration is returned as an
// error before the control plane boots, so a bad deployment fails fast rather
// than starting half-configured.
func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	// Admin subcommands are positional verbs (e.g. `trustctl token create`), handled
	// before the top-level flag parsing so they can carry their own flag set. The
	// token bootstrap (WIRE-002) is the first-run on-ramp: it mints the first
	// tenant-scoped API token directly against the datastore, needing no existing
	// credential and no network trust.
	if len(args) > 0 && args[0] == "token" {
		return runToken(ctx, args[1:], getenv, stdout, stderr)
	}

	fs := flag.NewFlagSet("trustctl", flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print version information and exit")
	checkConfig := fs.Bool("check-config", false, "resolve and print the effective configuration, then exit")
	healthCheck := fs.Bool("health-check", false, "probe the local control plane's /healthz and exit 0/1 (container health check)")
	backupPath := fs.String("backup", "", "back up the event log (source of truth) to FILE, then exit")
	restorePath := fs.String("restore", "", "restore the event log from FILE, rebuild the read model, then exit")
	rebuild := fs.Bool("rebuild", false, "atomically rebuild the read model from the existing event log, then exit (DR recovery)")
	migrateStatus := fs.Bool("migrate-status", false, "list pending database migrations (the dry-run plan), then exit")
	migrate := fs.Bool("migrate", false, "apply pending database migrations under an advisory lock, then exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			// -h/--help already printed usage to stderr; this is a clean exit.
			return nil
		}
		return err
	}

	if *showVersion {
		_, _ = fmt.Fprintln(stdout, buildinfo.String("trustctl"))
		return nil
	}

	cfg, err := config.Load(getenv)
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}

	if *checkConfig {
		_, _ = io.WriteString(stdout, configSummary(cfg))
		return nil
	}
	if *healthCheck {
		return healthProbe(cfg)
	}
	if *backupPath != "" {
		n, err := server.RunBackup(ctx, cfg, *backupPath)
		if err != nil {
			return fmt.Errorf("backup: %w", err)
		}
		_, _ = fmt.Fprintf(stdout, "backed up %d events to %s\n", n, *backupPath)
		return nil
	}
	if *restorePath != "" {
		n, err := server.RunRestore(ctx, cfg, *restorePath)
		if err != nil {
			return fmt.Errorf("restore: %w", err)
		}
		_, _ = fmt.Fprintf(stdout, "restored %d events from %s and rebuilt the read model\n", n, *restorePath)
		return nil
	}
	if *rebuild {
		// Atomically re-derive the read model from the event log already present
		// (RESIL-003): the truncate + replay run in one transaction, so an interrupted
		// rebuild rolls back to the prior read model rather than leaving a partial
		// inventory. This is the failed-restore / divergence recovery — it does not
		// require an empty event store the way --restore does.
		n, err := server.RunRebuild(ctx, cfg)
		if err != nil {
			return fmt.Errorf("rebuild: %w", err)
		}
		_, _ = fmt.Fprintf(stdout, "rebuilt the read model from %d events in the log\n", n)
		return nil
	}
	if *migrateStatus {
		pending, err := server.MigrateStatus(ctx, cfg)
		if err != nil {
			return fmt.Errorf("migrate-status: %w", err)
		}
		if len(pending) == 0 {
			_, _ = fmt.Fprintln(stdout, "no pending migrations")
			return nil
		}
		_, _ = fmt.Fprintf(stdout, "%d pending migration(s):\n", len(pending))
		for _, p := range pending {
			_, _ = fmt.Fprintf(stdout, "  %s\n", p)
		}
		return nil
	}
	if *migrate {
		n, err := server.RunMigrate(ctx, cfg)
		if err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
		_, _ = fmt.Fprintf(stdout, "applied %d migration(s)\n", n)
		return nil
	}

	// Assemble and serve the control plane (S7.7). Run starts the event log,
	// projections, orchestrator, and API in order, supervises the signer as a
	// child process (AN-4), serves until ctx is cancelled, and then shuts down
	// gracefully (drain the outbox, close connections in order).
	_, _ = fmt.Fprintf(stderr, "starting %s\n", buildinfo.String("trustctl"))
	_, _ = io.WriteString(stderr, configSummary(cfg))
	if err := server.Run(ctx, cfg); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(stderr, "trustctl stopped cleanly")
	return nil
}

// runToken dispatches the `trustctl token ...` admin subcommands. Today it serves
// `token create`, the network-trust-free first-run bootstrap (WIRE-002) that mints
// the first tenant-scoped API token so a freshly deployed binary — which fails
// closed (401) until a credential exists and has no OIDC login wired yet — has an
// obtainable credential. It writes through the same store path the API
// authenticates against (store.CreateAPIToken) and never requires an existing
// credential.
func runToken(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "create" {
		return errors.New("usage: trustctl token create --tenant <uuid> [--subject <name>] [--scopes a,b,c] [--tenant-name <label>]")
	}

	fs := flag.NewFlagSet("trustctl token create", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tenant := fs.String("tenant", "", "tenant id (UUID) the token is scoped to (required); registered via the event log if new")
	tenantName := fs.String("tenant-name", "default", "human label recorded for a freshly registered tenant")
	subject := fs.String("subject", "bootstrap-admin", "the token's principal subject (who it acts as)")
	scopesCSV := fs.String("scopes", "", "comma-separated permission scopes; default is full operator control EXCLUDING certs:issue")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *tenant == "" {
		return errors.New("token create: --tenant <uuid> is required (the tenant the token is scoped to; a single-tenant deployment picks one well-known id)")
	}

	cfg, err := config.Load(getenv)
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}

	var scopes []string
	if s := strings.TrimSpace(*scopesCSV); s != "" {
		for _, p := range strings.Split(s, ",") {
			if p = strings.TrimSpace(p); p != "" {
				scopes = append(scopes, p)
			}
		}
	}

	raw, err := server.RunTokenCreate(ctx, cfg, server.TokenCreateOptions{
		TenantID:   *tenant,
		TenantName: *tenantName,
		Subject:    *subject,
		Scopes:     scopes,
	})
	if err != nil {
		return fmt.Errorf("token create: %w", err)
	}

	// The raw token is printed ONCE, to stdout only, so it can be captured by a
	// pipe; it is never logged or stored (only its hash is persisted). Operator
	// guidance goes to stderr so `... | read TOKEN` gets the bare secret.
	_, _ = fmt.Fprintf(stderr, "Created a tenant-scoped API token for tenant %s (subject %q).\n", *tenant, *subject)
	_, _ = fmt.Fprintln(stderr, "Store it now — it is shown only once and cannot be recovered. Use it as: Authorization: Bearer <token>")
	_, _ = fmt.Fprintln(stdout, raw)
	return nil
}

// healthProbe makes a GET to the local control plane's /healthz and returns nil
// only on a 2xx. It is what the container health check execs (distroless has no
// shell or curl). It matches the server's transport: HTTPS for the TLS modes
// (over a loopback liveness client that does not verify the ephemeral internal
// certificate), plaintext only when TLS is explicitly disabled.
func healthProbe(cfg *config.Config) error {
	host := cfg.Server.Addr
	if strings.HasPrefix(host, ":") {
		host = "127.0.0.1" + host
	}
	scheme := "https"
	client := mtls.LoopbackProbeClient(3 * time.Second)
	if cfg.Server.TLS.Mode == config.TLSDisabled {
		scheme = "http"
		client = &http.Client{Timeout: 3 * time.Second}
	}
	resp, err := client.Get(scheme + "://" + host + "/healthz")
	if err != nil {
		return fmt.Errorf("health check: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("health check: status %d", resp.StatusCode)
	}
	return nil
}

// configSummary renders the effective configuration for an operator, with any
// datastore credentials redacted so the output is safe to log.
func configSummary(cfg *config.Config) string {
	var b strings.Builder
	fmt.Fprintf(&b, "server.addr: %s\n", cfg.Server.Addr)
	fmt.Fprintf(&b, "server.tls.mode: %s\n", cfg.Server.TLS.Mode)
	if cfg.Server.TLS.Mode == config.TLSFile {
		fmt.Fprintf(&b, "server.tls.cert_file: %s\n", cfg.Server.TLS.CertFile)
		fmt.Fprintf(&b, "server.tls.key_file: %s\n", cfg.Server.TLS.KeyFile)
	}
	fmt.Fprintf(&b, "postgres.mode: %s\n", cfg.Postgres.Mode)
	if cfg.Postgres.Mode == config.PostgresExternal {
		fmt.Fprintf(&b, "postgres.dsn: %s\n", redact(cfg.Postgres.DSN))
	} else {
		fmt.Fprintf(&b, "postgres.data_dir: %s\n", cfg.Postgres.DataDir)
	}
	fmt.Fprintf(&b, "nats.mode: %s\n", cfg.NATS.Mode)
	if cfg.NATS.Mode == config.NATSExternal {
		fmt.Fprintf(&b, "nats.url: %s\n", redact(cfg.NATS.URL))
	} else {
		fmt.Fprintf(&b, "nats.store_dir: %s\n", cfg.NATS.StoreDir)
	}
	fmt.Fprintf(&b, "log.level: %s\n", cfg.Log.Level)
	fmt.Fprintf(&b, "log.format: %s\n", cfg.Log.Format)
	fmt.Fprintf(&b, "migrate.auto: %t\n", cfg.Migrate.Auto)
	fmt.Fprintf(&b, "secrets.kek_file: %s\n", cfg.Secrets.KEKFile)
	fmt.Fprintf(&b, "signer.mode: %s\n", cfg.Signer.Mode)
	if cfg.Signer.Mode == config.SignerExternal {
		fmt.Fprintf(&b, "signer.socket: %s\n", cfg.Signer.Socket)
	}
	fmt.Fprintf(&b, "ca.cert_file: %s\n", cfg.CA.CertFile)
	// Served issuance protocols (EXC-WIRE-02): show which RFC protocols the binary
	// will mount. They activate only when an issuing CA is provisioned (a signer is
	// configured); a protocol with no tenant fails closed at issuance (AN-1).
	fmt.Fprintf(&b, "protocols.acme.enabled: %t\n", cfg.Protocols.ACME.Enabled)
	fmt.Fprintf(&b, "protocols.est.enabled: %t\n", cfg.Protocols.EST.Enabled)
	fmt.Fprintf(&b, "protocols.scep.enabled: %t\n", cfg.Protocols.SCEP.Enabled)
	fmt.Fprintf(&b, "protocols.cmp.enabled: %t\n", cfg.Protocols.CMP.Enabled)
	fmt.Fprintf(&b, "protocols.spiffe.enabled: %t\n", cfg.Protocols.SPIFFE.Enabled)
	if cfg.Protocols.SPIFFE.Enabled {
		fmt.Fprintf(&b, "protocols.spiffe.trust_domain: %s\n", cfg.Protocols.SPIFFE.TrustDomain)
	}
	fmt.Fprintf(&b, "protocols.ssh.enabled: %t\n", cfg.Protocols.SSH.Enabled)
	// Served OIDC browser login + session + per-user tenant mapping (EXC-WIRE-01):
	// show whether the binary mounts the /auth/* login and, when on, the IdP it trusts
	// and the per-user tenant-mapping mode. Never the client secret or session secret
	// (AN-8) — only the public issuer/client-id.
	fmt.Fprintf(&b, "auth.oidc.enabled: %t\n", cfg.Auth.OIDC.Enabled)
	if cfg.Auth.OIDC.Enabled {
		fmt.Fprintf(&b, "auth.oidc.issuer: %s\n", cfg.Auth.OIDC.Issuer)
		fmt.Fprintf(&b, "auth.oidc.client_id: %s\n", cfg.Auth.OIDC.ClientID)
		mode := "tenant_mappings"
		if cfg.Auth.OIDC.ClaimIsTenant {
			mode = "claim_is_tenant(" + cfg.Auth.OIDC.TenantClaim + ")"
		} else if cfg.Auth.OIDC.TenantClaim != "" {
			mode = "tenant_claim(" + cfg.Auth.OIDC.TenantClaim + ")"
		}
		fmt.Fprintf(&b, "auth.oidc.tenant_mapping: %s\n", mode)
	}
	fmt.Fprintf(&b, "telemetry.enabled: %t\n", cfg.Telemetry.Enabled)
	if cfg.Telemetry.Enabled {
		fmt.Fprintf(&b, "telemetry.endpoint: %s\n", cfg.Telemetry.Endpoint)
		fmt.Fprintf(&b, "telemetry.interval: %s\n", cfg.Telemetry.Interval)
	}
	return b.String()
}

// redact returns a connection string with any embedded password masked, keeping
// the host visible so an operator can confirm what the process points at without
// exposing the secret.
func redact(conn string) string {
	u, err := url.Parse(conn)
	if err != nil {
		return "[unparseable connection string; redacted]"
	}
	return u.Redacted()
}
