// Command certctl is the certctl control-plane binary.
//
// In single-node mode it will also supervise the isolated signing service as a
// child process (AN-4); that wiring, along with the API, event spine, and
// stores, arrives in the binary-assembly sprint. Today the binary boots, reports
// its version via --version, resolves and validates its configuration (including
// the bundled-vs-external Postgres/NATS switches used by the container image and
// Compose stack, S7.4), prints it with --check-config, and shuts down cleanly on
// SIGINT/SIGTERM.
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

	"certctl.io/certctl/internal/buildinfo"
	"certctl.io/certctl/internal/config"
	"certctl.io/certctl/internal/crypto/mtls"
	"certctl.io/certctl/internal/server"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "certctl: %v\n", err)
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
	fs := flag.NewFlagSet("certctl", flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print version information and exit")
	checkConfig := fs.Bool("check-config", false, "resolve and print the effective configuration, then exit")
	healthCheck := fs.Bool("health-check", false, "probe the local control plane's /healthz and exit 0/1 (container health check)")
	backupPath := fs.String("backup", "", "back up the event log (source of truth) to FILE, then exit")
	restorePath := fs.String("restore", "", "restore the event log from FILE, rebuild the read model, then exit")
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
		_, _ = fmt.Fprintln(stdout, buildinfo.String("certctl"))
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
	_, _ = fmt.Fprintf(stderr, "starting %s\n", buildinfo.String("certctl"))
	_, _ = io.WriteString(stderr, configSummary(cfg))
	if err := server.Run(ctx, cfg); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(stderr, "certctl stopped cleanly")
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
