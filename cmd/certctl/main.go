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
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"certctl.io/certctl/internal/buildinfo"
	"certctl.io/certctl/internal/config"
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

	_, _ = fmt.Fprintf(stderr, "starting %s\n", buildinfo.String("certctl"))
	_, _ = io.WriteString(stderr, configSummary(cfg))
	<-ctx.Done()
	_, _ = fmt.Fprintln(stderr, "shutdown signal received; certctl stopped cleanly")
	return nil
}

// configSummary renders the effective configuration for an operator, with any
// datastore credentials redacted so the output is safe to log.
func configSummary(cfg *config.Config) string {
	var b strings.Builder
	fmt.Fprintf(&b, "server.addr: %s\n", cfg.Server.Addr)
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
