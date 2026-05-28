// Command certctl is the certctl control-plane binary.
//
// In single-node mode it will also supervise the isolated signing service as a
// child process (AN-4); that wiring, along with the API, event spine, and
// stores, arrives in later sprints. For sprint S0.1 this binary exists to prove
// the skeleton: it boots, reports its version via --version, and shuts down
// cleanly on SIGINT/SIGTERM.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"certctl.io/certctl/internal/buildinfo"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "certctl: %v\n", err)
		os.Exit(1)
	}
}

// run is the testable program entry point. It parses args and either prints
// version information and returns, or boots the control plane and blocks until
// ctx is cancelled (as it is on SIGINT/SIGTERM), then returns nil to signal a
// clean shutdown. Output is written to the provided writers so tests can capture
// it without touching the process's real stdio.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("certctl", flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print version information and exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			// -h/--help already printed usage to stderr; this is a clean exit.
			return nil
		}
		return err
	}

	if *showVersion {
		fmt.Fprintln(stdout, buildinfo.String("certctl"))
		return nil
	}

	fmt.Fprintf(stderr, "starting %s\n", buildinfo.String("certctl"))
	<-ctx.Done()
	fmt.Fprintln(stderr, "shutdown signal received; certctl stopped cleanly")
	return nil
}
