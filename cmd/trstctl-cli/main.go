// SPDX-License-Identifier: BUSL-1.1

// Command trstctl-cli is the trstctl command-line interface — a scriptable
// client at parity with the REST API (F11). Configuration comes from flags or
// TRSTCTL_* environment variables, so it drops cleanly into CI.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"trstctl.com/trstctl/internal/cli"
	"trstctl.com/trstctl/internal/netconfine"
	"trstctl.com/trstctl/internal/netsec"
)

func main() {
	// A257-L2: run as the helper that confines a launched command's network
	// (trstctl access agent --confine-network re-runs this binary for it).
	if len(os.Args) > 1 && os.Args[1] == netconfine.HelperArg {
		os.Exit(netconfine.RunHelper(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}
	// The runtime distrust list guards the process default transport too (eMudhra, Part 2).
	netsec.HardenProcessDefaults()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	env := cli.Env{
		Server:         os.Getenv("TRSTCTL_SERVER"),
		Token:          os.Getenv("TRSTCTL_TOKEN"),
		Tenant:         os.Getenv("TRSTCTL_TENANT"),
		CAFile:         os.Getenv("TRSTCTL_CA_FILE"),
		IdempotencyKey: os.Getenv("TRSTCTL_IDEMPOTENCY_KEY"),
	}
	os.Exit(cli.Run(ctx, os.Args[1:], env, os.Stdin, os.Stdout, os.Stderr))
}
