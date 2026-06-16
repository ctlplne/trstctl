// Command trstctl-cli is the trstctl command-line interface — a scriptable
// client at parity with the REST API (F11). Configuration comes from flags or
// the TRSTCTL_SERVER / TRSTCTL_TOKEN / TRSTCTL_TENANT environment variables, so
// it drops cleanly into CI.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"trstctl.com/trstctl/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	env := cli.Env{
		Server:         os.Getenv("TRSTCTL_SERVER"),
		Token:          os.Getenv("TRSTCTL_TOKEN"),
		Tenant:         os.Getenv("TRSTCTL_TENANT"),
		IdempotencyKey: os.Getenv("TRSTCTL_IDEMPOTENCY_KEY"),
	}
	os.Exit(cli.Run(ctx, os.Args[1:], env, os.Stdin, os.Stdout, os.Stderr))
}
