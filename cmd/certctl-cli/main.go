// Command certctl-cli is the certctl command-line interface — a scriptable
// client at parity with the REST API (F11). Configuration comes from flags or
// the CERTCTL_SERVER / CERTCTL_TOKEN / CERTCTL_TENANT environment variables, so
// it drops cleanly into CI.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"certctl.io/certctl/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	env := cli.Env{
		Server:         os.Getenv("CERTCTL_SERVER"),
		Token:          os.Getenv("CERTCTL_TOKEN"),
		Tenant:         os.Getenv("CERTCTL_TENANT"),
		IdempotencyKey: os.Getenv("CERTCTL_IDEMPOTENCY_KEY"),
	}
	os.Exit(cli.Run(ctx, os.Args[1:], env, os.Stdin, os.Stdout, os.Stderr))
}
