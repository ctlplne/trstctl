// SPDX-License-Identifier: BUSL-1.1

// Command trstctl-kms-wrap is the signer key store's KMS/HSM wrap adapter.
// trstctl-signer runs it as `trstctl-kms-wrap wrap|unwrap <provider> <keyRef>`
// when started with --kms-wrap-command; see internal/kms/wrapadapter for the
// protocol and configuration.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"trstctl.com/trstctl/internal/kms/wrapadapter"
	"trstctl.com/trstctl/internal/netsec"
)

func main() {
	netsec.HardenProcessDefaults()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := wrapadapter.Run(ctx, os.Args[1:], os.Getenv, os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
