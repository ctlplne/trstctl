// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"errors"
	"fmt"
	"io"
	"time"

	"trstctl.com/trstctl/internal/crypto/kek"
	"trstctl.com/trstctl/internal/crypto/kmswrap"
	"trstctl.com/trstctl/internal/signing"
)

// runRewrapKeystore is --rewrap-keystore (A200-L2): it moves a key store the
// local KEK sealed onto the external KMS/HSM adapter, keeping the original as
// the rollback copy, then exits. The adapter is probed first, so a disabled
// or unreachable key stops the run with the adapter's reason before anything
// is copied.
func runRewrapKeystore(keystore, kekFile, provider, keyRef, wrapCommand string, timeout time.Duration, out io.Writer) error {
	if keystore == "" || kekFile == "" || provider == "" || keyRef == "" || wrapCommand == "" {
		return errors.New("--rewrap-keystore needs --keystore, the --kek that sealed it, and --kms-provider, --kms-key-ref and --kms-wrap-command for the adapter it moves to")
	}
	source, err := kek.Load(kekFile)
	if err != nil {
		return fmt.Errorf("load the key store's KEK: %w", err)
	}
	defer source.Destroy()
	destination, err := kmswrap.NewExternalKMSWrapper(kmswrap.ExternalKMSConfig{
		Provider: provider, KeyRef: keyRef, WrapCommand: wrapCommand, Timeout: timeout,
	})
	if err != nil {
		return err
	}
	if err := probeKeystoreWrapper(destination); err != nil {
		return err
	}
	report, err := signing.RewrapKeyStore(keystore, source, destination, time.Now())
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "re-wrapped %d sealed files onto %s %s (%d signer keys open under it); carried %d other files unchanged\n",
		report.Rewrapped, provider, keyRef, report.Keys, report.Copied)
	_, _ = fmt.Fprintf(out, "the local-KEK key store is kept at %s for rollback; start the signer with --kms-provider, --kms-key-ref and --kms-wrap-command and without --kek\n",
		report.Backup)
	return nil
}
