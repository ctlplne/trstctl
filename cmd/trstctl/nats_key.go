// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"trstctl.com/trstctl/internal/crypto/natskey"
)

// runNATSKey prepares one stable evaluation broker identity. The public-only
// config and private seed are separate files in the task-owned secret volume.
func runNATSKey(args []string, stderr io.Writer) error {
	if len(args) != 3 || args[0] != "provision" || args[1] == "" || args[2] == "" {
		return errors.New("usage: trstctl nats-key provision <seed-file> <broker-config-file>")
	}
	public, err := natskey.Provision(args[1])
	if err != nil {
		return err
	}
	contents := []byte("authorization { users = [{ nkey: " + public + " }] }\n")
	existing, err := os.ReadFile(args[2]) // #nosec G304 -- exact operator-selected evaluation broker config path (CWE-22)
	if err == nil {
		if !bytes.Equal(existing, contents) {
			return errors.New("nats-key: existing broker config does not match the protected seed")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("nats-key: inspect broker config: %w", err)
	}
	f, err := os.OpenFile(args[2], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- exact operator-selected evaluation path with exclusive create (CWE-22)
	if err != nil {
		return fmt.Errorf("nats-key: create broker config: %w", err)
	}
	_, writeErr := f.Write(contents)
	closeErr := f.Close()
	if writeErr != nil {
		return fmt.Errorf("nats-key: write broker config: %w", writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("nats-key: close broker config: %w", closeErr)
	}
	_, _ = fmt.Fprintln(stderr, "Provisioned evaluation NATS NKey identity and broker config.")
	return nil
}
