// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"

	"trstctl.com/trstctl/internal/crypto/eventauth"
	"trstctl.com/trstctl/internal/crypto/natskey"
	"trstctl.com/trstctl/internal/crypto/secretfile"
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
	if err := eventauth.Provision(filepath.Join(filepath.Dir(args[1]), "event-auth.key")); err != nil {
		return fmt.Errorf("nats-key: provision event authentication key: %w", err)
	}
	contents := []byte("authorization { users = [{ nkey: " + public + " }] }\n")
	existing, err := secretfile.Load(args[2])
	if err == nil {
		if !bytes.Equal(existing, contents) {
			return errors.New("nats-key: existing broker config does not match the protected seed")
		}
		return nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("nats-key: inspect broker config: %w", err)
	}
	if err := secretfile.Create(args[2], contents); err != nil {
		return fmt.Errorf("nats-key: create broker config: %w", err)
	}
	_, _ = fmt.Fprintln(stderr, "Provisioned evaluation NATS NKey identity and broker config.")
	return nil
}
