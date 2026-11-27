// SPDX-License-Identifier: BUSL-1.1

// Package natskey provisions a NATS user identity in a protected seed file.
// Its public NKey may be copied into a broker authorization config; the seed
// stays outside the broker and survives evaluation stack restarts.
package natskey

import (
	"errors"
	"fmt"
	"io/fs"

	"github.com/nats-io/nkeys"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
)

// Provision creates a new user seed once, or verifies the existing protected
// file and returns its public identity. It never prints or returns the seed.
func Provision(path string) (string, error) {
	seed, err := secretfile.Load(path)
	if errors.Is(err, fs.ErrNotExist) {
		pair, createErr := nkeys.CreateUser()
		if createErr != nil {
			return "", fmt.Errorf("natskey: create user: %w", createErr)
		}
		defer pair.Wipe()
		seed, createErr = pair.Seed()
		if createErr != nil {
			return "", fmt.Errorf("natskey: encode user seed: %w", createErr)
		}
		defer secret.Wipe(seed)
		if createErr = secretfile.Create(path, seed); createErr != nil {
			return "", fmt.Errorf("natskey: persist user seed: %w", createErr)
		}
	} else if err != nil {
		return "", fmt.Errorf("natskey: load user seed: %w", err)
	} else {
		defer secret.Wipe(seed)
	}
	pair, err := nkeys.FromSeed(seed)
	if err != nil {
		return "", fmt.Errorf("natskey: parse user seed: %w", err)
	}
	defer pair.Wipe()
	public, err := pair.PublicKey()
	if err != nil || !nkeys.IsValidPublicUserKey(public) {
		return "", errors.New("natskey: invalid user identity")
	}
	return public, nil
}
