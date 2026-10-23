// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
)

// checkStartupKeyBinding is the startup gate for a long-lived key binding
// (owner decision, batch 11): the agent CA and the break-glass material. The
// public key must pass the weak-key checks crypto.RefuseWeakKey runs, and when
// the private key is in the signer (holder non-nil), the signer must prove it
// holds that exact key by signing a fresh challenge. Offline keys, which stay
// with the recovery side, get the weak-key check only. A failure stops startup
// with an error naming the binding and the check.
func checkStartupKeyBinding(binding string, pub crypto.PublicKey, holder crypto.DigestSigner) error {
	if err := crypto.RefuseWeakKey(pub); err != nil {
		return fmt.Errorf("startup binding %s: weak-key check failed: %w", binding, err)
	}
	if holder == nil {
		return nil
	}
	if err := crypto.ProvePossession(holder, pub); err != nil {
		return fmt.Errorf("startup binding %s: possession proof failed: %w", binding, err)
	}
	return nil
}
