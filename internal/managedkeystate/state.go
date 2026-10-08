// SPDX-License-Identifier: BUSL-1.1

// Package managedkeystate names remote key outcomes without mistaking a cloud
// provider's deletion queue for confirmed physical destruction. It has no KMS
// clients and can be shared by the isolated signer and event projections.
package managedkeystate

import "strings"

const DeletionPending = "deletion_pending"

// ZeroizeOutcome is deliberately conservative. Only the shipped local device
// adapters confirm that their destruction call removed key material. AWS KMS,
// Azure Key Vault, and Google Cloud KMS can retain material after accepting the
// call. Unknown future adapters must prove immediate destruction before joining
// the confirmed list.
func ZeroizeOutcome(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "pkcs11", "tpm2", "yubihsm2":
		return "zeroized"
	default:
		return DeletionPending
	}
}

// PublicState presents old cloud completion events conservatively. Their event
// bytes remain immutable; they recorded successful scheduling as "zeroized".
// This translation does not claim that the provider has since destroyed the key.
func PublicState(provider, state string) string {
	if state == "zeroized" && ZeroizeOutcome(provider) == DeletionPending {
		return DeletionPending
	}
	return state
}
