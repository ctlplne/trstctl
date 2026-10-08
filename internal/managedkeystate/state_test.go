// SPDX-License-Identifier: BUSL-1.1

package managedkeystate

import "testing"

func TestZeroizeOutcomeDoesNotClaimCloudMaterialWasDestroyed(t *testing.T) {
	for _, provider := range []string{"aws-kms", "azure-key-vault", "gcp-kms"} {
		if got := ZeroizeOutcome(provider); got != DeletionPending {
			t.Errorf("%s zeroize outcome = %q, want %q", provider, got, DeletionPending)
		}
		if got := PublicState(provider, "zeroized"); got != DeletionPending {
			t.Errorf("%s legacy zeroized state = %q, want conservative %q", provider, got, DeletionPending)
		}
	}
	for _, provider := range []string{"pkcs11", "tpm2", "yubihsm2"} {
		if got := ZeroizeOutcome(provider); got != "zeroized" {
			t.Errorf("%s zeroize outcome = %q, want zeroized", provider, got)
		}
		if got := PublicState(provider, "zeroized"); got != "zeroized" {
			t.Errorf("%s public state = %q, want zeroized", provider, got)
		}
	}
	if got := PublicState("aws-kms", "revoked"); got != "revoked" {
		t.Errorf("revoke state changed: %q", got)
	}
}
