// SPDX-License-Identifier: LicenseRef-trstctl-EE

package delegation

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

func TestDurableReachabilityTrustStore_PutAndLookup(t *testing.T) {
	signer, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	store := NewDurableReachabilityTrustStore(t.TempDir())
	if _, ok := store.TrustLookup("reach-key"); ok {
		t.Fatal("unprovisioned reachability verdict key unexpectedly trusted")
	}
	if err := store.PutVerdictSigner(context.Background(), "reach-key", signer.Public().DER); err != nil {
		t.Fatalf("PutVerdictSigner: %v", err)
	}
	got, ok := store.TrustLookup("reach-key")
	if !ok {
		t.Fatal("provisioned reachability verdict key was not trusted")
	}
	if string(got) != string(signer.Public().DER) {
		t.Fatal("trusted reachability verdict key DER changed")
	}
}

func TestDurableReachabilityTrustStore_UnsafePathRefused(t *testing.T) {
	store := NewDurableReachabilityTrustStore(t.TempDir())
	if err := store.PutVerdictSigner(context.Background(), "../reach-key", []byte("pub")); err == nil {
		t.Fatal("unsafe reachability verdict key path was accepted")
	}
	if _, ok := store.TrustLookup("../reach-key"); ok {
		t.Fatal("unsafe reachability verdict key path was trusted")
	}
}
