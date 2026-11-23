// SPDX-License-Identifier: BUSL-1.1

package transit_test

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/transit"
)

const tenantB = "22222222-2222-4222-8222-222222222222"

// A warm replica must lose transit authority when the tenant key domain stops
// opening its stored ring. The cold replica is the control: it cannot reload.
func TestCR044WarmTransitReplicaStopsAfterTenantCryptoIsUnavailable(t *testing.T) {
	ctx := context.Background()
	store, sealer := newMemKeyringStore(), newKEKSealer(t)
	warm := sharedReplica(t, store, sealer)
	if _, err := warm.CreateKey(ctx, tenantA, "orders", transit.KindAEAD); err != nil {
		t.Fatal(err)
	}
	if _, err := warm.CreateKey(ctx, tenantA, "signer", transit.KindSign); err != nil {
		t.Fatal(err)
	}
	if _, err := warm.CreateKey(ctx, tenantA, "mac", transit.KindHMAC); err != nil {
		t.Fatal(err)
	}
	if _, err := warm.CreateKey(ctx, tenantB, "orders", transit.KindAEAD); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := warm.Encrypt(ctx, tenantA, "orders", []byte("cardholder data"), nil)
	if err != nil {
		t.Fatal(err)
	}
	sig, pub, err := warm.Sign(ctx, tenantA, "signer", []byte("manifest"))
	if err != nil {
		t.Fatal(err)
	}
	sealer.failOpen, sealer.failTenant = true, tenantA
	cold := sharedReplica(t, store, sealer)
	if _, err := cold.Decrypt(ctx, tenantA, "orders", ciphertext, nil); err == nil {
		t.Fatal("cold replica decrypted a sealed tenant's keyring")
	}
	if plain, err := warm.Decrypt(ctx, tenantA, "orders", ciphertext, nil); err == nil {
		t.Errorf("warm replica decrypted %d bytes after tenant crypto became unavailable", len(plain))
	}
	if _, err := warm.Encrypt(ctx, tenantA, "orders", []byte("new data"), nil); err == nil {
		t.Error("warm replica encrypted after tenant crypto became unavailable")
	}
	if _, err := warm.Rewrap(ctx, tenantA, "orders", ciphertext, nil); err == nil {
		t.Error("warm replica rewrapped after tenant crypto became unavailable")
	}
	if _, err := warm.HMAC(ctx, tenantA, "mac", []byte("message")); err == nil {
		t.Error("warm replica computed an HMAC after tenant crypto became unavailable")
	}
	if _, _, err := warm.Sign(ctx, tenantA, "signer", []byte("manifest")); err == nil {
		t.Error("warm replica signed after tenant crypto became unavailable")
	}
	if err := warm.Verify(ctx, tenantA, []byte("manifest"), sig, pub); err == nil {
		t.Error("warm replica verified after tenant crypto became unavailable")
	}
	if err := warm.VerifyNamed(ctx, tenantA, "signer", []byte("manifest"), sig, pub); err == nil {
		t.Error("warm replica verified named signing key after tenant crypto became unavailable")
	}
	if _, err := warm.Rotate(ctx, tenantA, "orders"); err == nil {
		t.Error("warm replica rotated a key after tenant crypto became unavailable")
	}
	if _, err := warm.CreateKey(ctx, tenantA, "new-key", transit.KindAEAD); err == nil {
		t.Error("warm replica created a key after tenant crypto became unavailable")
	}
	if _, err := warm.ListKeys(ctx, tenantA); err == nil {
		t.Error("warm replica listed cached keys after tenant crypto became unavailable")
	}
	if _, _, err := warm.ListKeyVersions(ctx, tenantA, "orders"); err == nil {
		t.Error("warm replica listed cached key versions after tenant crypto became unavailable")
	}
	if _, err := warm.Encrypt(ctx, tenantB, "orders", []byte("neighbor data"), nil); err != nil {
		t.Errorf("sealing tenant A stopped unrelated tenant B: %v", err)
	}
	// Once access is restored, an offboarded row must not be replaced by the
	// replica's previously cached plaintext keyring.
	sealer.failOpen = false
	store.mu.Lock()
	delete(store.rows, tenantA)
	delete(store.revs, tenantA)
	store.mu.Unlock()
	if _, err := warm.Decrypt(ctx, tenantA, "orders", ciphertext, nil); err == nil {
		t.Error("warm replica kept the tenant's plaintext keyring after admission failed")
	}
}
