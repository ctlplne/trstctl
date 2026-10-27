// SPDX-License-Identifier: LicenseRef-trstctl-EE

package managedkeys

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

const (
	providerTenantA = "11111111-1111-4111-8111-111111111111"
	providerTenantB = "22222222-2222-4222-8222-222222222222"
)

func twoProviderService(keys map[[2]string]bool) *durableService {
	return &durableService{
		selection: ProviderSelection{
			Default: "pkcs11", Enabled: []string{"pkcs11", "aws"},
			Tenants: map[string]string{providerTenantA: "aws"},
		}.normalized(),
		loadKey: func(_ context.Context, tenantID, provider, keyID string) (store.ManagedKey, error) {
			if !keys[[2]string{provider, keyID}] {
				return store.ManagedKey{}, pgx.ErrNoRows
			}
			return store.ManagedKey{TenantID: tenantID, Provider: provider, KeyID: keyID, Algorithm: string(crypto.ECDSAP256), Version: 1, State: "active"}, nil
		},
	}
}

// A199: a new key goes to the provider the request names, else the tenant's
// pin, else the default; a pinned tenant names only its pin, and nobody names
// a provider the deployment does not run.
func TestDurableGenerationProviderHonorsPinsAndTheRunningSet(t *testing.T) {
	svc := twoProviderService(nil)
	for _, c := range []struct {
		tenant, requested, want string
		refused                 bool
	}{
		{providerTenantA, "", "aws-kms", false},
		{providerTenantA, "aws", "aws-kms", false},
		{providerTenantA, "pkcs11", "", true},
		{providerTenantB, "", "pkcs11", false},
		{providerTenantB, "aws-kms", "aws-kms", false},
		{providerTenantB, "gcp-kms", "", true},
	} {
		got, err := svc.generationProvider(c.tenant, c.requested)
		if c.refused {
			if !errors.Is(err, api.ErrManagedKeyProviderNotAllowed) {
				t.Errorf("tenant %s requesting %q = %q, %v; want refused", c.tenant, c.requested, got, err)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("tenant %s requesting %q = %q, %v; want %q", c.tenant, c.requested, got, err, c.want)
		}
	}
}

// An action's key is under the provider the request names, or the only
// running provider holding that handle; a handle under two providers needs the
// name.
func TestDurableActionProviderResolvesFromTheKeyHandle(t *testing.T) {
	svc := twoProviderService(map[[2]string]bool{
		{"pkcs11", "hsm-key"}: true, {"aws-kms", "kms-key"}: true,
		{"pkcs11", "shared"}: true, {"aws-kms", "shared"}: true,
	})
	ctx := context.Background()
	for keyID, want := range map[string]string{"hsm-key": "pkcs11", "kms-key": "aws-kms"} {
		if got, err := svc.keyProvider(ctx, providerTenantB, "", keyID); err != nil || got != want {
			t.Errorf("%s resolved to %q, %v; want %q", keyID, got, err, want)
		}
	}
	if _, err := svc.keyProvider(ctx, providerTenantB, "", "shared"); !errors.Is(err, api.ErrManagedKeyAmbiguous) {
		t.Errorf("a handle under two providers = %v, want ErrManagedKeyAmbiguous", err)
	}
	if got, err := svc.keyProvider(ctx, providerTenantB, "aws", "shared"); err != nil || got != "aws-kms" {
		t.Errorf("a named provider = %q, %v", got, err)
	}
	if _, err := svc.keyProvider(ctx, providerTenantB, "", "missing"); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("an unknown handle = %v, want ErrUnknownKey", err)
	}
	if _, err := svc.keyProvider(ctx, providerTenantB, "gcp-kms", "kms-key"); !errors.Is(err, api.ErrManagedKeyProviderNotAllowed) {
		t.Errorf("a provider the deployment does not run = %v", err)
	}
}

// A replay keeps the provider its original resolved and touches no key
// state; naming a different provider on the same idempotency key conflicts.
func TestDurableReplayKeepsTheOriginalProvider(t *testing.T) {
	const keyID = "kms-key"
	loads := 0
	svc := twoProviderService(nil)
	svc.loadKey = func(_ context.Context, tenantID, provider, requested string) (store.ManagedKey, error) {
		loads++
		return store.ManagedKey{TenantID: tenantID, Provider: provider, KeyID: requested, Algorithm: string(crypto.ECDSAP256), Version: 1, State: "revoked"}, nil
	}
	operationID, err := durableOperationID(providerTenantB, "revoke-once")
	if err != nil {
		t.Fatal(err)
	}
	svc.loadOperation = func(context.Context, string, string) (store.ManagedKeyOperation, error) {
		return store.ManagedKeyOperation{
			OperationID: operationID, Provider: "aws-kms", Action: "revoke", KeyID: keyID,
			RequestBinding: "sha256:binding", Status: "completed", ResultKeyID: keyID,
		}, nil
	}
	replay, err := svc.Revoke(context.Background(), providerTenantB, "", keyID, "alice", "revoke-once", "sha256:binding")
	if err != nil || replay.Provider != "aws-kms" || loads != 1 {
		t.Fatalf("replay = %+v, %v, key loads %d; want the original aws-kms result after one result read", replay, err, loads)
	}
	if _, err := svc.Revoke(context.Background(), providerTenantB, "pkcs11", keyID, "alice", "revoke-once", "sha256:binding"); err == nil {
		t.Fatal("a replay naming another provider was accepted")
	}
}
