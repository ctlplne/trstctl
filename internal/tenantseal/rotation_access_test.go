// SPDX-License-Identifier: BUSL-1.1

package tenantseal_test

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/tenantwrap"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

// While a tenant domain rotates, new data seals under the next generation, a
// container opens with exactly the generation its label names (each through its
// own wrapper), and everything else fails closed.
func TestAccessRotationSealsUnderTheNextGenerationAndOpensBothExactly(t *testing.T) {
	currentPath, nextPath := writeTestWrapper(t, 0x61), writeTestWrapper(t, 0x62)
	g1, err := tenantseal.DomainBinding(testTenantA, testDomainA, 1)
	if err != nil {
		t.Fatal(err)
	}
	g2, err := tenantseal.DomainBinding(testTenantA, testDomainA, 2)
	if err != nil {
		t.Fatal(err)
	}
	currentKey, currentWrapped, err := tenantwrap.CreateDomainKEK(currentPath, g1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(currentKey.Destroy)
	nextKey, nextWrapped, err := tenantwrap.CreateDomainKEK(nextPath, g2)
	if err != nil {
		t.Fatal(err)
	}
	nextKey.Destroy()
	deployment := newTestKEK(t, 0x63)
	aad := []byte("opaque rotation aad")
	oldRow, err := seal.SealDomain(currentKey, []byte("generation one"), aad, g1)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := seal.Seal(deployment, []byte("deployment row"), aad)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := seal.SealDomain(currentKey, []byte("other label"), aad, []byte("tenant=other;domain=x;generation=1"))
	if err != nil {
		t.Fatal(err)
	}

	domain := store.TenantKeyDomain{
		TenantID: testTenantA, DomainID: testDomainA, Generation: 1,
		ProtectionMode: store.TenantKeyProtectionTenantDomain,
		State:          store.TenantKeyDomainStateRotating,
		WrapperKind:    tenantseal.WrapperKindLocalFile, WrapperID: "tenant-wrapper",
		WrappedDomainKEK: currentWrapped,
		NextGeneration:   2, NextWrapperKind: tenantseal.WrapperKindLocalFile,
		NextWrapperID: "tenant-wrapper-next", NextWrappedDomainKEK: nextWrapped,
		OperationKind: store.TenantKeyOperationRotate, OperationStatus: store.TenantKeyOperationRunning,
		ProgressCompleted: 3, ProgressTotal: 13,
		LegacyHistoryExposure: store.TenantKeyLegacyExternalArchivesPossible,
	}
	localRegistry, err := tenantseal.NewLocalWrapperRegistry([]tenantseal.LocalWrapper{
		{ID: "tenant-wrapper", Path: currentPath},
		{ID: "tenant-wrapper-next", Path: nextPath},
	})
	if err != nil {
		t.Fatal(err)
	}
	registry := &recordingRegistry{inner: localRegistry}
	access, err := tenantseal.NewAccess(&fakeDomainStore{domain: &domain}, deployment, registry)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	err = access.WithTenant(ctx, testTenantA, func(cipher tenantseal.Cipher) error {
		written, err := cipher.Seal([]byte("written during rotation"), aad)
		if err != nil {
			return err
		}
		if label, err := seal.Domain(written); err != nil || string(label) != string(g2) {
			return errors.New("data written during the rotation is not in the next generation")
		}
		if plain, err := cipher.Open(written, aad); err != nil || string(plain) != "written during rotation" {
			return errors.New("next-generation container did not open")
		}
		if plain, err := cipher.Open(oldRow, aad); err != nil || string(plain) != "generation one" {
			return errors.New("previous-generation container did not open during the rotation")
		}
		for _, container := range [][]byte{legacy, foreign} {
			if _, err := cipher.Open(container, aad); !errors.Is(err, seal.ErrDomain) {
				return errors.New("rotation cipher opened a container outside its two generations")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithTenant during rotation: %v", err)
	}
	if len(registry.refs) != 2 || registry.refs[0].ID != "tenant-wrapper" || registry.refs[1].ID != "tenant-wrapper-next" {
		t.Fatalf("wrapper registry refs = %+v, want the current then the next wrapper", registry.refs)
	}

	domain.OperationStatus = store.TenantKeyOperationFailed
	domain.Retryable = true
	if err := access.WithTenant(ctx, testTenantA, func(cipher tenantseal.Cipher) error {
		_, err := cipher.Open(oldRow, aad)
		return err
	}); err != nil {
		t.Fatalf("a failed rotation stopped reading the previous generation: %v", err)
	}

	domain.NextWrappedDomainKEK = nil
	err = access.WithTenant(ctx, testTenantA, func(tenantseal.Cipher) error {
		return errors.New("callback ran for a rotation without its next generation")
	})
	requireStatus(t, err, tenantseal.StatusCorrupt)
}
