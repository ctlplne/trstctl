// SPDX-License-Identifier: BUSL-1.1

package tenantseal_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/tenantwrap"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

// aesHSMKey stands in for an HSM AES key behind the signer.
type aesHSMKey struct{ key []byte }

func (k aesHSMKey) Seal(plaintext, aad []byte) ([]byte, error) {
	return crypto.AESGCMSeal(k.key, plaintext, aad)
}

func (k aesHSMKey) Open(sealed, aad []byte) ([]byte, error) {
	plain, err := crypto.AESGCMOpen(k.key, sealed, aad)
	if err != nil {
		return nil, tenantwrap.ErrUnwrap
	}
	return plain, nil
}

// fakeSigner does what the signer's custody does, with the real HSM-wrapped
// container: the domain KEK exists only inside these calls.
type fakeSigner struct {
	keys                           map[string]aesHSMKey
	creates, opens, wraps, unwraps int
}

func newFakeSigner(t *testing.T, ids ...string) *fakeSigner {
	t.Helper()
	f := &fakeSigner{keys: map[string]aesHSMKey{}}
	for _, id := range ids {
		key, err := crypto.RandomBytes(32)
		if err != nil {
			t.Fatal(err)
		}
		f.keys[id] = aesHSMKey{key: key}
	}
	return f
}

func (f *fakeSigner) open(wrapperID string, wrapped, binding []byte) (*seal.LocalKEK, error) {
	key, ok := f.keys[wrapperID]
	if !ok {
		return nil, fmt.Errorf("%w: the signer holds no such wrapper", tenantseal.ErrWrapperNotConfigured)
	}
	return tenantwrap.OpenDomainKEKExternal(key, wrapped, binding)
}

func (f *fakeSigner) CreateTenantDomainKEK(_ context.Context, wrapperID string, binding []byte) ([]byte, error) {
	f.creates++
	key, ok := f.keys[wrapperID]
	if !ok {
		return nil, fmt.Errorf("%w: the signer holds no such wrapper", tenantseal.ErrWrapperNotConfigured)
	}
	kek, wrapped, err := tenantwrap.CreateDomainKEKExternal(key, binding)
	if err != nil {
		return nil, err
	}
	kek.Destroy()
	return wrapped, nil
}

func (f *fakeSigner) OpenTenantDomainKEK(_ context.Context, wrapperID string, wrapped, binding []byte) error {
	f.opens++
	kek, err := f.open(wrapperID, wrapped, binding)
	if err != nil {
		return err
	}
	kek.Destroy()
	return nil
}

func (f *fakeSigner) WrapTenantDataKey(_ context.Context, wrapperID string, wrapped, binding, dataKey []byte) ([]byte, error) {
	f.wraps++
	kek, err := f.open(wrapperID, wrapped, binding)
	if err != nil {
		return nil, err
	}
	defer kek.Destroy()
	return kek.WrapDEK(dataKey)
}

func (f *fakeSigner) UnwrapTenantDataKey(_ context.Context, wrapperID string, wrapped, binding, wrappedDataKey []byte) ([]byte, error) {
	f.unwraps++
	kek, err := f.open(wrapperID, wrapped, binding)
	if err != nil {
		return nil, err
	}
	defer kek.Destroy()
	return kek.UnwrapDEK(wrappedDataKey)
}

func signerRegistry(t *testing.T, signer tenantseal.SignerTenantKEK, ids ...string) *tenantseal.RoutedWrapperRegistry {
	t.Helper()
	local, err := tenantseal.NewLocalWrapperRegistry(nil)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := tenantseal.NewSignerWrapperRegistry(ids, func() tenantseal.SignerTenantKEK { return signer })
	if err != nil {
		t.Fatal(err)
	}
	return tenantseal.NewRoutedWrapperRegistry(local, reg)
}

// A123: a tenant migrated to a pkcs11 wrapper seals and opens its data through
// the signer. The control plane holds only the wrapped KEK: the handle it gets
// is not key memory, each wrap and unwrap is one signer call, and the handle
// refuses every call once its fenced callback ends.
func TestSignerWrapperKeepsTheDomainKEKInTheSigner(t *testing.T) {
	signer := newFakeSigner(t, "hsm-a")
	registry := signerRegistry(t, signer, "hsm-a")
	binding, err := tenantseal.DomainBinding(testTenantA, testDomainA, 1)
	if err != nil {
		t.Fatal(err)
	}
	ref := tenantseal.WrapperRef{Kind: tenantseal.WrapperKindPKCS11, ID: "hsm-a"}
	created, wrapped, err := registry.CreateDomainKEK(context.Background(), ref, binding)
	if err != nil {
		t.Fatalf("create through the signer: %v", err)
	}
	if _, isKeyMemory := created.(*seal.LocalKEK); isKeyMemory || !bytes.HasPrefix(wrapped, []byte("TDH1")) {
		t.Fatalf("the control plane got %T and a %q container, want a signer handle and an HSM-wrapped container", created, wrapped[:4])
	}
	created.Destroy()

	domain := store.TenantKeyDomain{
		TenantID: testTenantA, DomainID: testDomainA, Generation: 1,
		ProtectionMode: store.TenantKeyProtectionTenantDomain, State: store.TenantKeyDomainStateUnsealed,
		WrapperKind: tenantseal.WrapperKindPKCS11, WrapperID: "hsm-a", WrappedDomainKEK: wrapped,
		OperationKind: store.TenantKeyOperationMigrate, OperationStatus: store.TenantKeyOperationCompleted,
		ProgressCompleted: 10, ProgressTotal: 10, LegacyHistoryExposure: store.TenantKeyLegacyNone,
	}
	recording := &recordingRegistry{inner: registry}
	access, err := tenantseal.NewAccess(&fakeDomainStore{domain: &domain}, newTestKEK(t, 0x71), recording)
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte("row=1")
	err = access.WithTenant(context.Background(), testTenantA, func(cipher tenantseal.Cipher) error {
		container, err := cipher.Seal([]byte("tenant payload"), aad)
		if err != nil {
			return err
		}
		plain, err := cipher.Open(container, aad)
		if err != nil || !bytes.Equal(plain, []byte("tenant payload")) {
			return fmt.Errorf("round trip through the signer = %q, %v", plain, err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("tenant access through the signer: %v", err)
	}
	if signer.opens != 1 || signer.wraps != 1 || signer.unwraps != 1 {
		t.Fatalf("signer calls open/wrap/unwrap = %d/%d/%d, want 1/1/1", signer.opens, signer.wraps, signer.unwraps)
	}
	if _, err := recording.opened.WrapDEK(bytes.Repeat([]byte{1}, 32)); err == nil {
		t.Fatal("the signer handle still wrapped after its fenced callback ended")
	}
	if signer.wraps != 1 {
		t.Fatal("a destroyed handle reached the signer")
	}
}

// Failures keep their public status: a pkcs11 ID the control plane does not
// list is not configured and never reaches the signer, one the signer does not
// hold is unavailable, a signer that is down is unavailable, a wrong binding is
// an unwrap failure, and without a signer registry the kind is not configured.
func TestSignerWrapperFailuresKeepTheirStatus(t *testing.T) {
	signer := newFakeSigner(t, "hsm-a")
	registry := signerRegistry(t, signer, "hsm-a", "hsm-gone")
	binding, err := tenantseal.DomainBinding(testTenantA, testDomainA, 1)
	if err != nil {
		t.Fatal(err)
	}
	_, wrapped, err := registry.CreateDomainKEK(context.Background(), tenantseal.WrapperRef{Kind: tenantseal.WrapperKindPKCS11, ID: "hsm-a"}, binding)
	if err != nil {
		t.Fatal(err)
	}
	access := func(t *testing.T, reg tenantseal.DomainKEKRegistry, wrapperID string, tenantID, domainID string) error {
		t.Helper()
		domain := store.TenantKeyDomain{
			TenantID: tenantID, DomainID: domainID, Generation: 1,
			ProtectionMode: store.TenantKeyProtectionTenantDomain, State: store.TenantKeyDomainStateUnsealed,
			WrapperKind: tenantseal.WrapperKindPKCS11, WrapperID: wrapperID, WrappedDomainKEK: wrapped,
			OperationKind: store.TenantKeyOperationMigrate, OperationStatus: store.TenantKeyOperationCompleted,
			ProgressCompleted: 10, ProgressTotal: 10, LegacyHistoryExposure: store.TenantKeyLegacyNone,
		}
		a, err := tenantseal.NewAccess(&fakeDomainStore{domain: &domain}, newTestKEK(t, 0x72), reg)
		if err != nil {
			t.Fatal(err)
		}
		return a.WithTenant(context.Background(), tenantID, func(tenantseal.Cipher) error {
			return errors.New("callback must not run")
		})
	}

	before := signer.opens
	requireStatus(t, access(t, registry, "hsm-unlisted", testTenantA, testDomainA), tenantseal.StatusWrapperUnavailable)
	if signer.opens != before {
		t.Fatal("an unlisted wrapper reached the signer")
	}
	requireStatus(t, access(t, registry, "hsm-gone", testTenantA, testDomainA), tenantseal.StatusWrapperUnavailable)
	down := signerRegistryWith(t, func() tenantseal.SignerTenantKEK { return nil }, "hsm-a")
	requireStatus(t, access(t, down, "hsm-a", testTenantA, testDomainA), tenantseal.StatusWrapperUnavailable)
	requireStatus(t, access(t, registry, "hsm-a", testTenantB, testDomainA), tenantseal.StatusUnwrapFailed)

	local, err := tenantseal.NewLocalWrapperRegistry(nil)
	if err != nil {
		t.Fatal(err)
	}
	localOnly := tenantseal.NewRoutedWrapperRegistry(local, nil)
	if _, err := localOnly.OpenDomainKEK(context.Background(), tenantseal.WrapperRef{Kind: tenantseal.WrapperKindPKCS11, ID: "hsm-a"}, wrapped, binding); !errors.Is(err, tenantseal.ErrWrapperNotConfigured) {
		t.Fatalf("pkcs11 without a signer registry = %v, want ErrWrapperNotConfigured", err)
	}
	if _, err := registry.OpenDomainKEK(context.Background(), tenantseal.WrapperRef{Kind: "cloud_kms", ID: "hsm-a"}, wrapped, binding); !errors.Is(err, tenantseal.ErrWrapperNotConfigured) {
		t.Fatalf("an unknown kind = %v, want ErrWrapperNotConfigured", err)
	}
	for name, ids := range map[string][]string{"padded": {" hsm-a"}, "empty": {""}, "duplicate": {"hsm-a", "hsm-a"}} {
		if _, err := tenantseal.NewSignerWrapperRegistry(ids, func() tenantseal.SignerTenantKEK { return signer }); !errors.Is(err, tenantseal.ErrInvalidWrapperConfig) {
			t.Errorf("%s wrapper IDs = %v, want ErrInvalidWrapperConfig", name, err)
		}
	}
	if _, err := tenantseal.NewSignerWrapperRegistry([]string{"hsm-a"}, nil); !errors.Is(err, tenantseal.ErrInvalidWrapperConfig) {
		t.Fatalf("a registry without a signer = %v", err)
	}
}

func signerRegistryWith(t *testing.T, signer func() tenantseal.SignerTenantKEK, ids ...string) *tenantseal.RoutedWrapperRegistry {
	t.Helper()
	reg, err := tenantseal.NewSignerWrapperRegistry(ids, signer)
	if err != nil {
		t.Fatal(err)
	}
	return tenantseal.NewRoutedWrapperRegistry(nil, reg)
}
