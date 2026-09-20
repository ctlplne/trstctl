// SPDX-License-Identifier: BUSL-1.1

package tenantseal_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/tenantwrap"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

const (
	testTenantA = "11111111-1111-4111-8111-111111111111"
	testTenantB = "22222222-2222-4222-8222-222222222222"
	testDomainA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
)

type fakeDomainStore struct {
	domain        *store.TenantKeyDomain
	afterCallback func()
	tenantIDs     []string
}

func (s *fakeDomainStore) WithTenantKeyDomainShared(
	_ context.Context,
	tenantID string,
	fn func(*store.TenantKeyDomain) error,
) error {
	s.tenantIDs = append(s.tenantIDs, tenantID)
	var domain *store.TenantKeyDomain
	if s.domain != nil {
		copyOfDomain := *s.domain
		copyOfDomain.WrappedDomainKEK = append([]byte(nil), s.domain.WrappedDomainKEK...)
		domain = &copyOfDomain
	}
	err := fn(domain)
	if s.afterCallback != nil {
		s.afterCallback()
	}
	return err
}

type recordingRegistry struct {
	inner  tenantseal.DomainKEKRegistry
	refs   []tenantseal.WrapperRef
	opened tenantseal.TransientDomainKEK
	err    error
}

func (r *recordingRegistry) OpenDomainKEK(
	ctx context.Context,
	ref tenantseal.WrapperRef,
	wrapped, binding []byte,
) (tenantseal.TransientDomainKEK, error) {
	r.refs = append(r.refs, ref)
	if r.err != nil {
		return nil, r.err
	}
	key, err := r.inner.OpenDomainKEK(ctx, ref, wrapped, binding)
	if err == nil {
		r.opened = key
	}
	return key, err
}

var errPoisonedWrapperCall = errors.New("test wrapper received a forbidden call")

type countingWrapper struct {
	inner        seal.KeyWrapper
	wraps        int
	unwraps      int
	poisonWrap   bool
	poisonUnwrap bool
}

func (w *countingWrapper) WrapDEK(dek []byte) ([]byte, error) {
	w.wraps++
	if w.poisonWrap {
		return nil, errPoisonedWrapperCall
	}
	return w.inner.WrapDEK(dek)
}

func (w *countingWrapper) UnwrapDEK(wrapped []byte) ([]byte, error) {
	w.unwraps++
	if w.poisonUnwrap {
		return nil, errPoisonedWrapperCall
	}
	return w.inner.UnwrapDEK(wrapped)
}

type countingTransientKey struct {
	*countingWrapper
	local     *seal.LocalKEK
	destroyed bool
}

func (k *countingTransientKey) Destroy() {
	k.destroyed = true
	k.local.Destroy()
}

type oneKeyRegistry struct {
	key  tenantseal.TransientDomainKEK
	refs []tenantseal.WrapperRef
}

func (r *oneKeyRegistry) OpenDomainKEK(
	ctx context.Context,
	ref tenantseal.WrapperRef,
	_, _ []byte,
) (tenantseal.TransientDomainKEK, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.refs = append(r.refs, ref)
	return r.key, nil
}

func TestAccessMissingDomainUsesOnlyLegacyCipherInsideLease(t *testing.T) {
	deployment := newTestKEK(t, 0x11)
	registry := &recordingRegistry{err: errors.New("registry must not be used")}
	access, err := tenantseal.NewAccess(&fakeDomainStore{}, deployment, registry)
	if err != nil {
		t.Fatalf("NewAccess: %v", err)
	}

	var escaped tenantseal.Cipher
	aad := []byte("opaque-aad;tenant=not-a-routing-instruction")
	err = access.WithTenant(context.Background(), testTenantA, func(cipher tenantseal.Cipher) error {
		escaped = cipher
		container, err := cipher.Seal([]byte("legacy payload"), aad)
		if err != nil {
			return err
		}
		domain, err := seal.Domain(container)
		if err != nil {
			return err
		}
		if domain != nil {
			return errors.New("legacy tenant wrote a tenant-domain container")
		}
		plain, err := cipher.Open(container, aad)
		if err != nil {
			return err
		}
		if !bytes.Equal(plain, []byte("legacy payload")) {
			return errors.New("legacy cipher round trip changed plaintext")
		}

		// Even a v2 container wrapped by the deployment key is not a legacy
		// record. This prevents deleting a domain row from becoming a decrypt
		// fallback.
		v2, err := seal.SealDomain(
			deployment,
			[]byte("not legacy"),
			aad,
			[]byte("forged-domain"),
		)
		if err != nil {
			return err
		}
		if _, err := cipher.Open(v2, aad); !errors.Is(err, seal.ErrDomain) {
			return errors.New("legacy cipher accepted a tenant-domain container")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithTenant legacy: %v", err)
	}
	if len(registry.refs) != 0 {
		t.Fatalf("legacy access consulted tenant wrapper registry: %+v", registry.refs)
	}
	if _, err := escaped.Seal([]byte("after callback"), nil); !errors.Is(err, tenantseal.ErrCipherLeaseExpired) {
		t.Fatalf("escaped legacy Cipher.Seal error = %v, want ErrCipherLeaseExpired", err)
	}
	if _, err := escaped.Open([]byte("after callback"), nil); !errors.Is(err, tenantseal.ErrCipherLeaseExpired) {
		t.Fatalf("escaped legacy Cipher.Open error = %v, want ErrCipherLeaseExpired", err)
	}
}

func TestAccessRequiresExplicitTenantIDBeforeStoreOrWrapperWork(t *testing.T) {
	domains := &fakeDomainStore{}
	registry := &recordingRegistry{err: errors.New("registry must not be used")}
	access, err := tenantseal.NewAccess(domains, newTestKEK(t, 0x12), registry)
	if err != nil {
		t.Fatal(err)
	}
	if err := access.WithTenant(context.Background(), "", func(tenantseal.Cipher) error {
		return errors.New("callback must not run")
	}); err == nil {
		t.Fatal("WithTenant accepted an empty tenant id")
	}
	if len(domains.tenantIDs) != 0 || len(registry.refs) != 0 {
		t.Fatalf("empty tenant reached store=%v registry=%v", domains.tenantIDs, registry.refs)
	}
}

func TestAccessCompletedHotMigrationUsesExactDomainAndDestroysBeforeFenceRelease(t *testing.T) {
	wrapperPath := writeTestWrapper(t, 0x21)
	domain := readyDomain(t, testTenantA, testDomainA, wrapperPath)
	domain.State = store.TenantKeyDomainStatePartial
	domain.LegacyHistoryExposure = store.TenantKeyLegacyExternalArchivesPossible
	localRegistry, err := tenantseal.NewLocalWrapperRegistry([]tenantseal.LocalWrapper{{
		ID:   domain.WrapperID,
		Path: wrapperPath,
	}})
	if err != nil {
		t.Fatalf("NewLocalWrapperRegistry: %v", err)
	}
	registry := &recordingRegistry{inner: localRegistry}
	deployment := newTestKEK(t, 0x22)

	var escaped tenantseal.Cipher
	fencedStore := &fakeDomainStore{domain: &domain}
	fencedStore.afterCallback = func() {
		if registry.opened == nil {
			t.Fatal("tenant key was not opened")
		}
		localKey, ok := registry.opened.(*seal.LocalKEK)
		if !ok {
			t.Fatalf("local registry returned %T, want *seal.LocalKEK", registry.opened)
		}
		if err := localKey.WithKey(func([]byte) error {
			return errors.New("tenant key remained live when the shared fence released")
		}); !errors.Is(err, secret.ErrDestroyed) {
			t.Errorf("WithKey on the released tenant key = %v, want secret.ErrDestroyed", err)
		}
		if _, err := escaped.Seal(nil, nil); !errors.Is(err, tenantseal.ErrCipherLeaseExpired) {
			t.Fatalf("cipher remained usable when the shared fence released: %v", err)
		}
	}
	access, err := tenantseal.NewAccess(fencedStore, deployment, registry)
	if err != nil {
		t.Fatalf("NewAccess: %v", err)
	}

	aad := []byte{0x00, 0xff, ';', 't', 'e', 'n', 'a', 'n', 't', '=', 'B'}
	err = access.WithTenant(context.Background(), testTenantA, func(cipher tenantseal.Cipher) error {
		escaped = cipher
		container, err := cipher.Seal([]byte("tenant payload"), aad)
		if err != nil {
			return err
		}
		wantDomain, err := tenantseal.DomainBinding(testTenantA, testDomainA, 1)
		if err != nil {
			return err
		}
		gotDomain, err := seal.Domain(container)
		if err != nil {
			return err
		}
		if !bytes.Equal(gotDomain, wantDomain) {
			return errors.New("tenant cipher wrote the wrong authenticated domain")
		}
		plain, err := cipher.Open(container, aad)
		if err != nil {
			return err
		}
		if !bytes.Equal(plain, []byte("tenant payload")) {
			return errors.New("tenant cipher round trip changed plaintext")
		}
		if _, err := cipher.Open(container, append(aad, 0x01)); err == nil {
			return errors.New("tenant cipher parsed routing from AAD instead of authenticating opaque AAD")
		}
		if _, err := seal.Open(deployment, container, aad); err == nil {
			return errors.New("tenant-domain ciphertext fell back to the deployment KEK")
		}
		legacy, err := seal.Seal(deployment, []byte("legacy row"), aad)
		if err != nil {
			return err
		}
		if _, err := cipher.Open(legacy, aad); !errors.Is(err, seal.ErrDomain) {
			return errors.New("completed hot migration accepted a legacy v1 container")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithTenant tenant domain: %v", err)
	}
	if len(registry.refs) != 1 {
		t.Fatalf("wrapper registry calls = %d, want 1", len(registry.refs))
	}
	if got := registry.refs[0]; got.Kind != tenantseal.WrapperKindLocalFile || got.ID != domain.WrapperID {
		t.Fatalf("wrapper registry ref = %+v, want exact local_file/%s", got, domain.WrapperID)
	}
}

func TestAccessMigrationDualCipherRoutesByFormatWithoutTrialFallback(t *testing.T) {
	deploymentKey := newTestKEK(t, 0x23)
	tenantKey := newTestKEK(t, 0x24)
	binding, err := tenantseal.DomainBinding(testTenantA, testDomainA, 1)
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte("opaque migration aad")
	legacy, err := seal.Seal(deploymentKey, []byte("legacy row"), aad)
	if err != nil {
		t.Fatal(err)
	}
	tenantV2, err := seal.SealDomain(tenantKey, []byte("migrated row"), aad, binding)
	if err != nil {
		t.Fatal(err)
	}
	wrongDomainV2, err := seal.SealDomain(tenantKey, []byte("wrong domain"), aad, []byte("other-domain"))
	if err != nil {
		t.Fatal(err)
	}

	deployment := &countingWrapper{
		inner:      deploymentKey,
		poisonWrap: true,
	}
	tenantCounter := &countingWrapper{
		inner:        tenantKey,
		poisonUnwrap: true,
	}
	transient := &countingTransientKey{
		countingWrapper: tenantCounter,
		local:           tenantKey,
	}
	registry := &oneKeyRegistry{key: transient}
	domain := store.TenantKeyDomain{
		TenantID:              testTenantA,
		DomainID:              testDomainA,
		Generation:            1,
		ProtectionMode:        store.TenantKeyProtectionTenantDomain,
		State:                 store.TenantKeyDomainStateMigrating,
		WrapperKind:           tenantseal.WrapperKindLocalFile,
		WrapperID:             "tenant-wrapper",
		WrappedDomainKEK:      []byte("opaque wrapped key fixture"),
		OperationKind:         store.TenantKeyOperationMigrate,
		OperationStatus:       store.TenantKeyOperationRunning,
		ProgressCompleted:     4,
		ProgressTotal:         10,
		LegacyHistoryExposure: store.TenantKeyLegacyHotHistoryPending,
	}
	fencedStore := &fakeDomainStore{domain: &domain}
	fencedStore.afterCallback = func() {
		if !transient.destroyed {
			t.Fatal("migration tenant key was not destroyed before fence release")
		}
	}
	access, err := tenantseal.NewAccess(fencedStore, deployment, registry)
	if err != nil {
		t.Fatal(err)
	}

	err = access.WithTenant(context.Background(), testTenantA, func(cipher tenantseal.Cipher) error {
		written, err := cipher.Seal([]byte("new during migration"), aad)
		if err != nil {
			return err
		}
		writtenDomain, err := seal.Domain(written)
		if err != nil {
			return err
		}
		if !bytes.Equal(writtenDomain, binding) {
			return errors.New("migration write was not tenant-domain v2")
		}
		if deployment.wraps != 0 || tenantCounter.wraps != 1 {
			return errors.New("migration write did not use tenant wrapper exactly once")
		}

		// Poisoning tenant unwrap proves a v1 read routes only to deployment.
		plain, err := cipher.Open(legacy, aad)
		if err != nil || !bytes.Equal(plain, []byte("legacy row")) {
			return errors.New("v1 migration read did not route only to deployment wrapper")
		}
		if deployment.unwraps != 1 || tenantCounter.unwraps != 0 {
			return errors.New("v1 migration read trial-opened more than the deployment wrapper")
		}

		// Poisoning deployment unwrap proves an exact v2 read routes only to the
		// transient tenant key.
		tenantCounter.poisonUnwrap = false
		deployment.poisonUnwrap = true
		plain, err = cipher.Open(tenantV2, aad)
		if err != nil || !bytes.Equal(plain, []byte("migrated row")) {
			return errors.New("v2 migration read did not route only to tenant wrapper")
		}
		if deployment.unwraps != 1 || tenantCounter.unwraps != 1 {
			return errors.New("v2 migration read trial-opened more than the tenant wrapper")
		}

		deploymentBefore, tenantBefore := deployment.unwraps, tenantCounter.unwraps
		tenantCounter.poisonUnwrap = true
		if _, err := cipher.Open(wrongDomainV2, aad); !errors.Is(err, seal.ErrDomain) {
			return errors.New("wrong-domain v2 did not fail closed")
		}
		if _, err := cipher.Open([]byte("CSL1\x02broken"), aad); err == nil {
			return errors.New("corrupt container did not fail closed")
		}
		if deployment.unwraps != deploymentBefore || tenantCounter.unwraps != tenantBefore {
			return errors.New("wrong/corrupt container reached a fallback wrapper")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithTenant migration dual cipher: %v", err)
	}
	if len(registry.refs) != 1 ||
		registry.refs[0] != (tenantseal.WrapperRef{
			Kind: tenantseal.WrapperKindLocalFile,
			ID:   "tenant-wrapper",
		}) {
		t.Fatalf("migration wrapper refs = %+v, want one exact ref", registry.refs)
	}
}

func TestAccessAllowsOnlyExplicitUsablePostures(t *testing.T) {
	tests := []struct {
		name   string
		change func(*store.TenantKeyDomain)
		want   tenantseal.Status
		usable bool
	}{
		{
			name:   "unsealed completed",
			usable: true,
		},
		{
			name: "completed partial with only external archive exposure",
			change: func(domain *store.TenantKeyDomain) {
				domain.State = store.TenantKeyDomainStatePartial
				domain.LegacyHistoryExposure = store.TenantKeyLegacyExternalArchivesPossible
			},
			usable: true,
		},
		{
			name: "partial migration still running",
			change: func(domain *store.TenantKeyDomain) {
				domain.State = store.TenantKeyDomainStatePartial
				domain.OperationStatus = store.TenantKeyOperationRunning
				domain.LegacyHistoryExposure = store.TenantKeyLegacyHotHistoryPending
			},
			usable: true,
		},
		{
			name: "partial migration incomplete",
			change: func(domain *store.TenantKeyDomain) {
				domain.State = store.TenantKeyDomainStatePartial
				domain.ProgressCompleted--
				domain.LegacyHistoryExposure = store.TenantKeyLegacyExternalArchivesPossible
			},
			want: tenantseal.StatusPartial,
		},
		{
			name: "partial migration failed",
			change: func(domain *store.TenantKeyDomain) {
				domain.State = store.TenantKeyDomainStatePartial
				domain.OperationStatus = store.TenantKeyOperationFailed
				domain.LegacyHistoryExposure = store.TenantKeyLegacyExternalArchivesPossible
			},
			usable: true,
		},
		{
			name: "partial tenant-only domain after seal failed",
			change: func(domain *store.TenantKeyDomain) {
				domain.State = store.TenantKeyDomainStatePartial
				domain.OperationKind = store.TenantKeyOperationSeal
				domain.OperationStatus = store.TenantKeyOperationFailed
				domain.Retryable = true
				domain.LegacyHistoryExposure = store.TenantKeyLegacyExternalArchivesPossible
			},
			usable: true,
		},
		{
			name: "unsealed tenant-only domain after seal failed",
			change: func(domain *store.TenantKeyDomain) {
				domain.OperationKind = store.TenantKeyOperationSeal
				domain.OperationStatus = store.TenantKeyOperationFailed
				domain.Retryable = true
			},
			usable: true,
		},
		{
			name: "seal failure without retryable proof",
			change: func(domain *store.TenantKeyDomain) {
				domain.State = store.TenantKeyDomainStatePartial
				domain.OperationKind = store.TenantKeyOperationSeal
				domain.OperationStatus = store.TenantKeyOperationFailed
				domain.LegacyHistoryExposure = store.TenantKeyLegacyExternalArchivesPossible
			},
			want: tenantseal.StatusPartial,
		},
		{
			name: "migrating",
			change: func(domain *store.TenantKeyDomain) {
				domain.State = store.TenantKeyDomainStateMigrating
				domain.OperationStatus = store.TenantKeyOperationRunning
				domain.LegacyHistoryExposure = store.TenantKeyLegacyHotHistoryPending
			},
			usable: true,
		},
		{
			name: "migrating with invalid completed posture",
			change: func(domain *store.TenantKeyDomain) {
				domain.State = store.TenantKeyDomainStateMigrating
				domain.LegacyHistoryExposure = store.TenantKeyLegacyHotHistoryPending
			},
			want: tenantseal.StatusMigrating,
		},
		{
			name: "sealed",
			change: func(domain *store.TenantKeyDomain) {
				domain.State = store.TenantKeyDomainStateSealed
			},
			want: tenantseal.StatusSealed,
		},
		{
			name: "sealing",
			change: func(domain *store.TenantKeyDomain) {
				domain.State = store.TenantKeyDomainStateSealing
				domain.OperationStatus = store.TenantKeyOperationRunning
			},
			want: tenantseal.StatusSealing,
		},
		{
			name: "unsealing",
			change: func(domain *store.TenantKeyDomain) {
				domain.State = store.TenantKeyDomainStateUnsealing
				domain.OperationStatus = store.TenantKeyOperationRunning
			},
			want: tenantseal.StatusUnsealing,
		},
		{
			name: "wrapper unavailable state",
			change: func(domain *store.TenantKeyDomain) {
				domain.State = store.TenantKeyDomainStateWrapperUnavailable
			},
			want: tenantseal.StatusWrapperUnavailable,
		},
		{
			name: "wrong wrapper state",
			change: func(domain *store.TenantKeyDomain) {
				domain.State = store.TenantKeyDomainStateWrongWrapper
			},
			want: tenantseal.StatusWrongWrapper,
		},
		{
			name: "corrupt state",
			change: func(domain *store.TenantKeyDomain) {
				domain.State = store.TenantKeyDomainStateCorrupt
			},
			want: tenantseal.StatusCorrupt,
		},
		{
			name: "unsealed operation not completed",
			change: func(domain *store.TenantKeyDomain) {
				domain.OperationStatus = store.TenantKeyOperationRunning
			},
			want: tenantseal.StatusCorrupt,
		},
		{
			name: "unsealed with hot history pending",
			change: func(domain *store.TenantKeyDomain) {
				domain.LegacyHistoryExposure = store.TenantKeyLegacyHotHistoryPending
			},
			want: tenantseal.StatusCorrupt,
		},
		{
			name: "completed partial without external archive posture",
			change: func(domain *store.TenantKeyDomain) {
				domain.State = store.TenantKeyDomainStatePartial
			},
			want: tenantseal.StatusPartial,
		},
		{
			name: "unknown state",
			change: func(domain *store.TenantKeyDomain) {
				domain.State = "invented"
			},
			want: tenantseal.StatusCorrupt,
		},
		{
			name: "usable state missing wrapper id",
			change: func(domain *store.TenantKeyDomain) {
				domain.WrapperID = ""
			},
			want: tenantseal.StatusCorrupt,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wrapperPath := writeTestWrapper(t, 0x31)
			domain := readyDomain(t, testTenantA, testDomainA, wrapperPath)
			if test.change != nil {
				test.change(&domain)
			}
			localRegistry, err := tenantseal.NewLocalWrapperRegistry([]tenantseal.LocalWrapper{{
				ID: "tenant-wrapper", Path: wrapperPath,
			}})
			if err != nil {
				t.Fatal(err)
			}
			registry := &recordingRegistry{inner: localRegistry}
			access, err := tenantseal.NewAccess(
				&fakeDomainStore{domain: &domain},
				newTestKEK(t, 0x32),
				registry,
			)
			if err != nil {
				t.Fatal(err)
			}
			called := false
			err = access.WithTenant(context.Background(), testTenantA, func(tenantseal.Cipher) error {
				called = true
				return nil
			})
			if test.usable {
				if err != nil || !called || len(registry.refs) != 1 {
					t.Fatalf("usable posture returned err=%v called=%v registry_calls=%d", err, called, len(registry.refs))
				}
				return
			}
			if called {
				t.Fatal("fail-closed posture invoked the crypto callback")
			}
			requireStatus(t, err, test.want)
			if len(registry.refs) != 0 {
				t.Fatalf("fail-closed posture opened a wrapper: %+v", registry.refs)
			}
		})
	}
}

func TestAccessRejectsCrossTenantRowBeforeWrapperSelection(t *testing.T) {
	wrapperPath := writeTestWrapper(t, 0x41)
	domainA := readyDomain(t, testTenantA, testDomainA, wrapperPath)
	registry := &recordingRegistry{err: errors.New("must not be reached")}
	access, err := tenantseal.NewAccess(
		&fakeDomainStore{domain: &domainA},
		newTestKEK(t, 0x42),
		registry,
	)
	if err != nil {
		t.Fatal(err)
	}

	called := false
	err = access.WithTenant(context.Background(), testTenantB, func(tenantseal.Cipher) error {
		called = true
		return nil
	})
	if called {
		t.Fatal("cross-tenant row reached crypto callback")
	}
	requireStatus(t, err, tenantseal.StatusCorrupt)
	if len(registry.refs) != 0 {
		t.Fatalf("cross-tenant row selected a wrapper: %+v", registry.refs)
	}
}

func TestAccessClassifiesWrapperUnavailableCorruptAndAuthenticatedUnwrapFailure(t *testing.T) {
	wrapperPath := writeTestWrapper(t, 0x51)
	domain := readyDomain(t, testTenantA, testDomainA, wrapperPath)
	deployment := newTestKEK(t, 0x52)

	t.Run("unavailable exact wrapper id", func(t *testing.T) {
		registry, err := tenantseal.NewLocalWrapperRegistry(nil)
		if err != nil {
			t.Fatal(err)
		}
		access, err := tenantseal.NewAccess(&fakeDomainStore{domain: &domain}, deployment, registry)
		if err != nil {
			t.Fatal(err)
		}
		err = access.WithTenant(context.Background(), testTenantA, func(tenantseal.Cipher) error {
			return errors.New("callback must not run")
		})
		requireStatus(t, err, tenantseal.StatusWrapperUnavailable)
	})

	t.Run("corrupt wrapped representation", func(t *testing.T) {
		corrupt := domain
		corrupt.WrappedDomainKEK = append([]byte(nil), domain.WrappedDomainKEK...)
		corrupt.WrappedDomainKEK[len(corrupt.WrappedDomainKEK)-1] ^= 0xff
		registry, err := tenantseal.NewLocalWrapperRegistry([]tenantseal.LocalWrapper{{
			ID: domain.WrapperID, Path: wrapperPath,
		}})
		if err != nil {
			t.Fatal(err)
		}
		access, err := tenantseal.NewAccess(&fakeDomainStore{domain: &corrupt}, deployment, registry)
		if err != nil {
			t.Fatal(err)
		}
		err = access.WithTenant(context.Background(), testTenantA, func(tenantseal.Cipher) error {
			return errors.New("callback must not run")
		})
		requireStatus(t, err, tenantseal.StatusCorrupt)
	})

	t.Run("authenticated unwrap failure is not guessed to be wrong wrapper", func(t *testing.T) {
		wrongWrapperPath := writeTestWrapper(t, 0x53)
		registry, err := tenantseal.NewLocalWrapperRegistry([]tenantseal.LocalWrapper{{
			ID: domain.WrapperID, Path: wrongWrapperPath,
		}})
		if err != nil {
			t.Fatal(err)
		}
		access, err := tenantseal.NewAccess(&fakeDomainStore{domain: &domain}, deployment, registry)
		if err != nil {
			t.Fatal(err)
		}
		err = access.WithTenant(context.Background(), testTenantA, func(tenantseal.Cipher) error {
			return errors.New("callback must not run")
		})
		requireStatus(t, err, tenantseal.StatusUnwrapFailed)
		if status, _ := tenantseal.StatusOf(err); status == tenantseal.StatusWrongWrapper {
			t.Fatal("authenticated unwrap failure was falsely reported as a proven wrong wrapper")
		}
	})
}

func TestLocalWrapperRegistryRequiresExactKindAndID(t *testing.T) {
	wrapperPath := writeTestWrapper(t, 0x61)
	binding, err := tenantseal.DomainBinding(testTenantA, testDomainA, 1)
	if err != nil {
		t.Fatal(err)
	}
	created, wrapped, err := tenantwrap.CreateDomainKEK(wrapperPath, binding)
	if err != nil {
		t.Fatal(err)
	}
	created.Destroy()

	registry, err := tenantseal.NewLocalWrapperRegistry([]tenantseal.LocalWrapper{{
		ID: "only-this-id", Path: wrapperPath,
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range []tenantseal.WrapperRef{
		{Kind: "some_other_kind", ID: "only-this-id"},
		{Kind: tenantseal.WrapperKindLocalFile, ID: "other-id"},
		{Kind: "", ID: "only-this-id"},
	} {
		if _, err := registry.OpenDomainKEK(context.Background(), ref, wrapped, binding); !errors.Is(err, tenantseal.ErrWrapperNotConfigured) {
			t.Fatalf("OpenDomainKEK(%+v) error = %v, want ErrWrapperNotConfigured", ref, err)
		}
	}

	opened, err := registry.OpenDomainKEK(
		context.Background(),
		tenantseal.WrapperRef{Kind: tenantseal.WrapperKindLocalFile, ID: "only-this-id"},
		wrapped,
		binding,
	)
	if err != nil {
		t.Fatalf("OpenDomainKEK exact ref: %v", err)
	}
	opened.Destroy()

	createdByRegistry, registryWrapped, err := registry.CreateDomainKEK(
		context.Background(),
		tenantseal.WrapperRef{Kind: tenantseal.WrapperKindLocalFile, ID: "only-this-id"},
		binding,
	)
	if err != nil {
		t.Fatalf("CreateDomainKEK exact ref: %v", err)
	}
	createdByRegistry.Destroy()
	reopened, err := registry.OpenDomainKEK(
		context.Background(),
		tenantseal.WrapperRef{Kind: tenantseal.WrapperKindLocalFile, ID: "only-this-id"},
		registryWrapped,
		binding,
	)
	if err != nil {
		t.Fatalf("OpenDomainKEK registry-created key: %v", err)
	}
	reopened.Destroy()
}

func readyDomain(t *testing.T, tenantID, domainID, wrapperPath string) store.TenantKeyDomain {
	t.Helper()
	binding, err := tenantseal.DomainBinding(tenantID, domainID, 1)
	if err != nil {
		t.Fatal(err)
	}
	domainKey, wrapped, err := tenantwrap.CreateDomainKEK(wrapperPath, binding)
	if err != nil {
		t.Fatalf("CreateDomainKEK: %v", err)
	}
	domainKey.Destroy()
	return store.TenantKeyDomain{
		TenantID:              tenantID,
		DomainID:              domainID,
		Generation:            1,
		ProtectionMode:        store.TenantKeyProtectionTenantDomain,
		State:                 store.TenantKeyDomainStateUnsealed,
		WrapperKind:           tenantseal.WrapperKindLocalFile,
		WrapperID:             "tenant-wrapper",
		WrappedDomainKEK:      wrapped,
		OperationKind:         store.TenantKeyOperationMigrate,
		OperationStatus:       store.TenantKeyOperationCompleted,
		ProgressCompleted:     10,
		ProgressTotal:         10,
		LegacyHistoryExposure: store.TenantKeyLegacyNone,
	}
}

func newTestKEK(t *testing.T, fill byte) *seal.LocalKEK {
	t.Helper()
	raw := bytes.Repeat([]byte{fill}, 32)
	key, err := seal.NewLocalKEK(raw)
	secret.Wipe(raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	return key
}

func writeTestWrapper(t *testing.T, fill byte) string {
	t.Helper()
	raw := bytes.Repeat([]byte{fill}, 32)
	defer secret.Wipe(raw)
	path := filepath.Join(t.TempDir(), "operator-wrapper.key")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func requireStatus(t *testing.T, err error, want tenantseal.Status) {
	t.Helper()
	got, ok := tenantseal.StatusOf(err)
	if !ok || got != want {
		t.Fatalf("StatusOf(%v) = %q, %v; want %q, true", err, got, ok, want)
	}
}
