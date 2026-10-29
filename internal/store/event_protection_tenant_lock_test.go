// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/store"
)

func TestEventProtectionTenantGrantSerializesActivationAndEveryKey(t *testing.T) {
	s, err := store.Open(t.Context(), testDSN, store.WithPoolSizes(store.PoolSizes{Lock: 1}), store.WithAcquireTimeout(100*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	replica, err := store.Open(t.Context(), testDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(replica.Close)
	tenant := "d59b4292-1adc-4d43-a405-781f95b1779c"
	key := eventprotect.KeyRef{TenantID: tenant, ID: "02f0b795-3f17-46a9-a9cc-a7bdd7ee21eb"}
	var retained context.Context
	err = s.WithTenantEventProtection(t.Context(), tenant, func(granted context.Context) error {
		retained = granted
		// Nested custody must borrow the same session, rather than consuming
		// another bounded pool connection or deadlocking on its own lock.
		if err := s.WithKeyLock(granted, key, func(context.Context) error { return nil }); err != nil {
			return err
		}
		alias := key
		alias.TenantID = strings.ToUpper(tenant)
		if err := s.WithKeyLock(granted, alias, func(context.Context) error { return nil }); err != nil {
			return err
		}
		otherKey := key
		otherKey.ID = "262844c2-dc6b-446c-a1c4-042b2dca5285"
		called := false
		if err := replica.WithKeyLock(t.Context(), otherKey, func(context.Context) error { called = true; return nil }); !errors.Is(err, store.ErrDatastoreBusy) || called {
			t.Fatalf("another key bypassed the tenant activation fence: %v", err)
		}
		for _, attempt := range []func() error{
			func() error {
				return replica.WithTenantEventProtection(granted, tenant, func(context.Context) error { t.Fatal("grant crossed stores"); return nil })
			},
			func() error {
				return s.WithTenantEventProtection(granted, "2c14fe81-1956-4e9d-a174-e27a38e8e979", func(context.Context) error { t.Fatal("grant crossed tenants"); return nil })
			},
		} {
			if err := attempt(); err == nil {
				t.Fatal("foreign tenant grant accepted")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.WithKeyLock(retained, key, func(context.Context) error { t.Fatal("expired grant reached custody"); return nil }); err == nil {
		t.Fatal("expired grant accepted")
	}
	if err := replica.WithKeyLock(t.Context(), key, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("tenant fence leaked: %v", err)
	}
}

func TestEventProtectionTenantGrantReleasesAfterCallbackError(t *testing.T) {
	s := newStore(t)
	tenant := "d59b4292-1adc-4d43-a405-781f95b1779c"
	want := errors.New("activation refused")
	if err := s.WithTenantEventProtection(t.Context(), tenant, func(context.Context) error { return want }); !errors.Is(err, want) {
		t.Fatal(err)
	}
	if err := s.WithTenantEventProtection(t.Context(), tenant, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestEventProtectionNestedGrantHonorsCancellation(t *testing.T) {
	s := newStore(t)
	tenant := "d59b4292-1adc-4d43-a405-781f95b1779c"
	if err := s.WithTenantEventProtection(t.Context(), tenant, func(granted context.Context) error {
		canceled, stop := context.WithCancel(granted)
		stop()
		called := false
		err := s.WithTenantEventProtection(canceled, tenant, func(context.Context) error { called = true; return nil })
		if !errors.Is(err, context.Canceled) || called {
			t.Fatalf("canceled nested operation reached protected work: %v called=%v", err, called)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestEventProtectionSharesOneLockSessionWithServiceAndProjection(t *testing.T) {
	s, err := store.Open(t.Context(), testDSN, store.WithPoolSizes(store.PoolSizes{Lock: 1}), store.WithAcquireTimeout(100*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	tenant := "d59b4292-1adc-4d43-a405-781f95b1779c"
	service, release, err := s.BeginTenantService(t.Context(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	for _, outer := range []struct {
		name string
		run  func(context.Context, func(context.Context) error) error
	}{
		{"service", func(ctx context.Context, fn func(context.Context) error) error { return fn(ctx) }},
		{"projection", s.WithProjectionLock},
		{"issuance", func(ctx context.Context, fn func(context.Context) error) error {
			return s.WithIdentityIssuanceFence(ctx, tenant, "test-identity", fn)
		}},
	} {
		t.Run(outer.name, func(t *testing.T) {
			if err := outer.run(service, func(outerCtx context.Context) error {
				return s.WithTenantEventProtection(outerCtx, tenant, func(keyCtx context.Context) error {
					return s.WithProjectionLock(keyCtx, func(context.Context) error { return nil })
				})
			}); err != nil {
				t.Fatalf("nested custody consumed another lock-pool session: %v", err)
			}
		})
	}
}

func TestEventProtectionRefusesForeignAndExpiredParentSessions(t *testing.T) {
	s := newStore(t)
	replica, err := store.Open(t.Context(), testDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(replica.Close)
	tenant := "d59b4292-1adc-4d43-a405-781f95b1779c"
	var projection, custody context.Context
	if err := s.WithProjectionLock(t.Context(), func(projectCtx context.Context) error {
		projection = projectCtx
		if err := replica.WithTenantEventProtection(projectCtx, tenant, func(context.Context) error { t.Fatal("projection session crossed stores"); return nil }); err == nil {
			t.Fatal("foreign projection session accepted by custody")
		}
		if err := replica.WithProjectionLock(projectCtx, func(context.Context) error { t.Fatal("projection session crossed stores"); return nil }); err == nil {
			t.Fatal("foreign projection session accepted by projection")
		}
		return s.WithTenantEventProtection(projectCtx, tenant, func(keyCtx context.Context) error { custody = keyCtx; return nil })
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenantEventProtection(projection, tenant, func(context.Context) error { t.Fatal("expired projection reached custody"); return nil }); err == nil {
		t.Fatal("expired projection session accepted")
	}
	if err := s.WithProjectionLock(custody, func(context.Context) error { t.Fatal("expired custody reached projection"); return nil }); err == nil {
		t.Fatal("expired custody session accepted")
	}
	service, release, err := s.BeginTenantService(t.Context(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err := s.WithTenantEventProtection(service, "2c14fe81-1956-4e9d-a174-e27a38e8e979", func(context.Context) error { t.Fatal("service session crossed tenants"); return nil }); err == nil {
		t.Fatal("foreign service tenant accepted")
	}
}

func TestEventProtectionSharedProjectionSessionRejectsConcurrentUse(t *testing.T) {
	s := newStore(t)
	tenant := "d59b4292-1adc-4d43-a405-781f95b1779c"
	if err := s.WithProjectionLock(t.Context(), func(projectCtx context.Context) error {
		entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
		go func() {
			done <- s.WithTenantEventProtection(projectCtx, tenant, func(context.Context) error { close(entered); <-release; return nil })
		}()
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			close(release)
			t.Fatal("first custody callback did not enter")
		}
		called := false
		err := s.WithTenantEventProtection(projectCtx, tenant, func(context.Context) error { called = true; return nil })
		close(release)
		if first := <-done; first != nil {
			return first
		}
		if !errors.Is(err, store.ErrDatastoreBusy) || called {
			t.Fatalf("shared PostgreSQL session allowed concurrent custody: %v called=%v", err, called)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
