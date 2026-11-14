// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// nativeExpiryProvider is a provider whose lease credentials expire in their
// backend (A239-L2: an LDAP dynamic entry). It records each refresh and
// refuses one while refuse is set.
type nativeExpiryProvider struct {
	issueOutboxProvider
	refuse    error
	refreshes []nativeExpiryRefresh
}

type nativeExpiryRefresh struct {
	ref string
	ttl time.Duration
	at  time.Time
}

func (p *nativeExpiryProvider) RefreshLeaseCredential(_ context.Context, ref string, ttl time.Duration) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refreshes = append(p.refreshes, nativeExpiryRefresh{ref: ref, ttl: ttl, at: time.Now()})
	return p.refuse
}

func (p *nativeExpiryProvider) setRefuse(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refuse = err
}

func (p *nativeExpiryProvider) Refreshes() []nativeExpiryRefresh {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]nativeExpiryRefresh(nil), p.refreshes...)
}

// TestDynamicSecretRenewalMovesTheBackendExpiryA239L2 is A239-L2's lifecycle
// proof: when a lease's credential expires in its backend (an LDAP dynamic
// entry), each renewal — the API's bound renewal and the direct one — asks
// the backend to keep the credential until the renewed expiry before the
// renewal is recorded. A backend that refuses (it would keep the credential
// for less) fails the renewal and the lease keeps its expiry, so trstctl never
// records a lease its backend will end early; the same bound renewal retried
// once the backend keeps it succeeds.
func TestDynamicSecretRenewalMovesTheBackendExpiryA239L2(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111239"
	ctx := context.Background()
	st, log, kek, outbox, _, _ := newDynamicSecretOutboxTestStack(t, tenant)
	provider := &nativeExpiryProvider{issueOutboxProvider: issueOutboxProvider{name: "ldap-dynamic", providerType: "ldap"}}
	now := time.Now().UTC().Truncate(time.Microsecond)
	seed := func(id string) store.DynamicSecretLease {
		t.Helper()
		pending := projections.DynamicSecretLeasePending{
			ID: id, IdempotencyKey: "issue-" + id, RequestBinding: "sha256:issue-" + id,
			Provider: provider.name, Role: "readonly",
			ExpiresAt: now.Add(20 * time.Minute), HardExpiresAt: now.Add(2 * time.Hour),
		}
		data, err := json.Marshal(pending)
		if err != nil {
			t.Fatal(err)
		}
		event, err := log.Append(ctx, events.Event{Type: projections.EventDynamicSecretLeasePending,
			TenantID: tenant, Time: now.Add(-time.Minute), Data: data})
		if err != nil {
			t.Fatal(err)
		}
		if err := projections.New(st).Apply(ctx, event); err != nil {
			t.Fatal(err)
		}
		record, err := st.GetDynamicSecretLease(ctx, tenant, id)
		if err != nil {
			t.Fatal(err)
		}
		record.BackendRef = "uid=trstctl-readonly-" + id + ",ou=leases,dc=lab,dc=test"
		if err := st.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			return st.ApplyDynamicSecretLeaseIssuedTx(ctx, tx, store.DynamicSecretLease{
				ID: record.ID, TenantID: tenant, TenantEpoch: record.TenantEpoch,
				IdempotencyKey: record.IdempotencyKey, RequestBinding: record.RequestBinding,
				Provider: record.Provider, Role: record.Role, BackendRef: record.BackendRef,
				SealedCredential: []byte("sealed-lease-credential"),
				IssuedAt:         now, ExpiresAt: record.ExpiresAt, HardExpiresAt: record.HardExpiresAt,
				UpdatedAt: now,
			})
		}); err != nil {
			t.Fatal(err)
		}
		record, err = st.GetDynamicSecretLease(ctx, tenant, id)
		if err != nil || record.State != store.DynamicSecretLeaseActive {
			t.Fatalf("seeded lease %s is %s (%v), want active", id, record.State, err)
		}
		return record
	}
	expiryOf := func(id string) time.Time {
		t.Helper()
		record, err := st.GetDynamicSecretLease(ctx, tenant, id)
		if err != nil {
			t.Fatal(err)
		}
		return record.ExpiresAt
	}
	checkRefresh := func(got nativeExpiryRefresh, lease store.DynamicSecretLease, until time.Time) {
		t.Helper()
		if drift := got.at.Add(got.ttl).Sub(until); got.ref != lease.BackendRef || drift < -time.Second || drift > time.Second {
			t.Fatalf("the backend was asked to keep %q for %s from %s; want %q until %s", got.ref, got.ttl, got.at, lease.BackendRef, until)
		}
	}
	lifecycle, err := newDurableDynamicSecretLifecycle(tenant, []dynsecret.Provider{provider}, st, log, kek, outbox, func() {})
	if err != nil {
		t.Fatal(err)
	}

	// The API's bound renewal moves the backend's expiry, then records it.
	bound := seed("lease-a239l2-bound")
	want := bound.ExpiresAt.Add(10 * time.Minute)
	renewed, err := lifecycle.RenewBound(ctx, bound.ID, 10*time.Minute, "a239l2-renew-bound", "sha256:a239l2-renew-bound")
	if err != nil || !renewed.ExpiresAt.Equal(want) {
		t.Fatalf("bound renewal expires %s (%v), want %s", renewed.ExpiresAt, err, want)
	}
	if refreshes := provider.Refreshes(); len(refreshes) != 1 {
		t.Fatalf("a bound renewal refreshed the backend %d times, want once", len(refreshes))
	} else {
		checkRefresh(refreshes[0], bound, want)
	}
	if got := expiryOf(bound.ID); !got.Equal(want) {
		t.Fatalf("the renewed lease reads expiry %s, want %s", got, want)
	}

	// So does the direct renewal.
	direct := seed("lease-a239l2-direct")
	want = direct.ExpiresAt.Add(5 * time.Minute)
	if renewed, err := lifecycle.Renew(ctx, direct.ID, 5*time.Minute); err != nil || !renewed.ExpiresAt.Equal(want) {
		t.Fatalf("direct renewal expires %s (%v), want %s", renewed.ExpiresAt, err, want)
	}
	if refreshes := provider.Refreshes(); len(refreshes) != 2 {
		t.Fatalf("a direct renewal left %d refreshes, want 2", len(refreshes))
	} else {
		checkRefresh(refreshes[1], direct, want)
	}

	// A backend that would keep the credential for less fails the renewal;
	// the lease keeps its expiry on both paths.
	refused := seed("lease-a239l2-refused")
	provider.setRefuse(dynsecret.ErrLDAPDynamicTTLShortened)
	if _, err := lifecycle.RenewBound(ctx, refused.ID, 10*time.Minute, "a239l2-renew-refused", "sha256:a239l2-renew-refused"); !errors.Is(err, dynsecret.ErrLDAPDynamicTTLShortened) {
		t.Fatalf("a bound renewal the backend refused returned %v", err)
	}
	if _, err := lifecycle.Renew(ctx, refused.ID, 10*time.Minute); !errors.Is(err, dynsecret.ErrLDAPDynamicTTLShortened) {
		t.Fatalf("a direct renewal the backend refused returned %v", err)
	}
	if got := expiryOf(refused.ID); !got.Equal(refused.ExpiresAt) {
		t.Fatalf("a refused renewal moved the lease to %s, want it kept at %s", got, refused.ExpiresAt)
	}

	// The same bound renewal, retried once the backend keeps it, succeeds.
	provider.setRefuse(nil)
	want = refused.ExpiresAt.Add(10 * time.Minute)
	if renewed, err := lifecycle.RenewBound(ctx, refused.ID, 10*time.Minute, "a239l2-renew-refused", "sha256:a239l2-renew-refused"); err != nil || !renewed.ExpiresAt.Equal(want) {
		t.Fatalf("the retried renewal expires %s (%v), want %s", renewed.ExpiresAt, err, want)
	}
	refreshes := provider.Refreshes()
	if len(refreshes) != 5 {
		t.Fatalf("refreshes = %d, want 5 (two kept, two refused, one retried)", len(refreshes))
	}
	checkRefresh(refreshes[4], refused, want)
	if got := expiryOf(refused.ID); !got.Equal(want) {
		t.Fatalf("the retried renewal left expiry %s, want %s", got, want)
	}
	t.Logf("A239L2_LIFECYCLE_OK refreshes=%d", len(refreshes))
}
