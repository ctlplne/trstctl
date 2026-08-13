// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	corestore "trstctl.com/trstctl/internal/store"
)

const aud60ProviderCredential = "Bearer aud60-provider-operator"

// aud60SnapshotStore makes every customer inventory touch observable. A denied
// path must never appear here: even a count query can disclose whether another
// provider customer's estate exists.
type aud60SnapshotStore struct {
	Store
	snapshots map[string]TenantSnapshot
	errors    map[string]error
	askedFor  []string
}

func (s *aud60SnapshotStore) DirectTenantSnapshot(_ context.Context, tenantID string) (TenantSnapshot, error) {
	s.askedFor = append(s.askedFor, tenantID)
	if err := s.errors[tenantID]; err != nil {
		return TenantSnapshot{}, err
	}
	snapshot, ok := s.snapshots[tenantID]
	if !ok {
		return TenantSnapshot{}, ErrNotFound
	}
	return snapshot, nil
}

func aud60HealthRequest(handler http.Handler, customer string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/provider/v1/tenants/"+customer+"/health", nil)
	req.Header.Set("Authorization", aud60ProviderCredential)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func aud60HealthHandler(t *testing.T, store Store, delegations StaticDelegations) http.Handler {
	t.Helper()
	return NewHandler(Config{
		License:       providerLicense(t, 10),
		Store:         store,
		Authenticator: stubAuth{accept: aud60ProviderCredential},
		Delegations:   delegations,
	})
}

func TestAUD60ProviderHealthAuthorizesBeforeCustomerRLSRead(t *testing.T) {
	store := &aud60SnapshotStore{
		Store: NewMemStore(),
		snapshots: map[string]TenantSnapshot{
			"tenant-alpha": {TenantID: "tenant-alpha", Health: "healthy", ActiveCertificates: 2},
			"tenant-bravo": {TenantID: "tenant-bravo", Health: "no_certificates", ActiveCertificates: 0},
		},
		errors: map[string]error{"tenant-error": errors.New("database unavailable")},
	}
	handler := aud60HealthHandler(t, store, StaticDelegations{
		{OperatorID: "op-1", CustomerID: "tenant-alpha", Operations: []Operation{OpRead}},
		{OperatorID: "op-1", CustomerID: "tenant-bravo", Operations: []Operation{OpRead}},
		{OperatorID: "op-1", CustomerID: "tenant-error", Operations: []Operation{OpRead}},
		{OperatorID: "op-1", CustomerID: "tenant-missing", Operations: []Operation{OpRead}},
	})

	for _, customer := range []string{"tenant-alpha", "tenant-bravo"} {
		response := aud60HealthRequest(handler, customer)
		if response.Code != http.StatusOK {
			t.Fatalf("delegated customer %s health = %d body=%s", customer, response.Code, response.Body.String())
		}
		var snapshot TenantSnapshot
		if err := json.Unmarshal(response.Body.Bytes(), &snapshot); err != nil {
			t.Fatal(err)
		}
		if snapshot.TenantID != customer {
			t.Fatalf("health response customer = %q, want %q", snapshot.TenantID, customer)
		}
	}

	before := len(store.askedFor)
	denied := aud60HealthRequest(handler, "tenant-charlie")
	if denied.Code != http.StatusForbidden {
		t.Fatalf("undelegated customer health = %d body=%s, want 403", denied.Code, denied.Body.String())
	}
	if got := store.askedFor[before:]; len(got) != 0 {
		t.Fatalf("undelegated customer reached snapshot storage: %v", got)
	}

	wrongOperation := aud60HealthHandler(t, store, StaticDelegations{
		{OperatorID: "op-1", CustomerID: "tenant-alpha", Operations: []Operation{OpSuspend}},
	})
	before = len(store.askedFor)
	denied = aud60HealthRequest(wrongOperation, "tenant-alpha")
	if denied.Code != http.StatusForbidden {
		t.Fatalf("suspend-only grant read customer health with status %d", denied.Code)
	}
	if got := store.askedFor[before:]; len(got) != 0 {
		t.Fatalf("wrong-operation grant reached snapshot storage: %v", got)
	}

	unavailable := aud60HealthRequest(handler, "tenant-error")
	if unavailable.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable customer health = %d body=%s, want explicit 503", unavailable.Code, unavailable.Body.String())
	}
	missing := aud60HealthRequest(handler, "tenant-missing")
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing delegated customer health = %d body=%s, want explicit 404", missing.Code, missing.Body.String())
	}
}

func TestAUD60ProviderHealthSurvivesRestartAndIsolatesCertificateCounts(t *testing.T) {
	ctx := t.Context()
	firstStore := openProviderStore(t)
	alpha := CustomerID("aud60-alpha")
	bravo := CustomerID("aud60-bravo")
	other := CustomerID("aud60-other")
	projectTenantFixture(t, firstStore, Tenant{ID: alpha, Slug: "aud60-alpha", Name: "Alpha", Status: TenantActive})
	projectTenantFixture(t, firstStore, Tenant{ID: bravo, Slug: "aud60-bravo", Name: "Bravo", Status: TenantSuspended})
	projectTenantFixture(t, firstStore, Tenant{ID: other, Slug: "aud60-other", Name: "Other", Status: TenantActive})
	seedCert(t, firstStore, alpha, "aud60-alpha-active-a", "active")
	seedCert(t, firstStore, alpha, "aud60-alpha-active-b", "active")
	seedCert(t, firstStore, alpha, "aud60-alpha-revoked", "revoked")
	seedCert(t, firstStore, bravo, "aud60-bravo-active", "active")
	for _, fingerprint := range []string{"aud60-other-a", "aud60-other-b", "aud60-other-c"} {
		seedCert(t, firstStore, other, fingerprint, "active")
	}
	firstStore.Close()

	restartedStore, err := corestore.Open(ctx, providerTestDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restartedStore.Close)
	handler := aud60HealthHandler(t, NewPGStore(restartedStore), StaticDelegations{
		{OperatorID: "op-1", CustomerID: alpha, Operations: []Operation{OpRead}},
		{OperatorID: "op-1", CustomerID: bravo, Operations: []Operation{OpRead}},
	})

	for _, test := range []struct {
		customer string
		health   string
		active   int
	}{
		{customer: alpha, health: "healthy", active: 2},
		{customer: bravo, health: "suspended", active: 1},
	} {
		response := aud60HealthRequest(handler, test.customer)
		if response.Code != http.StatusOK {
			t.Fatalf("health after restart for %s = %d body=%s", test.customer, response.Code, response.Body.String())
		}
		var snapshot TenantSnapshot
		if err := json.Unmarshal(response.Body.Bytes(), &snapshot); err != nil {
			t.Fatal(err)
		}
		if snapshot.TenantID != test.customer || snapshot.Health != test.health || snapshot.ActiveCertificates != test.active {
			t.Fatalf("isolated health for %s = %+v, want health=%s active=%d", test.customer, snapshot, test.health, test.active)
		}
	}

	denied := aud60HealthRequest(handler, other)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("another customer's three certificates leaked with status %d body=%s", denied.Code, denied.Body.String())
	}
}
