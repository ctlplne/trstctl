// SPDX-License-Identifier: MPL-2.0

package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

type fakeTenantKeyDomainLifecycle struct {
	domain       store.TenantKeyDomain
	statusErr    error
	migrateErr   error
	unsealErr    error
	migrateCalls int
	unsealCalls  int
	tenantIDs    []string
	refs         []tenantseal.WrapperRef
}

func (f *fakeTenantKeyDomainLifecycle) Status(_ context.Context, tenantID string) (store.TenantKeyDomain, error) {
	f.tenantIDs = append(f.tenantIDs, tenantID)
	return f.domain, f.statusErr
}

func (f *fakeTenantKeyDomainLifecycle) Migrate(_ context.Context, tenantID string, ref tenantseal.WrapperRef) (store.TenantKeyDomain, error) {
	f.migrateCalls++
	f.tenantIDs = append(f.tenantIDs, tenantID)
	f.refs = append(f.refs, ref)
	return f.domain, f.migrateErr
}

func (f *fakeTenantKeyDomainLifecycle) Seal(context.Context, string) (store.TenantKeyDomain, error) {
	return store.TenantKeyDomain{}, errors.New("seal is intentionally asynchronous and not served by this slice")
}

func (f *fakeTenantKeyDomainLifecycle) Unseal(_ context.Context, tenantID string) (store.TenantKeyDomain, error) {
	f.unsealCalls++
	f.tenantIDs = append(f.tenantIDs, tenantID)
	return f.domain, f.unsealErr
}

func TestTenantKeyDomainStatusReportsLegacyAndSanitizesFailures(t *testing.T) {
	legacy := &fakeTenantKeyDomainLifecycle{statusErr: store.ErrTenantKeyDomainNotFound}
	handler := api.New(nil, orchestrator.NewMemoryIdempotency(), nil,
		api.WithInsecureHeaderResolver(), api.WithTenantKeyDomainLifecycle(legacy))
	req := tenantDomainRequest(http.MethodGet, "/api/v1/platform/tenant-key-domain", nil, "")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("legacy status = %d body=%s", rec.Code, rec.Body.String())
	}
	var status api.TenantKeyDomainStatus
	if err := json.NewDecoder(rec.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	if !status.Served || status.State != "legacy" || status.ProtectionMode != "legacy_deployment_kek" || !status.LocalWrapperZeroEgress {
		t.Fatalf("legacy status = %+v", status)
	}
	if len(legacy.tenantIDs) != 1 || legacy.tenantIDs[0] != connectorTenantA {
		t.Fatalf("status tenant scope = %v", legacy.tenantIDs)
	}

	leaking := &fakeTenantKeyDomainLifecycle{statusErr: errors.New("postgres://secret-user:secret-password@db.internal")}
	handler = api.New(nil, orchestrator.NewMemoryIdempotency(), nil,
		api.WithInsecureHeaderResolver(), api.WithTenantKeyDomainLifecycle(leaking))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, tenantDomainRequest(http.MethodGet, "/api/v1/platform/tenant-key-domain", nil, ""))
	for _, secretValue := range []string{"secret-user", "secret-password", "db.internal"} {
		if bytes.Contains(rec.Body.Bytes(), []byte(secretValue)) {
			t.Fatalf("status leaked provider error: %s", rec.Body.String())
		}
	}
}

func TestTenantKeyDomainMigrateAndUnsealAreTenantScopedAndIdempotent(t *testing.T) {
	operationID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	service := &fakeTenantKeyDomainLifecycle{domain: store.TenantKeyDomain{
		TenantID: connectorTenantA, DomainID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		Generation: 1, ProtectionMode: store.TenantKeyProtectionTenantDomain,
		State:       store.TenantKeyDomainStatePartial,
		WrapperKind: tenantseal.WrapperKindLocalFile, WrapperID: "tenant-a-wrapper",
		OperationID: &operationID, OperationKind: store.TenantKeyOperationMigrate,
		OperationStatus:   store.TenantKeyOperationCompleted,
		ProgressCompleted: 10, ProgressTotal: 10,
		LegacyHistoryExposure: store.TenantKeyLegacyExternalArchivesPossible,
		LastTransitionAt:      now, LastTransitionEvidenceRefs: []string{"tenant-history://receipt"},
	}}
	handler := api.New(nil, orchestrator.NewMemoryIdempotency(), nil,
		api.WithInsecureHeaderResolver(), api.WithTenantKeyDomainLifecycle(service))

	body := []byte(`{"wrapper_kind":"local_file","wrapper_id":"tenant-a-wrapper"}`)
	for range 2 {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, tenantDomainRequest(
			http.MethodPost, "/api/v1/platform/tenant-key-domain/migrate", body, "tenant-migrate-1",
		))
		if rec.Code != http.StatusOK {
			t.Fatalf("migrate status = %d body=%s", rec.Code, rec.Body.String())
		}
		var status api.TenantKeyDomainStatus
		if err := json.NewDecoder(rec.Body).Decode(&status); err != nil {
			t.Fatal(err)
		}
		if status.State != store.TenantKeyDomainStatePartial || status.WrapperID != "tenant-a-wrapper" || status.ProgressCompleted != 10 {
			t.Fatalf("migrate response = %+v", status)
		}
	}
	if service.migrateCalls != 1 {
		t.Fatalf("same Idempotency-Key executed migration %d times, want 1", service.migrateCalls)
	}
	if len(service.refs) != 1 || service.refs[0] != (tenantseal.WrapperRef{Kind: tenantseal.WrapperKindLocalFile, ID: "tenant-a-wrapper"}) {
		t.Fatalf("migration wrapper refs = %+v", service.refs)
	}
	if len(service.tenantIDs) != 1 || service.tenantIDs[0] != connectorTenantA {
		t.Fatalf("migration tenant scope = %v", service.tenantIDs)
	}

	service.domain.State = store.TenantKeyDomainStateUnsealed
	service.domain.OperationKind = store.TenantKeyOperationUnseal
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, tenantDomainRequest(
		http.MethodPost, "/api/v1/platform/tenant-key-domain/unseal", nil, "tenant-unseal-1",
	))
	if rec.Code != http.StatusOK || service.unsealCalls != 1 {
		t.Fatalf("unseal status=%d calls=%d body=%s", rec.Code, service.unsealCalls, rec.Body.String())
	}
}

func TestTenantKeyDomainMutationsRequireIdempotencyAndExactLocalWrapper(t *testing.T) {
	service := &fakeTenantKeyDomainLifecycle{}
	handler := api.New(nil, orchestrator.NewMemoryIdempotency(), nil,
		api.WithInsecureHeaderResolver(), api.WithTenantKeyDomainLifecycle(service))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, tenantDomainRequest(
		http.MethodPost, "/api/v1/platform/tenant-key-domain/migrate",
		[]byte(`{"wrapper_kind":"local_file","wrapper_id":"wrapper"}`), "",
	))
	if rec.Code != http.StatusBadRequest || service.migrateCalls != 0 {
		t.Fatalf("missing idempotency status=%d calls=%d", rec.Code, service.migrateCalls)
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, tenantDomainRequest(
		http.MethodPost, "/api/v1/platform/tenant-key-domain/migrate",
		[]byte(`{"wrapper_kind":"remote","wrapper_id":"wrapper"}`), "tenant-migrate-remote",
	))
	if rec.Code != http.StatusBadRequest || service.migrateCalls != 0 {
		t.Fatalf("remote wrapper status=%d calls=%d body=%s", rec.Code, service.migrateCalls, rec.Body.String())
	}
}

func tenantDomainRequest(method, path string, body []byte, idempotencyKey string) *http.Request {
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		reader = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("X-Tenant-ID", connectorTenantA)
	req.Header.Set("X-Roles", "admin")
	req.Header.Set("X-Subject", "tenant-custody-operator")
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	return req
}
