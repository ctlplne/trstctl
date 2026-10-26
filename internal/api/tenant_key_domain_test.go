// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

type fakeTenantKeyDomainLifecycle struct {
	domain           store.TenantKeyDomain
	statusErr        error
	migrateErr       error
	unsealErr        error
	requestSealErr   error
	rotateErr        error
	migrateCalls     int
	unsealCalls      int
	requestSealCalls int
	rotateCalls      int
	tenantIDs        []string
	refs             []tenantseal.WrapperRef
	rotateRefs       []tenantseal.WrapperRef
	sealKeys         []string
	sealBindings     []string
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

func (f *fakeTenantKeyDomainLifecycle) RequestSeal(
	_ context.Context,
	tenantID, idempotencyKey, requestBinding string,
) (store.TenantKeyDomain, error) {
	f.requestSealCalls++
	f.tenantIDs = append(f.tenantIDs, tenantID)
	f.sealKeys = append(f.sealKeys, idempotencyKey)
	f.sealBindings = append(f.sealBindings, requestBinding)
	return f.domain, f.requestSealErr
}

func (f *fakeTenantKeyDomainLifecycle) CompleteSeal(context.Context, string, string) (store.TenantKeyDomain, error) {
	return store.TenantKeyDomain{}, errors.New("CompleteSeal belongs to the bounded worker")
}

func (f *fakeTenantKeyDomainLifecycle) FailSeal(context.Context, string, string) (store.TenantKeyDomain, error) {
	return store.TenantKeyDomain{}, errors.New("FailSeal belongs to the bounded worker")
}

func (f *fakeTenantKeyDomainLifecycle) Unseal(_ context.Context, tenantID string) (store.TenantKeyDomain, error) {
	f.unsealCalls++
	f.tenantIDs = append(f.tenantIDs, tenantID)
	return f.domain, f.unsealErr
}

func (f *fakeTenantKeyDomainLifecycle) Rotate(_ context.Context, tenantID string, ref tenantseal.WrapperRef) (store.TenantKeyDomain, error) {
	f.rotateCalls++
	f.tenantIDs = append(f.tenantIDs, tenantID)
	f.rotateRefs = append(f.rotateRefs, ref)
	return f.domain, f.rotateErr
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

func TestTenantKeyDomainStatusExplainsFailedSealRetryIdentity(t *testing.T) {
	service := &fakeTenantKeyDomainLifecycle{domain: store.TenantKeyDomain{
		TenantID: connectorTenantA, ProtectionMode: store.TenantKeyProtectionTenantDomain,
		State: store.TenantKeyDomainStatePartial, OperationKind: store.TenantKeyOperationSeal,
		OperationStatus: store.TenantKeyOperationFailed, Retryable: true,
		LastErrorCode: "seal_delivery_exhausted",
		LastError:     "tenant seal worker exhausted its retry budget before the seal committed",
	}}
	handler := api.New(nil, orchestrator.NewMemoryIdempotency(), nil,
		api.WithInsecureHeaderResolver(), api.WithTenantKeyDomainLifecycle(service))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, tenantDomainRequest(
		http.MethodGet, "/api/v1/platform/tenant-key-domain", nil, "",
	))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var status api.TenantKeyDomainStatus
	if err := json.NewDecoder(rec.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status.Recovery, "new Idempotency-Key") ||
		!strings.Contains(status.Recovery, "crypto remains available") {
		t.Fatalf("failed seal recovery = %q", status.Recovery)
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

func TestTenantKeyDomainSealQueuesOneStableWorkerOperation(t *testing.T) {
	operationID := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	service := &fakeTenantKeyDomainLifecycle{domain: store.TenantKeyDomain{
		TenantID: connectorTenantA, DomainID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		Generation: 1, ProtectionMode: store.TenantKeyProtectionTenantDomain,
		State:       store.TenantKeyDomainStateSealQueued,
		OperationID: &operationID, OperationKind: store.TenantKeyOperationSeal,
		OperationStatus: store.TenantKeyOperationPending,
	}}
	handler := api.New(nil, orchestrator.NewMemoryIdempotency(), nil,
		api.WithInsecureHeaderResolver(), api.WithTenantKeyDomainLifecycle(service))

	for range 2 {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, tenantDomainRequest(
			http.MethodPost, "/api/v1/platform/tenant-key-domain/seal", nil, "tenant-seal-1",
		))
		if rec.Code != http.StatusAccepted {
			t.Fatalf("seal status = %d body=%s", rec.Code, rec.Body.String())
		}
		var receipt api.TenantKeyDomainSealReceipt
		if err := json.NewDecoder(rec.Body).Decode(&receipt); err != nil {
			t.Fatal(err)
		}
		if !receipt.Accepted || receipt.OperationID != operationID ||
			receipt.State != store.TenantKeyDomainStateSealQueued ||
			receipt.StatusURL != "/api/v1/platform/tenant-key-domain" {
			t.Fatalf("seal receipt = %+v", receipt)
		}
	}
	if service.requestSealCalls != 1 {
		t.Fatalf("same Idempotency-Key queued seal %d times, want 1", service.requestSealCalls)
	}
	if len(service.sealKeys) != 1 || service.sealKeys[0] != "tenant-seal-1" ||
		len(service.sealBindings) != 1 || service.sealBindings[0] == "" {
		t.Fatalf("seal request key/binding = %v/%v", service.sealKeys, service.sealBindings)
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

// A123: a tenant migrates to a pkcs11 wrapper the signer holds. The exact
// kind and ID reach the lifecycle, and the status says the domain KEK lives in
// the signer under an HSM key (not a zero-egress local file), with recovery
// that names the signer's HSM custody when the wrapper is unavailable.
func TestTenantKeyDomainMigratesToASignerHeldHSMWrapper(t *testing.T) {
	operationID := "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	service := &fakeTenantKeyDomainLifecycle{domain: store.TenantKeyDomain{
		TenantID: connectorTenantA, DomainID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		Generation: 1, ProtectionMode: store.TenantKeyProtectionTenantDomain,
		State:       store.TenantKeyDomainStateUnsealed,
		WrapperKind: tenantseal.WrapperKindPKCS11, WrapperID: "hsm-a",
		OperationID: &operationID, OperationKind: store.TenantKeyOperationMigrate,
		OperationStatus:   store.TenantKeyOperationCompleted,
		ProgressCompleted: 10, ProgressTotal: 10,
		LegacyHistoryExposure: store.TenantKeyLegacyNone,
	}}
	handler := api.New(nil, orchestrator.NewMemoryIdempotency(), nil,
		api.WithInsecureHeaderResolver(), api.WithTenantKeyDomainLifecycle(service))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, tenantDomainRequest(
		http.MethodPost, "/api/v1/platform/tenant-key-domain/migrate",
		[]byte(`{"wrapper_kind":"pkcs11","wrapper_id":"hsm-a"}`), "tenant-migrate-hsm",
	))
	if rec.Code != http.StatusOK {
		t.Fatalf("migrate to pkcs11 = %d body=%s", rec.Code, rec.Body.String())
	}
	if len(service.refs) != 1 || service.refs[0] != (tenantseal.WrapperRef{Kind: tenantseal.WrapperKindPKCS11, ID: "hsm-a"}) {
		t.Fatalf("migration wrapper refs = %+v", service.refs)
	}
	var status api.TenantKeyDomainStatus
	if err := json.NewDecoder(rec.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	if status.WrapperKind != "pkcs11" || status.LocalWrapperZeroEgress || status.RemoteWrapperState != "signer_hsm" {
		t.Fatalf("pkcs11 status = %+v", status)
	}

	service.domain.State = store.TenantKeyDomainStateWrapperUnavailable
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, tenantDomainRequest(http.MethodGet, "/api/v1/platform/tenant-key-domain", nil, ""))
	if err := json.NewDecoder(rec.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status.Recovery, "HSM key") || strings.Contains(status.Recovery, "local wrapper file") {
		t.Fatalf("pkcs11 wrapper-unavailable recovery = %q", status.Recovery)
	}
}

// A129: rotation keeps the current wrapper when the body is empty, moves to a
// named wrapper when one is given, replays one Idempotency-Key once, refuses an
// unknown wrapper kind, and reports the promoted generation and the conflict
// status as public statuses.
func TestTenantKeyDomainRotateKeepsOrMovesTheWrapperAndReplaysOnce(t *testing.T) {
	operationID := "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	rotatedAt := time.Date(2026, 10, 26, 13, 0, 0, 0, time.UTC)
	service := &fakeTenantKeyDomainLifecycle{domain: store.TenantKeyDomain{
		TenantID: connectorTenantA, DomainID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		Generation: 2, ProtectionMode: store.TenantKeyProtectionTenantDomain,
		State:       store.TenantKeyDomainStateUnsealed,
		WrapperKind: tenantseal.WrapperKindLocalFile, WrapperID: "tenant-a-wrapper",
		OperationID: &operationID, OperationKind: store.TenantKeyOperationRotate,
		OperationStatus:   store.TenantKeyOperationCompleted,
		ProgressCompleted: 13, ProgressTotal: 13, RotatedAt: &rotatedAt,
		LegacyHistoryExposure: store.TenantKeyLegacyExternalArchivesPossible,
	}}
	handler := api.New(nil, orchestrator.NewMemoryIdempotency(), nil,
		api.WithInsecureHeaderResolver(), api.WithTenantKeyDomainLifecycle(service))

	for range 2 {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, tenantDomainRequest(
			http.MethodPost, "/api/v1/platform/tenant-key-domain/rotate", nil, "tenant-rotate-1",
		))
		if rec.Code != http.StatusOK {
			t.Fatalf("rotate status = %d body=%s", rec.Code, rec.Body.String())
		}
		var status api.TenantKeyDomainStatus
		if err := json.NewDecoder(rec.Body).Decode(&status); err != nil {
			t.Fatal(err)
		}
		if status.Generation != 2 || status.OperationKind != store.TenantKeyOperationRotate ||
			status.RotatedAt == nil || !status.RotatedAt.Equal(rotatedAt) || status.NextGeneration != 0 ||
			!strings.Contains(status.Recovery, "previous generation") {
			t.Fatalf("rotate response = %+v", status)
		}
	}
	if service.rotateCalls != 1 || len(service.rotateRefs) != 1 || service.rotateRefs[0] != (tenantseal.WrapperRef{}) {
		t.Fatalf("same Idempotency-Key rotated %d times with refs %+v, want once with the current wrapper", service.rotateCalls, service.rotateRefs)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, tenantDomainRequest(
		http.MethodPost, "/api/v1/platform/tenant-key-domain/rotate",
		[]byte(`{"wrapper_kind":"pkcs11","wrapper_id":"hsm-a"}`), "tenant-rotate-hsm",
	))
	if rec.Code != http.StatusOK || service.rotateRefs[len(service.rotateRefs)-1] != (tenantseal.WrapperRef{Kind: tenantseal.WrapperKindPKCS11, ID: "hsm-a"}) {
		t.Fatalf("rotate onto pkcs11 = %d refs=%+v body=%s", rec.Code, service.rotateRefs, rec.Body.String())
	}

	calls := service.rotateCalls
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, tenantDomainRequest(
		http.MethodPost, "/api/v1/platform/tenant-key-domain/rotate",
		[]byte(`{"wrapper_kind":"remote","wrapper_id":"kms-a"}`), "tenant-rotate-remote",
	))
	if rec.Code != http.StatusBadRequest || service.rotateCalls != calls {
		t.Fatalf("rotate onto a remote wrapper = %d calls=%d body=%s", rec.Code, service.rotateCalls, rec.Body.String())
	}

	service.rotateErr = tenantseal.ErrLifecycleConflict
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, tenantDomainRequest(
		http.MethodPost, "/api/v1/platform/tenant-key-domain/rotate", nil, "tenant-rotate-conflict",
	))
	if rec.Code != http.StatusConflict {
		t.Fatalf("rotate in a conflicting state = %d body=%s", rec.Code, rec.Body.String())
	}
}
