// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/kek"
	"trstctl.com/trstctl/internal/tenancy"
)

func TestWhitespaceSecretApprovalCannotPoisonRecoveryC0086(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.RequireApproval = true
		d.RequiredApprovals = 2
	})
	registerServedTenant(t, h, "approval-name tenant")
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "name-writer", "secrets:read", "secrets:write")
	const name = "edge "
	if code, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", requester, "edge-create",
		map[string]any{"name": name, "value": "fixture-v1"}); code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", code, body)
	}
	code, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/store/edge%20", requester, "edge-rotate",
		map[string]any{"value": "fixture-v2"})
	if code != http.StatusForbidden || !strings.Contains(string(body), "approval_required") {
		t.Fatalf("exact approval not available: status=%d body=%s", code, body)
	}
	fence, err := h.store.GetApplicationSecretMutationFence(t.Context(), h.tenant, name)
	if err != nil || fence.Approval == nil {
		t.Fatalf("approved name left an unbound fence: %+v err=%v", fence, err)
	}
	if count, err := h.srv.api.ReconcileApplicationSecretMutationFences(t.Context()); err != nil || count != 0 {
		t.Fatalf("one tenant's pending approval stopped recovery: count=%d err=%v", count, err)
	}
	if err := h.srv.api.ApplicationSecretMutationReconcileHealth(t.Context()); err != nil {
		t.Fatalf("pending exact approval degraded shared readiness: %v", err)
	}
	if current, err := h.store.GetSecret(t.Context(), h.tenant, name); err != nil || current.Version != 1 {
		t.Fatalf("pending approval changed secret: %+v err=%v", current, err)
	}
	rows, err := h.store.ListOperationApprovals(t.Context(), h.tenant, "", 100)
	if err != nil || len(rows) != 1 || !strings.HasPrefix(rows[0].ResourceID, "secret-name-b64:") {
		t.Fatalf("approval did not bind the exact edge-whitespace name: %+v err=%v", rows, err)
	}
	for _, approver := range []string{"reviewer-a", "reviewer-b"} {
		token := seedScopedTokenSubject(t, h.store, h.tenant, approver, "secrets:write")
		if code, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store/approvals/edge%20", token,
			"approve-"+approver, map[string]any{"action": "rotate", "request_id": rows[0].ID, "intent_digest": rows[0].IntentDigest}); code != http.StatusOK {
			t.Fatalf("%s exact review status=%d body=%s", approver, code, body)
		}
	}
	if code, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/store/edge%20", requester, "edge-rotate",
		map[string]any{"value": "fixture-v2"}); code != http.StatusOK {
		t.Fatalf("approved exact rotation status=%d body=%s", code, body)
	}
	if current, err := h.store.GetSecret(t.Context(), h.tenant, name); err != nil || current.Version != 2 {
		t.Fatalf("approved exact rotation did not finish: %+v err=%v", current, err)
	}
}

func TestWhitespaceRequesterCannotLeaveUnboundSecretFenceC0086(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.RequireApproval = true
		d.RequiredApprovals = 2
	})
	registerServedTenant(t, h, "requester-name tenant")
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "edge-writer ", "secrets:read", "secrets:write")
	if code, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", requester, "requester-create",
		map[string]any{"name": "normal-secret", "value": "fixture-v1"}); code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", code, body)
	}
	code, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/store/normal-secret", requester, "requester-rotate",
		map[string]any{"value": "fixture-v2"})
	if code != http.StatusForbidden || !strings.Contains(string(body), "approval_required") {
		t.Fatalf("exact requester approval not available: status=%d body=%s", code, body)
	}
	fence, err := h.store.GetApplicationSecretMutationFence(t.Context(), h.tenant, "normal-secret")
	if err != nil || fence.Approval == nil {
		t.Fatalf("requester left an unbound fence: %+v err=%v", fence, err)
	}
	if _, err := h.srv.api.ReconcileApplicationSecretMutationFences(t.Context()); err != nil {
		t.Fatalf("requester blocked shared recovery: %v", err)
	}
}

func TestSuspendedTenantUnboundSecretFenceDoesNotFailStartupC0086(t *testing.T) {
	secretKEK, err := kek.LoadOrCreate(secretsTestKEKPath(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(secretKEK.Destroy)
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.EnableSecretsAPI = true
		d.KEK = secretKEK
		d.RequireApproval = true
		d.RequiredApprovals = 2
		// Model a crash after the fence claim, before approval authority exists.
		d.APIOptions = append(d.APIOptions, api.WithMutationGate(api.MutationGate{RequireApproval: true}))
	})
	registerServedTenant(t, h, "suspended fence tenant")
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "suspended-writer", "secrets:read", "secrets:write")
	if code, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", requester, "suspend-create",
		map[string]any{"name": "suspend-secret", "value": "fixture-v1"}); code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", code, body)
	}
	if code, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/store/suspend-secret", requester, "suspend-rotate",
		map[string]any{"value": "fixture-v2"}); code != http.StatusForbidden {
		t.Fatalf("unbound fence fixture status=%d body=%s", code, body)
	}
	fence, err := h.store.GetApplicationSecretMutationFence(t.Context(), h.tenant, "suspend-secret")
	if err != nil || !fence.ApprovalRequired || fence.Approval != nil {
		t.Fatalf("missing unbound fence: %+v err=%v", fence, err)
	}
	const tenantB = "22222222-2222-2222-2222-222222222222"
	registerServedTenantID(t, h, tenantB, "healthy recovery tenant")
	backendB := h.srv.buildSecretsBackend(Deps{Store: h.store, KEK: secretKEK})
	noLogB := api.New(h.store, h.srv.idem, h.srv.orch,
		api.WithInsecureHeaderResolver(), api.WithSecrets(backendB), api.WithMutationGate(api.MutationGate{}))
	bodyB, _ := json.Marshal(map[string]any{"name": "healthy-secret", "value": "fixture-v1"})
	reqB := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/store", bytes.NewReader(bodyB))
	reqB.Header.Set("Content-Type", "application/json")
	reqB.Header.Set("X-Tenant-ID", tenantB)
	reqB.Header.Set("X-Roles", "admin")
	reqB.Header.Set("X-Subject", "healthy-writer")
	reqB.Header.Set("Idempotency-Key", "healthy-create")
	recB := httptest.NewRecorder()
	noLogB.ServeHTTP(recB, reqB)
	if recB.Code != http.StatusInternalServerError {
		t.Fatalf("healthy pending command fixture status=%d body=%s", recB.Code, recB.Body.Bytes())
	}
	ctx := context.Background()
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO provider_tenants(tenant_id,slug,name,status,created_at,updated_at)
			VALUES($1,'c0086-fixture','C0086 fixture','suspended',now(),now())`, h.tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.store.RequireLiveTenantService(ctx, h.tenant); !errors.Is(err, tenancy.ErrServiceUnavailable) {
		t.Fatalf("tenant was not suspended: %v", err)
	}
	restarted, err := Build(ctx, Deps{
		Store: h.store, Log: h.log, Signer: h.signer, SignAuthorizer: h.authz,
		CACertFile: h.caFile, KEK: secretKEK, EnableSecretsAPI: true,
		RequireApproval: true, RequiredApprovals: 2,
	})
	if err != nil {
		t.Fatalf("one suspended tenant's fence aborted shared startup: %v", err)
	}
	cleanupServedServer(t, restarted)
	if err := restarted.api.ApplicationSecretMutationReconcileHealth(ctx); err != nil {
		t.Fatalf("suspended tenant degraded shared readiness: %v", err)
	}
	if current, err := h.store.GetSecret(ctx, tenantB, "healthy-secret"); err != nil || current.Version != 1 {
		t.Fatalf("healthy tenant's pending command was not recovered: %+v err=%v", current, err)
	}
	if current, err := h.store.GetSecret(ctx, h.tenant, "suspend-secret"); err != nil || current.Version != 1 {
		t.Fatalf("suspended tenant's fence bypassed approval: %+v err=%v", current, err)
	}
	if _, err := h.store.GetApplicationSecretMutationFence(ctx, h.tenant, "suspend-secret"); err != nil {
		t.Fatalf("suspended tenant's command fence was discarded: %v", err)
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM provider_tenants WHERE tenant_id=$1`, h.tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	restarted.reconcileApplicationSecretMutationsOnce(ctx)
	fence, err = h.store.GetApplicationSecretMutationFence(ctx, h.tenant, "suspend-secret")
	if err != nil || fence.Approval == nil {
		t.Fatalf("resumed tenant's exact approval did not recover: %+v err=%v", fence, err)
	}
}

func TestLegacyUnboundWhitespaceSecretFenceRecoversC0086(t *testing.T) {
	secretKEK, err := kek.LoadOrCreate(secretsTestKEKPath(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(secretKEK.Destroy)
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.EnableSecretsAPI = true
		d.KEK = secretKEK
		d.RequireApproval = true
		d.RequiredApprovals = 2
		d.APIOptions = append(d.APIOptions, api.WithMutationGate(api.MutationGate{RequireApproval: true}))
	})
	registerServedTenant(t, h, "historical name tenant")
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "legacy-writer", "secrets:read", "secrets:write")
	const name = "legacy "
	if code, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", requester, "legacy-create",
		map[string]any{"name": name, "value": "fixture-v1"}); code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", code, body)
	}
	if code, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/store/legacy%20", requester, "legacy-rotate",
		map[string]any{"value": "fixture-v2"}); code != http.StatusForbidden {
		t.Fatalf("unbound legacy fence fixture status=%d body=%s", code, body)
	}
	fence, err := h.store.GetApplicationSecretMutationFence(t.Context(), h.tenant, name)
	if err != nil || fence.Approval != nil {
		t.Fatalf("historical fence is not unbound: %+v err=%v", fence, err)
	}
	restarted, err := Build(t.Context(), Deps{
		Store: h.store, Log: h.log, Signer: h.signer, SignAuthorizer: h.authz,
		CACertFile: h.caFile, KEK: secretKEK, EnableSecretsAPI: true,
		RequireApproval: true, RequiredApprovals: 2,
	})
	if err != nil {
		t.Fatalf("historical unbound name aborted startup: %v", err)
	}
	cleanupServedServer(t, restarted)
	fence, err = h.store.GetApplicationSecretMutationFence(t.Context(), h.tenant, name)
	if err != nil || fence.Approval == nil {
		t.Fatalf("historical name did not bind exact approval: %+v err=%v", fence, err)
	}
	if current, err := h.store.GetSecret(t.Context(), h.tenant, name); err != nil || current.Version != 1 {
		t.Fatalf("historical fence bypassed review: %+v err=%v", current, err)
	}
}
