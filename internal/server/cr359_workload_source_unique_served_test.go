// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenancy"
)

// CR-359: a second source for the same cloud target must be refused before
// an immutable event is published. PostgreSQL's target uniqueness is only a
// projection guard; discovering it after append poisons later replay.
func TestCR359SecondWorkloadIdentitySourceForTargetRefusedBeforeAppend(t *testing.T) {
	fixture := newAWSFederatedSecretSyncFixture(t)
	trust := servedDynamicK8sTrustFixture(t, "cr359-aws-wif")
	h := newAWSFederatedServedHarness(t, fixture, nil)
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "cr359-source-operator",
		"secrets:read", "secrets:write", "certs:read", "certs:issue", "issuers:write")
	firstID := configureServedAWSFederatedSource(t, h, operator, trust)
	first, err := h.store.GetSecretSyncWorkloadIdentitySource(t.Context(), h.tenant, firstID)
	if err != nil {
		t.Fatal(err)
	}
	status, body := secretsReqKey(t, h, http.MethodPut,
		"/api/v1/secrets/syncs/workload-identity-sources/"+firstID, operator,
		"cr359-same-source-update", map[string]any{
			"name": "updated first AWS federation", "provider": "aws",
			"role_arn": first.RoleARN, "audience": first.Audience, "subject": first.Subject,
			"target_id":          first.TargetID,
			"workload_proof_ref": first.WorkloadProofRef,
			"trust_source_id":    first.TrustSourceID,
		})
	if status != http.StatusOK {
		t.Fatalf("same-source update was blocked: status=%d body=%s", status, body)
	}
	before, err := h.log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	status, body = secretsReqKey(t, h, http.MethodPost,
		"/api/v1/secrets/syncs/workload-identity-sources", operator,
		"cr359-second-source", map[string]any{
			"name": "conflicting AWS federation", "provider": "aws",
			"role_arn": "arn:aws:iam::123456789012:role/trstctl-secret-sync",
			"audience": "trstctl", "subject": servedAWSFederatedSubject,
			"target_id":                   servedAWSFederatedTargetID,
			"allowed_remote_key_prefixes": []string{"prod/payments/"},
			"workload_proof_ref":          "secret://" + servedAWSFederatedProofName,
			"trust_source_id":             first.TrustSourceID,
		})
	if status != http.StatusConflict {
		t.Errorf("second source status = %d, want 409; body=%s", status, body)
	}
	after, err := h.log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Errorf("rejected second source appended event: before=%d after=%d", before, after)
	}
	if got, err := h.store.GetSecretSyncWorkloadIdentitySource(t.Context(), h.tenant, firstID); err != nil || got.Status != store.SecretSyncWorkloadIdentityReady {
		t.Errorf("first source changed after conflicting create: source=%+v err=%v", got, err)
	}
}

// A duplicate target published by an older version is still immutable. Its
// tenant must be quarantined while later events for another tenant replay.
func TestCR359HistoricalDuplicateTargetConfinesTenantDuringCatchUp(t *testing.T) {
	fixture := newAWSFederatedSecretSyncFixture(t)
	trust := servedDynamicK8sTrustFixture(t, "cr359-historical-aws-wif")
	h := newAWSFederatedServedHarness(t, fixture, nil)
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "cr359-history-operator",
		"secrets:read", "secrets:write", "certs:read", "certs:issue", "issuers:write")
	firstID := configureServedAWSFederatedSource(t, h, operator, trust)
	first, err := h.store.GetSecretSyncWorkloadIdentitySource(t.Context(), h.tenant, firstID)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := json.Marshal(projections.SecretSyncWorkloadIdentitySourceUpserted{
		ID: uuid.NewString(), Name: "historical conflicting source", Provider: first.Provider,
		RoleARN: first.RoleARN, Audience: first.Audience, Subject: first.Subject,
		TargetID: first.TargetID, WorkloadProofRef: first.WorkloadProofRef,
		TrustSourceID: first.TrustSourceID, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.log.Append(t.Context(), events.Event{
		Type: projections.EventSecretSyncWorkloadIdentityUpserted, TenantID: h.tenant, Data: duplicate,
	}); err != nil {
		t.Fatal(err)
	}
	neighbor := uuid.NewString()
	if _, err := h.log.Append(t.Context(), events.Event{
		Type: projections.EventTenantRegistered, TenantID: neighbor,
		Data: json.RawMessage(`{"name":"healthy neighbor"}`),
	}); err != nil {
		t.Fatal(err)
	}
	if err := projections.New(h.store).ProjectCatchUp(t.Context(), h.log); err != nil {
		t.Errorf("historical duplicate blocked shared catch-up: %v", err)
	}
	if _, err := h.store.GetTenant(t.Context(), neighbor); err != nil {
		t.Errorf("neighbor registration did not project after duplicate: %v", err)
	}
	if err := h.store.RequireLiveTenantService(t.Context(), h.tenant); !errors.Is(err, tenancy.ErrServiceUnavailable) {
		t.Errorf("conflicting tenant remained serviceable: %v", err)
	}
	if err := h.store.RequireLiveTenantService(t.Context(), neighbor); err != nil {
		t.Errorf("healthy neighbor refused: %v", err)
	}
}

func TestCR359WorkloadIdentitySourceRetargetConflictRefusedBeforeAppend(t *testing.T) {
	fixture := newAWSFederatedSecretSyncFixture(t)
	trust := servedDynamicK8sTrustFixture(t, "cr359-retarget-aws-wif")
	h := newAWSFederatedServedHarness(t, fixture, nil)
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "cr359-retarget-operator",
		"secrets:read", "secrets:write", "certs:read", "certs:issue", "issuers:write")
	firstID := configureServedAWSFederatedSource(t, h, operator, trust)
	first, err := h.store.GetSecretSyncWorkloadIdentitySource(t.Context(), h.tenant, firstID)
	if err != nil {
		t.Fatal(err)
	}
	otherID := uuid.NewString()
	otherTarget := "retarget-source-original-target"
	other, err := json.Marshal(projections.SecretSyncWorkloadIdentitySourceUpserted{
		ID: otherID, Name: "older second target", Provider: first.Provider,
		RoleARN: first.RoleARN, Audience: first.Audience, Subject: first.Subject,
		TargetID: otherTarget, WorkloadProofRef: first.WorkloadProofRef,
		TrustSourceID: first.TrustSourceID, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	event, err := h.log.Append(t.Context(), events.Event{
		Type: projections.EventSecretSyncWorkloadIdentityUpserted, TenantID: h.tenant, Data: other,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(h.store).Apply(t.Context(), event); err != nil {
		t.Fatal(err)
	}
	before, err := h.log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	status, body := secretsReqKey(t, h, http.MethodPut,
		"/api/v1/secrets/syncs/workload-identity-sources/"+otherID, operator,
		"cr359-retarget-conflict", map[string]any{
			"name": "retargeted second source", "provider": "aws",
			"role_arn": first.RoleARN, "audience": first.Audience, "subject": first.Subject,
			"target_id":          first.TargetID,
			"workload_proof_ref": first.WorkloadProofRef,
			"trust_source_id":    first.TrustSourceID,
		})
	if status != http.StatusConflict {
		t.Errorf("retarget to occupied source status = %d, want 409; body=%s", status, body)
	}
	after, err := h.log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Errorf("rejected retarget appended event: before=%d after=%d", before, after)
	}
	if got, err := h.store.GetSecretSyncWorkloadIdentitySource(t.Context(), h.tenant, otherID); err != nil || got.TargetID != otherTarget {
		t.Errorf("old target changed after conflicting retarget: source=%+v err=%v", got, err)
	}
}
