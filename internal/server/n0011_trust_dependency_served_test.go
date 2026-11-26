// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
)

func TestN0011ServedTrustDeleteWithWorkloadSourceRefusedBeforeAppend(t *testing.T) {
	fixture := newAWSFederatedSecretSyncFixture(t)
	trust := servedDynamicK8sTrustFixture(t, "n0011-trust")
	h := newAWSFederatedServedHarness(t, fixture, nil)
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "n0011-operator",
		"secrets:read", "secrets:write", "certs:read", "certs:issue", "issuers:write")
	sourceID := configureServedAWSFederatedSource(t, h, operator, trust)
	var trustID string
	if err := h.store.SystemPool().QueryRow(t.Context(),
		`SELECT trust_source_id::text FROM secret_sync_workload_identity_sources WHERE tenant_id=$1 AND id=$2`,
		h.tenant, sourceID).Scan(&trustID); err != nil {
		t.Fatal(err)
	}
	status, body := secretsReqKey(t, h, http.MethodDelete,
		"/api/v1/workloads/attester-trust-sources/"+trustID,
		operator, "n0011-delete-referenced", nil)
	if status != http.StatusConflict {
		t.Fatalf("referenced trust delete status=%d, want 409; body=%s", status, body)
	}
	tenantUUID := uuid.MustParse(h.tenant)
	eventID := uuid.NewSHA1(tenantUUID, []byte("trstctl:workload-attester-trust-command:n0011-delete-referenced")).String()
	if _, found, err := h.log.EventByID(t.Context(), eventID); err != nil || found {
		t.Fatalf("referenced trust delete appended event: found=%v err=%v", found, err)
	}
	status, body = secretsReqKey(t, h, http.MethodDelete,
		"/api/v1/secrets/syncs/workload-identity-sources/"+sourceID,
		operator, "n0011-remove-dependent", nil)
	if status != http.StatusNoContent {
		t.Fatalf("remove dependent source status=%d body=%s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodDelete,
		"/api/v1/workloads/attester-trust-sources/"+trustID,
		operator, "n0011-delete-after-dependent", nil)
	if status != http.StatusNoContent {
		t.Fatalf("delete unreferenced trust status=%d body=%s", status, body)
	}
}
