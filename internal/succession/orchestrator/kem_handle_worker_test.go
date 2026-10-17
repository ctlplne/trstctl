// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/editionseam"
	coreorch "trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/orchestrator"
)

// The embedded nil interface panics if the worker reaches signer custody.
// A persisted pre-upgrade or forged outbox payload must fail before that call.
type neverKEMCustody struct{ editionseam.KEMCustody }

func TestKEMWorkerRejectsCrossTenantHandleBeforeSigner(t *testing.T) {
	const identityID = "spiffe://qa.local/kem-worker-fence"
	otherTenant := "22222222-2222-4222-8222-222222222222"
	payload, err := json.Marshal(map[string]any{
		"request_id": "kem-worker-tenant-fence",
		"request": map[string]any{
			"identity_id":           identityID,
			"predecessor_epoch":     0,
			"predecessor_handle":    succession.TenantKeyHandle(otherTenant, identityID, 0),
			"successor_sign_handle": succession.TenantKeyHandle(tenantA, identityID, 1),
			"successor_kem_handle":  succession.TenantKEMKeyHandle(tenantA, identityID, 1),
			"signing_algorithm":     "ECDSA-P384",
			"kem_algorithm":         "ML-KEM-768",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	worker := orchestrator.NewBreadthWorker(nil, neverKEMCustody{}, nil)
	err = worker.Deliver(context.Background(), coreorch.Message{
		TenantID: tenantA, Destination: orchestrator.KEMRewrapDestination, Payload: payload,
	})
	if err == nil || !strings.Contains(err.Error(), "bound to tenant") {
		t.Fatalf("forged KEM outbox payload reached signer custody: %v", err)
	}
}
