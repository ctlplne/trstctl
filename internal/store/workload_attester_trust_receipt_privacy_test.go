// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/store"
)

func TestAttesterTrustReceiptPrivacyErasureKeepsOnlyOpaqueRetryFence(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	seedTwoTenants(t, st)
	const eventID = "a919a919-a919-4919-8919-a919a919a919"
	const sourceID = "b929b929-b929-4929-8929-b929b929b929"
	binding := strings.Repeat("a", 64)
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO workload_attester_trust_receipts
			(tenant_id,event_id,source_id,event_type,request_binding,binding_sha256,
			 response_snapshot,projected_sequence)
			VALUES ($1,$2,$3,'workload.attester_trust_source.rotated',$4,$4,$5::jsonb,7)`,
			tenantA, eventID, sourceID, binding, `{"Name":"alice-k8s","Enabled":false}`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	candidate := store.PrivacySubjectErasurePreparation{
		PrivacySubjectErasure: store.PrivacySubjectErasure{
			TenantID: tenantA, SubjectRef: privacy.SubjectRef(tenantA, "alice"),
			RequestedByRef: privacy.SubjectRef(tenantA, "privacy-admin"),
			Reason:         "qa erasure", ErasedAt: time.Now().UTC(),
		},
		OperationID:        "sha256:" + strings.Repeat("1", 64),
		RequestBinding:     "sha256:attester-trust-receipt-erasure",
		EventID:            "sha256:" + strings.Repeat("2", 64),
		RewriteOperationID: "sha256:" + strings.Repeat("3", 64),
		TargetGeneration:   "attester-trust-receipt-privacy",
	}
	prepared, err := st.PreparePrivacySubjectErasure(ctx, tenantA, "alice", candidate)
	if err != nil {
		t.Fatalf("prepare receipt erasure: %v", err)
	}
	if prepared.Counts["workload_attester_trust_receipts"] != 1 ||
		len(prepared.Selectors.ReadModels) != 1 ||
		prepared.Selectors.ReadModels[0].Table != "workload_attester_trust_receipts" ||
		prepared.Selectors.ReadModels[0].ID != eventID {
		t.Fatalf("privacy selection missed exact receipt: %+v", prepared.Selectors.ReadModels)
	}
	for range 2 {
		if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return st.ApplyPrivacySubjectErasedTx(ctx, tx, prepared.PrivacySubjectErasure)
		}); err != nil {
			t.Fatalf("project privacy erasure: %v", err)
		}
	}
	receipt, err := st.WorkloadAttesterTrustReceiptByEventID(ctx, tenantA, eventID)
	if err != nil || len(receipt.Snapshot) != 0 || receipt.RequestBinding != binding ||
		receipt.SourceID != sourceID {
		t.Fatalf("erasure kept raw result or lost retry fence: %+v err=%v", receipt, err)
	}
}
