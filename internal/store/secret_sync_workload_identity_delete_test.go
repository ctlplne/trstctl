// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// The command-side projector and event tail may apply the same deletion in
// either order. Once the row is absent, applying that event again must converge
// rather than reporting a 500 after the operator's deletion already succeeded.
func TestSecretSyncWorkloadIdentityDeletionConvergesOnReplay(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	at := time.Now().UTC()
	trustID := uuid(tenantA, 9701)
	sourceID := uuid(tenantA, 9702)
	trust := store.WorkloadAttesterTrustSource{
		ID: trustID, TenantID: tenantA, Name: "qa-wif-delete-trust", Method: "k8s_sat",
		Issuer: "https://kubernetes.default.svc.cluster.local", Audience: "trstctl",
		JWKS: json.RawMessage(`{"keys":[]}`), Enabled: true, RotationVersion: 1,
		CreatedAt: at, UpdatedAt: at,
	}
	mustTx(t, ctx, s, func(tx pgx.Tx) error {
		return s.ApplyWorkloadAttesterTrustSourceUpsertedTx(ctx, tx, trust)
	})
	source := store.SecretSyncWorkloadIdentitySource{
		ID: sourceID, TenantID: tenantA, Name: "qa-wif-delete-source", Provider: "aws",
		RoleARN: "arn:aws:iam::123456789012:role/qa-wif", Audience: "trstctl",
		Subject: "system:serviceaccount:qa:worker", TargetID: "qa-wif-target",
		AllowedRemoteKeyPrefixes: []string{"qa/wif/"}, WorkloadProofRef: "file:/run/qa-proof.jwt",
		TrustSourceID: trustID, Enabled: true, CreatedAt: at, UpdatedAt: at,
	}
	mustTx(t, ctx, s, func(tx pgx.Tx) error {
		return s.ApplySecretSyncWorkloadIdentitySourceUpsertedTx(ctx, tx, source)
	})
	for n := 0; n < 2; n++ {
		mustTx(t, ctx, s, func(tx pgx.Tx) error {
			return s.ApplySecretSyncWorkloadIdentitySourceDeletedTx(ctx, tx, tenantA, sourceID)
		})
	}
	if _, err := s.GetSecretSyncWorkloadIdentitySource(ctx, tenantA, sourceID); !errors.Is(err, store.ErrSecretSyncWorkloadIdentitySourceNotFound) {
		t.Fatalf("deleted source was resurrected or unreadable for another reason: %v", err)
	}
}
