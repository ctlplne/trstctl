// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

func TestPQCHostRollbackRechecksUnmanagedPredecessorWithoutWeakeningOrdinaryRollback(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	seedTwoTenants(t, st)
	const ownerID = "11111111-1111-4111-8111-111111111112"
	const identityID = "11111111-1111-4111-8111-111111111113"
	const targetID = "11111111-1111-4111-8111-111111111114"
	const assetID = "11111111-1111-4111-8111-111111111115"
	const agentID = "11111111-1111-4111-8111-111111111116"
	predecessor, successor := strings.Repeat("a", 64), strings.Repeat("b", 64)
	if err := st.UpsertOwner(ctx, store.Owner{ID: ownerID, TenantID: tenantA, Kind: store.OwnerService, Name: "PQC rollback owner"}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertIdentity(ctx, store.Identity{ID: identityID, TenantID: tenantA, OwnerID: ownerID,
		Kind: store.KindX509Certificate, Name: "apache.example.test", Status: "requested"}); err != nil {
		t.Fatal(err)
	}
	config := json.RawMessage(`{"executor":"agent","required_agent_id":"` + agentID + `","verify_address":"127.0.0.1:10443","verify_server_name":"apache.example.test"}`)
	if err := st.UpsertDeploymentTarget(ctx, store.DeploymentTarget{ID: targetID, TenantID: tenantA,
		Name: "Apache host", Type: "apache", Config: config, Enabled: true, EnabledSet: true}); err != nil {
		t.Fatal(err)
	}
	target, err := st.GetDeploymentTarget(ctx, tenantA, targetID)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return st.ApplyCryptoAssetObservedTx(ctx, tx, store.CryptoAsset{ID: assetID, TenantID: tenantA,
			Kind: "certificate-key", Location: "127.0.0.1:10443", Algorithm: "ML-DSA-65",
			CertificateFingerprint: successor, Strength: "strong"}, 1, time.Now().UTC())
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertCertificate(ctx, store.Certificate{TenantID: tenantA, Fingerprint: successor,
		Subject: "apache.example.test", Serial: "pqc-successor", Source: "issued"}); err != nil {
		t.Fatal(err)
	}
	payload := map[string]string{
		"pqc_run_id": "11111111-1111-4111-8111-111111111117", "pqc_asset_id": assetID,
		"identity_id": identityID, "target_id": targetID, "target_revision": target.RevisionID,
		"connector": "apache", "required_agent_id": agentID,
		"verify_address": "127.0.0.1:10443", "verify_server_name": "apache.example.test",
		"predecessor_fingerprint": predecessor, "successor_fingerprint": successor,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CheckConnectorRollbackPayload(ctx, tenantA, encoded); err != nil {
		t.Fatalf("exact host-adopted predecessor was refused: %v", err)
	}
	ordinary, err := json.Marshal(map[string]string{"identity_id": identityID, "predecessor_fingerprint": predecessor})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CheckConnectorRollbackPayload(ctx, tenantA, ordinary); !errors.Is(err, store.ErrUnsafeRollback) {
		t.Fatalf("ordinary unknown predecessor was admitted: %v", err)
	}
	if err := st.CheckConnectorRollbackPayload(ctx, tenantB, encoded); !errors.Is(err, store.ErrUnsafeRollback) {
		t.Fatalf("cross-tenant PQC predecessor was admitted: %v", err)
	}
	key := "licensed-crypto-migration-host-rollback:" + payload["pqc_run_id"] + ":" + assetID
	var jobID int64
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO outbox
			(tenant_id, destination, payload, idempotency_key, status, claim_attempts,
			 required_agent_role, required_agent_id, last_error)
			VALUES ($1, 'connector.rollback', $2, $3, 'failed', 1, 'host', $4::uuid, 'old refusal')
			RETURNING id`, tenantA, encoded, key, agentID).Scan(&jobID)
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		requeued, err := st.RequeueFailedPQCConnectorRollbackTx(ctx, tx, tenantA, key, encoded, agentID)
		if err != nil || !requeued {
			t.Fatalf("explicit exact rollback recovery requeued=%t, err=%v", requeued, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var status string
	var claims int
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT status, claim_attempts FROM outbox WHERE tenant_id=$1 AND id=$2`, tenantA, jobID).
			Scan(&status, &claims)
	}); err != nil {
		t.Fatal(err)
	}
	if status != "pending" || claims != 1 {
		t.Fatalf("recovery erased claim history or left command terminal: %s / %d", status, claims)
	}
	if _, err := st.UpsertCertificate(ctx, store.Certificate{TenantID: tenantA, Fingerprint: predecessor,
		Subject: "apache.example.test", Serial: "known-predecessor", Source: "import"}); err != nil {
		t.Fatal(err)
	}
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return st.SetCertificateRevokedTx(ctx, tx, tenantA, predecessor, "keyCompromise", time.Now().UTC())
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.CheckConnectorRollbackPayload(ctx, tenantA, encoded); !errors.Is(err, store.ErrUnsafeRollback) {
		t.Fatalf("known revoked predecessor was admitted: %v", err)
	}
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE outbox SET status='failed' WHERE tenant_id=$1 AND id=$2`, tenantA, jobID)
		if err != nil {
			return err
		}
		_, err = st.RequeueFailedPQCConnectorRollbackTx(ctx, tx, tenantA, key, encoded, agentID)
		if !errors.Is(err, store.ErrUnsafeRollback) {
			t.Fatalf("revoked predecessor recovery was admitted: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
