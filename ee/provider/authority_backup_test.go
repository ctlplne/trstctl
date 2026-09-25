// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"bytes"
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/backup"
)

func TestProviderAuthorityBackupPreservesRevocationCompletion(t *testing.T) {
	st, _, sink := authorityReplayFixture(t)
	customer := CustomerID("backup-revoked-authority")
	payload := AuthorityEvent{Delegation: &DelegationMutation{
		OperatorID: "worker", CustomerID: customer, Operation: OpRead,
	}, EffectiveAt: time.Now().UTC()}
	grant, err := sink.Append(t.Context(), "grant", EventDelegationGranted, customer, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sink.Append(t.Context(), "revoke", EventDelegationRevoked, customer, payload); err != nil {
		t.Fatal(err)
	}
	var artifact bytes.Buffer
	key := bytes.Repeat([]byte{0x5a}, 32)
	if _, err := backup.WritePostgresStateAtCutWithKey(t.Context(), st, &artifact, 2, key, backup.PostgresStateIdentity{}); err != nil {
		t.Fatal(err)
	}
	if err := sink.projection.Reset(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := backup.RestorePostgresStateWithKey(t.Context(), st, &artifact, key, backup.PostgresStateIdentity{}); err != nil {
		t.Fatal(err)
	}
	assertReplayAuthority(t, st, "worker", customer, false)
	// Initial recovery can run without Provider's event projector attached.
	// PostgreSQL state must therefore preserve proof of the completed revoke.
	if err := NewAuthorityProjection(st).Apply(t.Context(), grant); err != nil {
		t.Fatal(err)
	}
	assertReplayAuthority(t, st, "worker", customer, false)
	var receipts int
	if err := st.SystemPool().QueryRow(t.Context(), `SELECT count(*) FROM provider_authority_projection_receipts WHERE tenant_id=$1`, providerAuthorityTenant).Scan(&receipts); err != nil || receipts != 2 {
		t.Fatalf("restore lost completed authority events: %d, %v", receipts, err)
	}
}

func TestProviderAuthorityBackupPreservesUpgradeUncertainty(t *testing.T) {
	st, _, sink := authorityReplayFixture(t)
	// This marker models migration 0224 detecting populated legacy authority.
	if _, err := st.SystemPool().Exec(t.Context(), `UPDATE provider_authority_projection_state SET needs_rebuild=true WHERE tenant_id=$1`, providerAuthorityTenant); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = st.SystemPool().Exec(context.Background(), `UPDATE provider_authority_projection_state SET needs_rebuild=false WHERE tenant_id=$1`, providerAuthorityTenant)
	})
	var artifact bytes.Buffer
	key := bytes.Repeat([]byte{0x6b}, 32)
	if _, err := backup.WritePostgresStateAtCutWithKey(t.Context(), st, &artifact, 0, key, backup.PostgresStateIdentity{}); err != nil {
		t.Fatal(err)
	}
	if err := sink.projection.Reset(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := backup.RestorePostgresStateWithKey(t.Context(), st, &artifact, key, backup.PostgresStateIdentity{}); err != nil {
		t.Fatal(err)
	}
	var uncertain bool
	if err := st.SystemPool().QueryRow(t.Context(), `SELECT needs_rebuild FROM provider_authority_projection_state WHERE tenant_id=$1`, providerAuthorityTenant).Scan(&uncertain); err != nil || !uncertain {
		t.Fatalf("restore converted unknown legacy completion into initialized authority: %v, %v", uncertain, err)
	}
}
