// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

func TestEndpointVerificationSweepRetainsTargetProtocolAndExpectedLeaf(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	ctx := t.Context()
	const targetID = "03600000-0000-4000-8000-000000000001"
	const foreignID = "03600000-0000-4000-8000-000000000002"
	const otherTenant = "03600000-0000-4000-8000-000000000003"
	if err := h.store.UpsertTenant(ctx, store.Tenant{TenantID: otherTenant, Name: "other verification tenant", CreatedAt: time.Now().UTC(), EventSeq: 1}); err != nil {
		t.Fatal(err)
	}
	for _, target := range []store.DeploymentTarget{
		{ID: targetID, TenantID: h.tenant, Name: "database", Type: "postgresql", Config: json.RawMessage(`{"verify_server_name":"database.example.test"}`)},
		{ID: foreignID, TenantID: otherTenant, Name: "foreign", Type: "postgresql", Config: json.RawMessage(`{"verify_server_name":"foreign.example.test"}`)},
	} {
		if err := h.store.UpsertDeploymentTarget(ctx, target); err != nil {
			t.Fatal(err)
		}
	}
	// These are projection fixtures, including a divergent observed leaf. The
	// scheduled job must preserve the expected leaf instead of blessing drift.
	ids := []string{targetID, foreignID, "legacy-listener", "03600000-0000-4000-8000-000000000004"}
	for _, id := range ids {
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			return h.store.ApplyEndpointVerificationTx(ctx, tx, store.EndpointVerification{
				TenantID: h.tenant, EndpointID: id, Address: "127.0.0.1:10448", Vantage: "local",
				Reached: true, Mismatch: "fingerprint", ExpectedFingerprint: "expected-leaf", ObservedFingerprint: "wrong-leaf",
				LastCheckedAt: time.Now().UTC(), EventSequence: 1,
			})
		}); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if n, err := h.srv.queueEndpointVerificationSweep(ctx, h.tenant); err != nil || n != len(ids) {
			t.Fatalf("queued=%d err=%v", n, err)
		}
	}
	var payload []byte
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = $2`, h.tenant, relay.KindEndpointVerify).Scan(&count); err != nil {
			return err
		}
		if count != 1 {
			t.Fatalf("replayed sweep enqueued %d jobs", count)
		}
		return tx.QueryRow(ctx, `SELECT payload FROM outbox WHERE tenant_id = $1 AND destination = $2`, h.tenant, relay.KindEndpointVerify).Scan(&payload)
	}); err != nil {
		t.Fatal(err)
	}
	var intent relay.EndpointVerifyIntent
	if err := json.Unmarshal(payload, &intent); err != nil {
		t.Fatal(err)
	}
	if len(intent.Endpoints) != len(ids) {
		t.Fatalf("lost observations: %s", payload)
	}
	for _, want := range intent.Endpoints {
		if want.Fingerprint != "expected-leaf" || want.Address != "127.0.0.1:10448" {
			t.Fatalf("replaced expected identity/address: %+v", want)
		}
		if want.EndpointID == targetID {
			if want.Connector != "postgresql" || want.ServerName != "database.example.test" {
				t.Fatalf("lost protocol/SNI: %+v", want)
			}
		} else if want.Connector != "" || want.ServerName != "" {
			t.Fatalf("invented context or leaked foreign tenant target: %+v", want)
		}
	}
}
