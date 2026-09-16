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

// A later relay measurement of the replacement must not perpetually renew
// the older relay expectation. This is the live PostgreSQL false-alarm shape.
func TestEndpointSweepDoesNotPinTheOldRelayExpectationAfterDeployment(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	ctx := t.Context()
	const endpointID = "03700000-0000-4000-8000-000000000001"
	if err := h.store.UpsertDeploymentTarget(ctx, store.DeploymentTarget{
		ID: endpointID, TenantID: h.tenant, Name: "renewed-postgresql", Type: "postgresql",
		Config: json.RawMessage(`{"verify_server_name":"db.example.test"}`),
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, row := range []store.EndpointVerification{
		{TenantID: h.tenant, EndpointID: endpointID, Address: "127.0.0.1:10448", Vantage: "local",
			Reached: true, ExpectedFingerprint: "replacement-from-deployment", ObservedFingerprint: "replacement-from-deployment",
			LastCheckedAt: now.Add(-time.Minute), EventSequence: 10},
		{TenantID: h.tenant, EndpointID: endpointID, Address: "127.0.0.1:10448", Vantage: "relay",
			Reached: true, Mismatch: "fingerprint", ExpectedFingerprint: "old-before-deployment", ObservedFingerprint: "replacement-from-deployment",
			LastCheckedAt: now, EventSequence: 11},
	} {
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			return h.store.ApplyEndpointVerificationTx(ctx, tx, row)
		}); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := h.srv.queueEndpointVerificationSweep(ctx, h.tenant); err != nil || n != 1 {
		t.Fatalf("queue sweep: count=%d error=%v", n, err)
	}
	var raw []byte
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT payload FROM outbox WHERE tenant_id=$1 AND destination=$2`, h.tenant, relay.KindEndpointVerify).Scan(&raw)
	}); err != nil {
		t.Fatal(err)
	}
	var intent relay.EndpointVerifyIntent
	if err := json.Unmarshal(raw, &intent); err != nil {
		t.Fatal(err)
	}
	if len(intent.Endpoints) != 1 || intent.Endpoints[0].EndpointID != endpointID || intent.Endpoints[0].Fingerprint != "replacement-from-deployment" {
		t.Fatalf("renewed endpoint still compared against obsolete relay expectation: %+v", intent.Endpoints)
	}
}

func TestEndpointSweepKeepsDeploymentFailuresRollbackAndRelayOnlyExpectations(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	ctx := t.Context()
	now := time.Now().UTC()
	want := map[string]string{
		"failed-reload":           "newly-deployed",
		"restored-predecessor":    "restored-older-leaf",
		"relay-only":              "original-expected",
		"newer-relay-drift":       "deployed-before-drift",
		"empty-local-expectation": "relay-known-expected",
	}
	rows := []store.EndpointVerification{
		{EndpointID: "failed-reload", Vantage: "local", Mismatch: "fingerprint", ExpectedFingerprint: "newly-deployed", ObservedFingerprint: "reload-did-not-activate"},
		{EndpointID: "failed-reload", Vantage: "relay", Mismatch: "fingerprint", ExpectedFingerprint: "obsolete", ObservedFingerprint: "reload-did-not-activate"},
		{EndpointID: "restored-predecessor", Vantage: "local", ExpectedFingerprint: "restored-older-leaf", ObservedFingerprint: "restored-older-leaf"},
		{EndpointID: "restored-predecessor", Vantage: "relay", Mismatch: "fingerprint", ExpectedFingerprint: "superseded-successor", ObservedFingerprint: "restored-older-leaf"},
		{EndpointID: "relay-only", Vantage: "relay", Mismatch: "fingerprint", ExpectedFingerprint: "original-expected", ObservedFingerprint: "unapproved-peer"},
		{EndpointID: "newer-relay-drift", Vantage: "local", ExpectedFingerprint: "deployed-before-drift", ObservedFingerprint: "deployed-before-drift"},
		{EndpointID: "newer-relay-drift", Vantage: "relay", Mismatch: "fingerprint", ExpectedFingerprint: "obsolete", ObservedFingerprint: "unapproved-new-peer"},
		{EndpointID: "empty-local-expectation", Vantage: "local"},
		{EndpointID: "empty-local-expectation", Vantage: "relay", Mismatch: "fingerprint", ExpectedFingerprint: "relay-known-expected", ObservedFingerprint: "unapproved-peer"},
	}
	for n, row := range rows {
		row.TenantID, row.Address = h.tenant, "127.0.0.1:10448"
		row.Reached, row.LastCheckedAt, row.EventSequence = true, now.Add(time.Duration(n)*time.Second), uint64(n+1)
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			return h.store.ApplyEndpointVerificationTx(ctx, tx, row)
		}); err != nil {
			t.Fatal(err)
		}
	}
	// A local row from another tenant must never become this tenant's expected
	// identity, even when its endpoint identifier is identical.
	const otherTenant = "03700000-0000-4000-8000-000000000002"
	if err := h.store.UpsertTenant(ctx, store.Tenant{TenantID: otherTenant, Name: "foreign sweep", CreatedAt: now, EventSeq: 1}); err != nil {
		t.Fatal(err)
	}
	if err := h.store.WithTenant(ctx, otherTenant, func(tx pgx.Tx) error {
		return h.store.ApplyEndpointVerificationTx(ctx, tx, store.EndpointVerification{
			TenantID: otherTenant, EndpointID: "relay-only", Address: "127.0.0.1:10449", Vantage: "local",
			Reached: true, ExpectedFingerprint: "foreign-leaf", ObservedFingerprint: "foreign-leaf", LastCheckedAt: now, EventSequence: 1,
		})
	}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if n, err := h.srv.queueEndpointVerificationSweep(ctx, h.tenant); err != nil || n != len(want) {
			t.Fatalf("queue sweep: count=%d error=%v", n, err)
		}
	}
	var raw []byte
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id=$1 AND destination=$2`, h.tenant, relay.KindEndpointVerify).Scan(&count); err != nil {
			return err
		}
		if count != 1 {
			t.Fatalf("replayed sweep created %d jobs", count)
		}
		return tx.QueryRow(ctx, `SELECT payload FROM outbox WHERE tenant_id=$1 AND destination=$2`, h.tenant, relay.KindEndpointVerify).Scan(&raw)
	}); err != nil {
		t.Fatal(err)
	}
	var intent relay.EndpointVerifyIntent
	if err := json.Unmarshal(raw, &intent); err != nil {
		t.Fatal(err)
	}
	if len(intent.Endpoints) != len(want) {
		t.Fatalf("lost or duplicated an endpoint: %+v", intent.Endpoints)
	}
	for _, endpoint := range intent.Endpoints {
		if endpoint.Fingerprint != want[endpoint.EndpointID] || endpoint.Address != "127.0.0.1:10448" {
			t.Fatalf("lost deployed intent, blessed drift, or crossed tenant: %+v", endpoint)
		}
	}
}
