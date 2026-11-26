// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/delegation"
)

func TestHistoricalSignedDelegationOverflowQuarantinesOnlyItsTenant(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, os.Getenv("TRSTCTL_STORE_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	const poisoned = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	const healthy = "ffffffff-ffff-4fff-8fff-ffffffffffff"
	if _, err := st.SystemPool().Exec(ctx, `DELETE FROM projection_tenant_quarantines WHERE tenant_id IN ($1,$2)`, poisoned, healthy); err != nil {
		t.Fatal(err)
	}
	key, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	receipt := delegation.Receipt{Command: delegation.Command{
		TenantID: poisoned, OperationID: "historical-overflow", Kind: "scope", ScopeID: "root",
		EpochFloor: uint64(math.MaxInt64) + 1,
	}, AppliedFloor: uint64(math.MaxInt64) + 1}
	body, err := receipt.SignedBody()
	if err != nil {
		t.Fatal(err)
	}
	receipt.PublicKeyDER = key.Public().DER
	receipt.Signature, err = key.Sign(body, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	event, err := succession.Encode(succession.DelegationAppliedV1{TenantID: poisoned, ReceiptJSON: encoded})
	if err != nil {
		t.Fatal(err)
	}
	event.Sequence = 19
	q := newTenantPoisonQuarantine(st)
	if skip, err := q.skip(ctx, event); err != nil || !skip {
		t.Fatalf("historical signed overflow skipped=%v err=%v", skip, err)
	}
	if quarantined, err := st.ProjectionTenantQuarantined(ctx, poisoned); err != nil || !quarantined {
		t.Fatalf("poisoned tenant quarantine=%v err=%v", quarantined, err)
	}
	other := events.Event{Sequence: 20, TenantID: healthy, Type: EventOwnerCreated, Data: []byte(`{}`)}
	if skip, err := q.skip(ctx, other); err != nil || skip {
		t.Fatalf("healthy tenant skipped=%v err=%v", skip, err)
	}
	invalidReceipt := receipt
	invalidReceipt.TenantID = healthy // signed body no longer matches
	invalidJSON, err := json.Marshal(invalidReceipt)
	if err != nil {
		t.Fatal(err)
	}
	badSignature, err := succession.Encode(succession.DelegationAppliedV1{TenantID: healthy, ReceiptJSON: invalidJSON})
	if err != nil {
		t.Fatal(err)
	}
	badSignature.Sequence = 21
	if skip, err := q.skip(ctx, badSignature); err != nil || skip {
		t.Fatalf("unverified overflow was quarantined: skipped=%v err=%v", skip, err)
	}
	const futureTenant = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaee"
	futureReceipt := receipt
	futureReceipt.TenantID = futureTenant
	futureBody, err := futureReceipt.SignedBody()
	if err != nil {
		t.Fatal(err)
	}
	futureReceipt.Signature, err = key.Sign(futureBody, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	futureJSON, err := json.Marshal(futureReceipt)
	if err != nil {
		t.Fatal(err)
	}
	future, err := succession.Encode(succession.DelegationAppliedV1{TenantID: futureTenant, ReceiptJSON: futureJSON})
	if err != nil {
		t.Fatal(err)
	}
	future.Sequence, future.SchemaVersion = 22, succession.DelegationAppliedSchemaV1+1
	if skip, err := q.skip(ctx, future); err != nil || skip {
		t.Fatalf("future-version delegation event was quarantined: skipped=%v err=%v", skip, err)
	}
}
