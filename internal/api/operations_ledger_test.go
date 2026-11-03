// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

// A245: nothing turns green on an HTTP 200 or an outbox receipt alone, a
// stranded or quarantined effect reads uncertain, and approvals read as
// review states.
func TestOperationStatesNeedConsumerEvidenceA245(t *testing.T) {
	outbox := int64(7)
	for name, tc := range map[string]struct {
		row      store.OperationLedgerRow
		adoption string
		want     string
	}{
		"delivery receipt alone":         {store.OperationLedgerRow{Source: "connector_delivery", Status: "delivered", Fingerprint: "f"}, "", opStateDelivered},
		"delivery seen at an endpoint":   {store.OperationLedgerRow{Source: "connector_delivery", Status: "delivered", Fingerprint: "f", ObservedVantage: "relay"}, "", opStateVerified},
		"delivery read back":             {store.OperationLedgerRow{Source: "connector_delivery", Status: "verified"}, "", opStateVerified},
		"delivery rolled back":           {store.OperationLedgerRow{Source: "connector_delivery", Status: "rolled_back"}, "", opStateRecovered},
		"delivery failed":                {store.OperationLedgerRow{Source: "connector_delivery", Status: "failed", Detail: "target refused"}, "", opStateFailed},
		"containment unconfirmed":        {store.OperationLedgerRow{Source: "connector_delivery", Status: "containment_unverified"}, "", opStateUncertain},
		"dry run":                        {store.OperationLedgerRow{Source: "connector_delivery", Status: "dry_run_planned"}, "", opStateReviewed},
		"rotation succeeded, no proof":   {store.OperationLedgerRow{Source: "certificate_rotation", Status: "succeeded", Fingerprint: "f"}, "", opStateDelivered},
		"rotation succeeded, read back":  {store.OperationLedgerRow{Source: "certificate_rotation", Status: "succeeded", Fingerprint: "f", ReadBack: true}, "", opStateVerified},
		"rotation queued":                {store.OperationLedgerRow{Source: "certificate_rotation", Status: "running", OutboxID: &outbox, OutboxStatus: "pending"}, "", opStateQueued},
		"rotation executing":             {store.OperationLedgerRow{Source: "certificate_rotation", Status: "running", OutboxID: &outbox, OutboxStatus: "processing"}, "", opStateExecuting},
		"rotation lease ran out":         {store.OperationLedgerRow{Source: "certificate_rotation", Status: "running", OutboxID: &outbox, OutboxStatus: "processing", OutboxLeaseExpired: true}, "", opStateUncertain},
		"rotation quarantined":           {store.OperationLedgerRow{Source: "certificate_rotation", Status: "running", OutboxID: &outbox, Quarantined: true}, "", opStateUncertain},
		"secret rotated, nobody named":   {store.OperationLedgerRow{Source: "secret_rotation", Status: store.SecretStaticRotationCompleted}, consumerAdoptionNotRequested, opStateDelivered},
		"secret rotated, consumers lag":  {store.OperationLedgerRow{Source: "secret_rotation", Status: store.SecretStaticRotationCompleted}, consumerAdoptionPending, opStateDelivered},
		"secret rotated, consumers read": {store.OperationLedgerRow{Source: "secret_rotation", Status: store.SecretStaticRotationCompleted}, consumerAdoptionAdopted, opStateVerified},
		"secret verified, not retired":   {store.OperationLedgerRow{Source: "secret_rotation", Status: store.SecretStaticRotationVerified}, "", opStateDelivered},
		"secret staged":                  {store.OperationLedgerRow{Source: "secret_rotation", Status: store.SecretStaticRotationStaged}, "", opStateExecuting},
		"secret rolled back":             {store.OperationLedgerRow{Source: "secret_rotation", Status: store.SecretStaticRotationRolledBack}, "", opStateRecovered},
		"secret retirement held":         {store.OperationLedgerRow{Source: "secret_rotation", Status: store.SecretStaticRotationRetirePending}, "", opStateFailed},
		"approval pending":               {store.OperationLedgerRow{Source: "approval", Status: "pending"}, "", opStateAwaitingApproval},
		"approval approved":              {store.OperationLedgerRow{Source: "approval", Status: "approved"}, "", opStateReviewed},
		"approval superseded":            {store.OperationLedgerRow{Source: "approval", Status: "superseded"}, "", opStateFailed},
	} {
		if got, reason := normalizeOperation(tc.row, tc.adoption); got != tc.want || reason == "" {
			t.Errorf("%s: state %q (%q), want %q", name, got, reason, tc.want)
		}
	}
}

func TestOperationCursorRoundTripsA245(t *testing.T) {
	row := store.OperationLedgerRow{Source: "approval", ID: "a1", UpdatedAt: time.Now()}
	c, err := decodeOperationCursor(encodeOperationCursor(row))
	if err != nil || c == nil || c.Key != "approval:a1" {
		t.Fatalf("cursor = %+v %v", c, err)
	}
	if _, err := decodeOperationCursor("not-a-cursor"); err == nil {
		t.Fatal("a malformed cursor was accepted")
	}
}
