// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"testing"

	"trstctl.com/trstctl/internal/store"
)

// A244: the inventory tells the six states apart from the identity's status
// and its delivery evidence.
func TestInventoryStateTellsTheSixStatesApartA244(t *testing.T) {
	served := store.InventoryEvidence{Fingerprint: "f", ReceiptStatus: "delivered", Active: true, ObservedVantage: "relay"}
	for _, tc := range []struct {
		status string
		e      store.InventoryEvidence
		found  bool
		want   string
	}{
		{"requested", store.InventoryEvidence{}, false, "requested"},
		{"issued", store.InventoryEvidence{}, false, "issued"},
		{"deployed", store.InventoryEvidence{Fingerprint: "f", ReceiptStatus: "delivered", Active: false}, true, "issued"},
		{"deployed", store.InventoryEvidence{Fingerprint: "f", ReceiptStatus: "delivered", Active: true}, true, "delivered"},
		{"deployed", store.InventoryEvidence{Fingerprint: "f", ReceiptStatus: "verified", Active: true}, true, "served"},
		{"renewing", served, true, "served"},
		{"renewal_failed", served, true, "served"},
		{"revoked", served, true, "revoked"},
		{"retired", served, true, "retired"},
	} {
		if got := inventoryState(tc.status, tc.e, tc.found); got != tc.want {
			t.Errorf("%s %+v: %s, want %s", tc.status, tc.e, got, tc.want)
		}
	}
}
