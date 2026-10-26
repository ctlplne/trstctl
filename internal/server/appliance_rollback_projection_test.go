// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/store"
)

// A122: the relay's view of a rollback job keeps the predecessor's appliance
// key object. The projection is an allow-list, so a field it does not name
// never reaches the relay and the re-bind would look for a key that a deploy
// never installed.
func TestRollbackProjectionCarriesThePredecessorApplianceKeyObject(t *testing.T) {
	payload, err := json.Marshal(map[string]any{
		"connector": "netscaler", "target": "web-prod", "target_id": "0f3c9a71-2d4e-4b8a-9c1d-5e6f7a8b9c0d",
		"target_config":           map[string]string{"endpoint": "https://ns.example.test", "password_ref": "secret://connectors/ns"},
		"predecessor_fingerprint": "appliance-leaf", "predecessor_key_object": "trstctl-0f3c9a71-j41",
	})
	if err != nil {
		t.Fatal(err)
	}
	projected, err := projectRollbackIntent(store.AgentJob{Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	var intent struct {
		PredecessorKeyObject string `json:"predecessor_key_object"`
	}
	if err := json.Unmarshal(projected, &intent); err != nil || intent.PredecessorKeyObject != "trstctl-0f3c9a71-j41" {
		t.Fatalf("relay rollback intent = %s (%v), want the predecessor's appliance key object", projected, err)
	}
}
