// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"encoding/json"
	"testing"
	"time"
)

func TestProviderAccessOmitsAbsentLifecycleTimes(t *testing.T) {
	row := OperatorAccess{Identity: OperatorIdentity{ID: "operator", Active: true}, Delegations: []DelegationRecord{{OperatorID: "operator", CustomerID: "customer", Operation: OpRead}}}
	raw, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	var fields struct {
		Identity    map[string]json.RawMessage   `json:"identity"`
		Delegations []map[string]json.RawMessage `json:"delegations"`
	}
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"expires_at", "last_used_at", "revoked_at"} {
		if _, exists := fields.Delegations[0][name]; exists {
			t.Errorf("absent %s was serialized as a lifecycle fact", name)
		}
	}
	if _, exists := fields.Identity["deprovisioned_at"]; exists {
		t.Error("active employee has a serialized deprovisioning date")
	}
	actual := time.Date(2026, 9, 16, 18, 0, 0, 0, time.UTC)
	row.Identity.DeprovisionedAt = actual
	row.Delegations[0].ExpiresAt = actual
	row.Delegations[0].LastUsedAt = actual
	row.Delegations[0].RevokedAt = actual
	raw, err = json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	var decoded OperatorAccess
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.Identity.DeprovisionedAt.Equal(actual) || !decoded.Delegations[0].ExpiresAt.Equal(actual) || !decoded.Delegations[0].LastUsedAt.Equal(actual) || !decoded.Delegations[0].RevokedAt.Equal(actual) {
		t.Fatal("real lifecycle times were lost")
	}
}
