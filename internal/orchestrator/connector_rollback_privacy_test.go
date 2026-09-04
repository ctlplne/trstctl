// SPDX-License-Identifier: MPL-2.0

package orchestrator_test

import (
	"context"
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
)

// The production log uses a closed privacy vocabulary. A rollback that works
// in the ordinary test log but is absent from that vocabulary becomes a 500 in
// the real binary before its outbox command can be committed.
func TestConnectorRollbackRequestedFitsProductionPrivacyCatalog(t *testing.T) {
	log := openLogWithOptions(t, events.WithRequiredPrivacyEventPolicies())
	payload, err := json.Marshal(orchestrator.ConnectorRollbackRequest{
		Connector:              "apache",
		Target:                 "payments listener",
		TargetID:               "target-1",
		IdentityID:             "identity-1",
		TargetConfig:           json.RawMessage(`{"cert_path":"/etc/apache/payments.crt","verify_server_name":"payments.example.test"}`),
		PredecessorFingerprint: "old-fingerprint",
		PredecessorSerial:      "01",
		SuccessorFingerprint:   "new-fingerprint",
		Reason:                 "restore after failed listener check",
		RequestedBy:            "operator@example.test",
		RequiredAgentID:        "agent-1",
		RequiredAgentRole:      "host",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(context.Background(), events.Event{
		Type: orchestrator.EventConnectorRollbackRequested, TenantID: tenantA, Data: payload,
	}); err != nil {
		t.Fatalf("production privacy gate rejected connector rollback event: %v", err)
	}
}
