// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"encoding/json"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// A122: a rollback to a predecessor whose key the appliance generated names
// the appliance object holding that key, derived from the certificate's
// issuance key and the destination; a predecessor whose key a deploy
// installed names none; and an appliance predecessor that does not say which
// job made its key is refused before anything is queued.
func TestRollbackToAnApplianceGeneratedPredecessorNamesItsKeyObject(t *testing.T) {
	ctx := t.Context()
	s := newStore(t)
	mustRegisterTenant(t, s, tenantA)
	o := orchestrator.NewOrchestrator(openLog(t), s, orchestrator.NewOutbox(s))
	if _, err := o.CreateOwner(ctx, tenantA, "service", "rollback fixture", ""); err != nil {
		t.Fatal(err)
	}
	const targetID = "0f3c9a71-2d4e-4b8a-9c1d-5e6f7a8b9c0d"
	for _, cert := range []store.Certificate{
		{Fingerprint: "appliance-leaf", Serial: "02", Source: "issued", KeyOrigin: "appliance", KeyStorage: "appliance",
			KeyExportable: "exportable", KeyGeneratedBy: "dmz-relay", IssuanceIdempotencyKey: "agentcsr:41:0:0123456789abcdef"},
		{Fingerprint: "deployed-leaf", Serial: "03", Source: "import"},
		{Fingerprint: "appliance-orphan", Serial: "04", Source: "issued", KeyOrigin: "appliance", KeyStorage: "appliance",
			KeyExportable: "exportable", KeyGeneratedBy: "dmz-relay", IssuanceIdempotencyKey: "imported-elsewhere"},
	} {
		if _, err := o.RecordCertificate(ctx, tenantA, cert); err != nil {
			t.Fatalf("record %s: %v", cert.Fingerprint, err)
		}
	}
	queuedKeyObject := func(predecessor string) (string, error) {
		t.Helper()
		queued, err := o.RequestConnectorRollback(ctx, tenantA, orchestrator.ConnectorRollbackRequest{
			Connector: "netscaler", Target: "web-prod", TargetID: targetID,
			PredecessorFingerprint: predecessor, SuccessorFingerprint: "successor-leaf",
		})
		if err != nil {
			return "", err
		}
		var payload []byte
		if err := s.SystemPool().QueryRow(ctx, `SELECT payload FROM outbox WHERE id = $1`, queued.OutboxID).Scan(&payload); err != nil {
			t.Fatal(err)
		}
		var command struct {
			PredecessorKeyObject string `json:"predecessor_key_object"`
		}
		if err := json.Unmarshal(payload, &command); err != nil {
			t.Fatal(err)
		}
		return command.PredecessorKeyObject, nil
	}
	if object, err := queuedKeyObject("appliance-leaf"); err != nil || object != connector.ApplianceKeyObjectName(targetID, 41) {
		t.Fatalf("appliance predecessor key object = %q, %v; want %q", object, err, connector.ApplianceKeyObjectName(targetID, 41))
	}
	if object, err := queuedKeyObject("deployed-leaf"); err != nil || object != "" {
		t.Fatalf("deploy-installed predecessor key object = %q, %v; want none", object, err)
	}
	if _, err := queuedKeyObject("appliance-orphan"); err == nil || !strings.Contains(err.Error(), "renewal job") {
		t.Fatalf("appliance predecessor without its job = %v, want a refusal naming the job", err)
	}
}
