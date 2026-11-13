// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// ISE-O1: a takedown of a certificate whose key the appliance generated
// names the job's key object, derived from the certificate's issuance key and
// the destination, so the relay removes it with the certificate; a
// certificate whose key a deploy installed names none; an appliance
// certificate that does not say which job made its key is refused before
// anything is queued; and a caller cannot name the object itself.
func TestTakedownOfAnApplianceKeyCertificateNamesItsKeyObjectISEO1(t *testing.T) {
	ctx := t.Context()
	s := newStore(t)
	mustRegisterTenant(t, s, tenantA)
	o := orchestrator.NewOrchestrator(openLog(t), s, orchestrator.NewOutbox(s))
	if _, err := o.CreateOwner(ctx, tenantA, "service", "takedown fixture", ""); err != nil {
		t.Fatal(err)
	}
	const targetID = "0f3c9a71-2d4e-4b8a-9c1d-5e6f7a8b9c0d"
	fp := func(b byte) string { return hex.EncodeToString([]byte(strings.Repeat(string(rune(b)), 32))) }
	appliance, deployed, orphan := fp('a'), fp('d'), fp('o')
	for _, cert := range []store.Certificate{
		{Fingerprint: appliance, Serial: "12", Source: "issued", KeyOrigin: "appliance", KeyStorage: "appliance",
			KeyExportable: "exportable", KeyGeneratedBy: "dmz-relay", IssuanceIdempotencyKey: "agentcsr:61:0:0123456789abcdef"},
		{Fingerprint: deployed, Serial: "13", Source: "import"},
		{Fingerprint: orphan, Serial: "14", Source: "issued", KeyOrigin: "appliance", KeyStorage: "appliance",
			KeyExportable: "exportable", KeyGeneratedBy: "dmz-relay", IssuanceIdempotencyKey: "imported-elsewhere"},
	} {
		if _, err := o.RecordCertificate(ctx, tenantA, cert); err != nil {
			t.Fatalf("record %s: %v", cert.Fingerprint, err)
		}
	}
	target, err := o.UpsertDeploymentTarget(ctx, tenantA, store.DeploymentTarget{ID: targetID, Name: "web-prod", Type: "netscaler",
		Config: json.RawMessage(`{"address":"10.0.0.5"}`), Enabled: true, EnabledSet: true})
	if err != nil {
		t.Fatal(err)
	}
	queuedKeyObject := func(fingerprint, key string) (string, error) {
		t.Helper()
		receipt, err := o.RequestConnectorTakedown(ctx, tenantA, orchestrator.ConnectorTakedownRequest{
			Connector: "netscaler", Target: "web-prod", TargetID: targetID, TargetRevision: target.RevisionID,
			Fingerprint: fingerprint, TargetConfig: target.Config, IdempotencyKey: key,
			KeyObject: "trstctl-attacker-j1",
		})
		if err != nil {
			return "", err
		}
		var payload []byte
		if err := s.SystemPool().QueryRow(ctx, `SELECT payload FROM outbox WHERE id = $1`, *receipt.OutboxID).Scan(&payload); err != nil {
			t.Fatal(err)
		}
		var command struct {
			KeyObject string `json:"key_object"`
		}
		if err := json.Unmarshal(payload, &command); err != nil {
			t.Fatal(err)
		}
		return command.KeyObject, nil
	}
	if object, err := queuedKeyObject(appliance, "iseo1-appliance"); err != nil || object != connector.ApplianceKeyObjectName(targetID, 61) {
		t.Fatalf("appliance key object = %q, %v; want %q", object, err, connector.ApplianceKeyObjectName(targetID, 61))
	}
	if object, err := queuedKeyObject(deployed, "iseo1-deployed"); err != nil || object != "" {
		t.Fatalf("deploy-installed certificate key object = %q, %v; want none", object, err)
	}
	if _, err := queuedKeyObject(orphan, "iseo1-orphan"); err == nil || !strings.Contains(err.Error(), "renewal job") {
		t.Fatalf("appliance certificate without its job = %v, want a refusal naming the job", err)
	}
}
