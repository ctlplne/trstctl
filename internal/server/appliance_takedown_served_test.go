// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
)

// ISE-O1 Done-when (served): a certificate whose key the appliance generated
// through the pinned relay is taken down with that key. After the relay's
// renewal installs it, a takedown requested through the API queues a relay
// command naming the renewal job's key object, derived from the issuance
// record; the relay's connector removes that object and its CSR with the
// certificate (proven per family against each appliance's stand-in).
func TestServedTakedownOfAnApplianceKeyCertificateNamesItsKeyObjectISEO1(t *testing.T) {
	ctx := t.Context()
	h, target, _ := queueApplianceFirstIssuance(t)
	job := claimOneRenewal(t, ctx, h)
	key, err := crypto.GenerateHostSubjectKey("vip.example.test", []string{"vip.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	issued, err := h.client.SignJobCSR(ctx, &transport.SignJobCSRRequest{JobID: job.JobID, Attempt: job.Attempt, CSRDER: key.CSRDER})
	if err != nil {
		t.Fatalf("sign the appliance's CSR: %v", err)
	}
	id := h.identity.Identity()
	report, err := transport.SignedReportWithCustody(id, id.TenantID(), id.CommonName(), job.JobID, job.Attempt,
		transport.JobOutcomeExecuted, "installed against the appliance key", "", issued.Fingerprint, relay.ApplianceRenewCustody(id.CommonName()), time.Now().UTC().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if accepted, err := h.client.ReportJobResult(ctx, report); err != nil || !accepted.Accepted {
		t.Fatalf("appliance install report = %+v, %v", accepted, err)
	}

	operator := seedScopedToken(t, h.store, h.tenant, "connectors:write", "connectors:read", "certs:read")
	status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/revocation/rogue-certificates/takedown", operator, "iseo1-takedown",
		map[string]any{"fingerprint": issued.Fingerprint, "target_id": target.ID, "reason": "retire the appliance key"})
	if status != http.StatusAccepted {
		t.Fatalf("takedown = %d %s", status, body)
	}
	var payload []byte
	if err := h.store.SystemPool().QueryRow(ctx, `SELECT payload FROM outbox WHERE tenant_id = $1 AND destination = $2`,
		h.tenant, orchestrator.DestinationConnectorTakedown).Scan(&payload); err != nil {
		t.Fatalf("no takedown was queued: %v", err)
	}
	var intent relay.TakedownIntent
	if err := json.Unmarshal(payload, &intent); err != nil {
		t.Fatal(err)
	}
	want := connector.ApplianceKeyObjectName(target.ID, job.JobID)
	if want == "" || intent.KeyObject != want || intent.Fingerprint != issued.Fingerprint || intent.Connector != "netscaler" {
		t.Fatalf("takedown intent = %+v, want key object %q", intent, want)
	}
	t.Logf("ISEO1_TAKEDOWN_KEY_OBJECT_OK object=%s", intent.KeyObject)
}
