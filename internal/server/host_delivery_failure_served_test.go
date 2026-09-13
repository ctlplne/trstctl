// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// An initial host failure may precede both the CSR and certificate. The ordinary
// identity API must still expose the failed attempt, then converge on recovery.
func TestServedInitialHostFailureIsVisibleBeforeCertificateAndAfterRecovery(t *testing.T) {
	h, _, identityID := servedHostRevocationFixture(t)
	ctx := t.Context()
	token := seedScopedToken(t, h.store, h.tenant, "connectors:read")
	job := claimOneRenewal(t, ctx, h)
	const detail = "host signing refused: requested DNS name does not match the approved profile"
	failed := h.report(t, job.JobID, job.Attempt, transport.JobOutcomeFailed, detail, "")
	result, err := h.client.ReportJobResult(ctx, failed)
	if err != nil || !result.Accepted {
		t.Fatalf("failure report: result=%v err=%v", result, err)
	}
	read := func() map[string]any {
		t.Helper()
		code, body := secretsReqKey(t, h.servedHarness, http.MethodGet,
			"/api/v1/connectors/deliveries?identity_id="+identityID, token, "", nil)
		var page struct {
			Items []map[string]any `json:"items"`
		}
		if code != http.StatusOK || json.Unmarshal(body, &page) != nil || len(page.Items) != 1 {
			t.Fatalf("identity failure evidence: HTTP%d body=%s", code, body)
		}
		return page.Items[0]
	}
	first := read()
	if first["status"] != "failed" || first["attempts"] != float64(1) || first["identity_id"] != identityID ||
		first["outbox_id"] != float64(job.JobID) || first["fingerprint"] != "" ||
		!strings.Contains(first["detail"].(string), detail) || first["rollback_ref"] != "" {
		t.Fatalf("failure was hidden or claimed delivery: %+v", first)
	}
	// The receipt is a tenant-scoped projection, not a new cross-tenant route.
	otherToken := seedScopedToken(t, h.store, "22222222-2222-4222-8222-222222222222", "connectors:read")
	code, body := secretsReqKey(t, h.servedHarness, http.MethodGet,
		"/api/v1/connectors/deliveries/"+first["id"].(string), otherToken, "", nil)
	if code != http.StatusNotFound {
		t.Fatalf("another tenant can read failure: HTTP%d body=%s", code, body)
	}
	if duplicate, err := h.client.ReportJobResult(ctx, failed); err != nil || duplicate.Accepted {
		t.Fatalf("released failure replay: result=%v err=%v", duplicate, err)
	}
	// Advance only the test-owned retry deadline; never change the host clock.
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE outbox SET agent_next_attempt_at=$3 WHERE tenant_id=$1 AND id=$2`, h.tenant, job.JobID, time.Now().Add(-time.Second))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	next := claimOneRenewal(t, ctx, h)
	if next.JobID != job.JobID || next.Attempt != 2 {
		t.Fatalf("recovery changed command/generation: %+v", next)
	}
	key, err := crypto.GenerateHostSubjectKey("mail.revocation.test", []string{"mail.revocation.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	issued, err := h.client.SignJobCSR(ctx, &transport.SignJobCSRRequest{JobID: next.JobID, Attempt: next.Attempt, CSRDER: key.CSRDER})
	if err != nil {
		t.Fatal(err)
	}
	id := h.identity.Identity()
	record := custody.Record{Origin: custody.OriginHostAgent, Storage: custody.StorageFile, Exportable: custody.Exportable, GeneratedBy: id.CommonName()}
	success, err := transport.SignedReportWithCustody(id, id.TenantID(), id.CommonName(), next.JobID, next.Attempt,
		transport.JobOutcomeVerified, "", "", issued.Fingerprint, record, time.Now().UTC().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if result, err := h.client.ReportJobResult(ctx, success); err != nil || !result.Accepted {
		t.Fatalf("recovery result: result=%v err=%v", result, err)
	}
	last := read()
	if last["id"] != first["id"] || last["status"] != "delivered" || last["attempts"] != float64(2) || last["fingerprint"] != issued.Fingerprint {
		t.Fatalf("recovery lost canonical receipt: %+v", last)
	}
	var failures, deliveries int
	if err := h.log.Replay(ctx, 0, func(event events.Event) error {
		if event.TenantID != h.tenant || event.Type != projections.EventConnectorDeliveryRecorded {
			return nil
		}
		var receipt projections.ConnectorDeliveryRecorded
		if err := json.Unmarshal(event.Data, &receipt); err != nil {
			return err
		}
		if receipt.OutboxID != nil && *receipt.OutboxID == job.JobID {
			switch receipt.Status {
			case "failed":
				failures++
			case "delivered":
				deliveries++
			}
		}
		return nil
	}); err != nil || failures != 1 || deliveries != 1 {
		t.Fatalf("immutable failure/recovery history: failures=%d deliveries=%d err=%v", failures, deliveries, err)
	}
}
