// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
)

// A103: a scheduled report announces each completed run beyond the archive.
// A schedule names configured notification channels and one ServiceNow ticket
// on an operator-approved binding; the completion queues one notice per
// channel and the ticket in its own transaction, each naming the run, its
// digest and its download route and never the report body. Unconfigured
// channels and unapproved bindings are refused, a binding withdrawn later
// skips the ticket on the run's receipt, and reconciliation adds nothing.
func TestServedScheduledReportDispatchAnnouncesCompletedRuns(t *testing.T) {
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	signer := &reportWorkerSigner{key: key}
	archiveRoot := t.TempDir()
	// #nosec G302 -- owner execute is required to traverse this private test directory.
	if err := os.Chmod(archiveRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	const instanceURL, tokenRef = "https://grc.service-now.example.test", "secret://itsm/grc-token" // #nosec G101 -- fabricated fixture reference; no value is real (CWE-798)
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AuditArchiveDir = archiveRoot
		d.APIOptions = append(d.APIOptions, api.WithComplianceEvidence(signer))
		d.ServiceNowBindings = []api.ServiceNowBinding{{InstanceURL: instanceURL, TokenRef: tokenRef}}
	})
	ctx := t.Context()
	admin := seedScopedToken(t, h.store, h.tenant, "audit:write", "audit:read", "notifications:read", "notifications:write")
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/notification-channels", admin, "a103-channel", map[string]any{
		"id": "webhook", "channel_type": "webhook", "label": "GRC intake", "endpoint_url": "https://grc.example.test/hooks/trstctl", "enabled": true,
	}); status != http.StatusCreated {
		t.Fatalf("create channel = %d %s", status, body)
	}
	dispatch := map[string]any{
		"channels": []string{" Webhook ", "webhook"},
		"ticket":   map[string]any{"provider": "servicenow", "instance_url": instanceURL + "/", "table": "sc_task", "token_ref": tokenRef},
	}
	definition := map[string]any{"framework": "soc2", "name": "monthly SOC 2 pack", "report_type": "audit_summary", "interval_seconds": 3600, "dispatch": dispatch}

	// Refusals: a channel this tenant has not configured, and a ticket off the
	// operator's approved bindings.
	for name, bad := range map[string]map[string]any{
		"unknown channel":     {"channels": []string{"ghost-channel"}},
		"unapproved binding":  {"ticket": map[string]any{"provider": "servicenow", "instance_url": "https://attacker.example.test", "token_ref": tokenRef}},
		"unsupported tracker": {"ticket": map[string]any{"provider": "jira", "instance_url": instanceURL, "token_ref": tokenRef}},
	} {
		body := map[string]any{"framework": "soc2", "name": "refused " + name, "report_type": "audit_summary", "interval_seconds": 3600, "dispatch": bad}
		status, resp := secretsReqKey(t, h, http.MethodPost, "/api/v1/compliance/report-schedules", admin, "a103-refused-"+name, body)
		if status != http.StatusUnprocessableEntity && status != http.StatusBadRequest {
			t.Fatalf("%s: create = %d %s", name, status, resp)
		}
	}

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/compliance/report-schedules/preview", admin, definition)
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"ready":true`)) || !bytes.Contains(body, []byte("notification channel webhook")) ||
		!bytes.Contains(body, []byte("ServiceNow sc_task ticket")) {
		t.Fatalf("dispatch preview = %d %s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/compliance/report-schedules", admin, "a103-create", definition)
	var created struct {
		Dispatch struct {
			Channels []string `json:"channels"`
			Ticket   struct {
				InstanceURL string `json:"instance_url"`
				Table       string `json:"table"`
			} `json:"ticket"`
		} `json:"dispatch"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &created) != nil || len(created.Dispatch.Channels) != 1 ||
		created.Dispatch.Channels[0] != "webhook" || created.Dispatch.Ticket.InstanceURL != instanceURL || created.Dispatch.Ticket.Table != "sc_task" {
		t.Fatalf("create = %d %s", status, body)
	}

	// Two due schedules: one with an approved ticket, one whose stored ticket
	// is no longer approved (as if the operator withdrew the binding).
	due := time.Now().UTC().Add(-time.Hour)
	seed := func(id, name, ticketURL string) {
		t.Helper()
		data, err := json.Marshal(map[string]any{"id": id, "framework": "soc2", "name": name, "report_type": "audit_summary",
			"interval_seconds": 3600, "enabled": true, "delivery": "audit_export",
			"dispatch": map[string]any{"channels": []string{"webhook"},
				"ticket": map[string]any{"provider": "servicenow", "instance_url": ticketURL, "table": "incident", "token_ref": tokenRef}}})
		if err != nil {
			t.Fatal(err)
		}
		ev, err := h.log.Append(ctx, events.Event{TenantID: h.tenant, Type: projections.EventComplianceReportScheduleUpserted,
			Time: due.Add(-time.Hour), SchemaVersion: 1, Data: data})
		if err != nil {
			t.Fatal(err)
		}
		if err := projections.New(h.store).Apply(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	const approvedID, withdrawnID = "4d5a8f8e-0b1c-4e0a-9d3c-1a2b3c4d5e01", "4d5a8f8e-0b1c-4e0a-9d3c-1a2b3c4d5e02"
	seed(approvedID, "approved pack", instanceURL)
	seed(withdrawnID, "withdrawn pack", "https://retired.service-now.example.test")
	if processed, err := h.srv.RunComplianceReportsOnce(ctx); err != nil || processed != 2 {
		t.Fatalf("due sweep = %d, %v", processed, err)
	}
	run, err := h.store.GetComplianceReportRunByDue(ctx, h.tenant, approvedID, due)
	if err != nil || run.Status != "completed" || run.Dispatch == nil || run.Dispatch.ScheduleName != "approved pack" || run.Dispatch.Ticket == nil {
		t.Fatalf("approved run = %+v, %v", run, err)
	}
	withdrawn, err := h.store.GetComplianceReportRunByDue(ctx, h.tenant, withdrawnID, due)
	if err != nil || withdrawn.Status != "completed" || withdrawn.Dispatch == nil || withdrawn.Dispatch.Ticket != nil ||
		!strings.Contains(withdrawn.Dispatch.TicketSkipped, "no longer approved") {
		t.Fatalf("withdrawn-binding run = %+v, %v", withdrawn, err)
	}

	outboxRows := func(runID string) (notices, tickets int, alert notify.Alert, ticket orchestrator.ServiceNowTicketRequest) {
		t.Helper()
		rows, err := h.store.SystemPool().Query(ctx, `SELECT destination, idempotency_key, payload FROM outbox
			WHERE tenant_id = $1 AND (idempotency_key LIKE $2 OR idempotency_key = $3)`,
			h.tenant, "compliance-report:"+runID+":%", "compliance-report-ticket:"+runID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var destination, key string
			var payload []byte
			if err := rows.Scan(&destination, &key, &payload); err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(payload, []byte(`"signature"`)) || bytes.Contains(payload, []byte(`"manifest"`)) {
				t.Fatalf("%s carries the signed report body: %s", destination, payload)
			}
			switch destination {
			case notify.DestinationComplianceReport:
				notices++
				if err := json.Unmarshal(payload, &alert); err != nil {
					t.Fatal(err)
				}
			case orchestrator.DestinationITSMServiceNow:
				tickets++
				if err := json.Unmarshal(payload, &ticket); err != nil {
					t.Fatal(err)
				}
			default:
				t.Fatalf("unexpected dispatch row %s %s", destination, key)
			}
		}
		return notices, tickets, alert, ticket
	}
	notices, tickets, alert, ticket := outboxRows(run.ID)
	if notices != 1 || tickets != 1 || alert.Kind != notify.KindComplianceReportReady || alert.TargetChannel != "webhook" ||
		alert.Subject != "approved pack" || alert.Report == nil || alert.Report.RunID != run.ID ||
		alert.Report.ArtifactSHA256 != run.ArtifactDigest || alert.Report.DownloadPath != "/api/v1/compliance/report-runs/"+run.ID+"/artifact" {
		t.Fatalf("approved run dispatch: notices=%d tickets=%d alert=%+v report=%+v", notices, tickets, alert, alert.Report)
	}
	if ticket.InstanceURL != instanceURL || ticket.TokenRef != tokenRef || ticket.Table != "incident" || ticket.CorrelationID != run.ID ||
		!strings.Contains(ticket.ShortDescription, "approved pack") || !strings.Contains(ticket.Description, run.ArtifactDigest) {
		t.Fatalf("approved run ticket = %+v", ticket)
	}
	if notices, tickets, _, _ := outboxRows(withdrawn.ID); notices != 1 || tickets != 0 {
		t.Fatalf("withdrawn-binding run dispatch: notices=%d tickets=%d", notices, tickets)
	}

	// The receipt names what the run announced.
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/compliance/report-runs/"+withdrawn.ID, admin, nil)
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"ticket_skipped"`)) || !bytes.Contains(body, []byte(`"webhook"`)) {
		t.Fatalf("withdrawn-binding receipt = %d %s", status, body)
	}

	// Reconciliation and a repeated completion converge on the same rows.
	if _, err := h.srv.orch.ReconcileOutbox(ctx, h.srv.log); err != nil {
		t.Fatalf("reconcile outbox: %v", err)
	}
	if _, err := h.srv.orch.RecordComplianceReportRun(ctx, run); err != nil {
		t.Fatalf("repeat completion: %v", err)
	}
	if notices, tickets, _, _ := outboxRows(run.ID); notices != 1 || tickets != 1 {
		t.Fatalf("after reconcile and repeat: notices=%d tickets=%d", notices, tickets)
	}
}
