// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/servedstatus"
	"trstctl.com/trstctl/internal/store"
)

// A missing host action is a permanent, signed refusal. The operator must see
// it in the exact receipt, and an agent poll must not execute it indefinitely.
func TestServedContainmentMissingHostActionIsVisibleAndTerminal(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleHost}, relay.KindEndpointContain)
	intent := relay.ContainmentIntent{
		TargetID: uuid.NewString(), TargetRevision: uuid.NewString(),
		IdentityID: uuid.NewString(), ExpectedFingerprint: strings.Repeat("a", 64),
		RequiredAgentID: agentRowID(h.tenant, h.agent),
	}
	payload, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	var jobID int64
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, required_agent_role, required_agent_id)
			 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
			h.tenant, relay.KindEndpointContain, payload, "contain:missing-action", mtls.AgentRoleHost,
			intent.RequiredAgentID).Scan(&jobID)
	}); err != nil {
		t.Fatal(err)
	}
	queued, err := h.srv.orch.RecordConnectorDeliveryWithEventID(ctx, h.tenant, uuid.NewString(),
		store.ConnectorDeliveryReceipt{
			ID: uuid.NewString(), OutboxID: &jobID, IdentityID: &intent.IdentityID, Destination: relay.KindEndpointContain,
			Connector: "apache", Target: "qa-host", Fingerprint: intent.ExpectedFingerprint,
			Status:         servedstatus.ConnectorContainmentQueued,
			IdempotencyKey: "contain:missing-action",
		})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{relay.KindEndpointContain}, Limit: 1})
	if err != nil || len(claimed.Jobs) != 1 || claimed.Jobs[0].JobID != jobID {
		t.Fatalf("claim exact host containment: %+v %v", claimed, err)
	}
	job := claimed.Jobs[0]
	result, err := h.client.ReportJobResult(ctx, h.report(t, jobID, job.Attempt,
		transport.JobOutcomeFailed, "host profile has no containment binding for this exact target", ""))
	if err != nil || !result.Accepted {
		t.Fatalf("report signed host refusal: %+v %v", result, err)
	}
	read, err := h.store.GetConnectorDeliveryReceipt(ctx, h.tenant, queued.ID)
	if err != nil || read.Status != servedstatus.ConnectorContainmentFailed || read.Attempts != job.Attempt {
		t.Fatalf("failed host action left receipt queued: %+v %v", read, err)
	}
	var failure struct {
		Reason            string `json:"reason"`
		ReceiptSignature  string `json:"receipt_signature_base64"`
		SignerFingerprint string `json:"signer_fingerprint"`
	}
	if err := json.Unmarshal([]byte(read.Detail), &failure); err != nil ||
		failure.Reason != "host profile has no containment binding for this exact target" ||
		failure.ReceiptSignature == "" || failure.SignerFingerprint == "" {
		t.Fatalf("terminal failure has no attributable signed reason: %+v %v", failure, err)
	}
	var outboxStatus string
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT status FROM outbox WHERE tenant_id=$1 AND id=$2`,
			h.tenant, jobID).Scan(&outboxStatus)
	}); err != nil || outboxStatus != "failed" {
		t.Fatalf("missing host action stayed claimable: status=%s err=%v", outboxStatus, err)
	}
	var alertBody []byte
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT payload FROM outbox WHERE tenant_id=$1 AND destination=$2 AND idempotency_key=$3`,
			h.tenant, notify.DestinationContainment, "containment-failed:"+queued.ID).Scan(&alertBody)
	}); err != nil {
		t.Fatalf("terminal containment failure has no operator alert: %v", err)
	}
	var alert notify.Alert
	if err := json.Unmarshal(alertBody, &alert); err != nil || alert.Kind != notify.KindEndpointContainmentFailed ||
		alert.IdentityID != intent.IdentityID || alert.DeploymentReceiptID != queued.ID ||
		alert.CertificateFingerprint != intent.ExpectedFingerprint || alert.Severity != notify.AlertSeverityCritical {
		t.Fatalf("containment alert lost exact incident scope: %+v %v", alert, err)
	}
	// A fresh poll cannot silently turn a failed emergency stop into an
	// unbounded loop if the operator has not repaired the host profile.
	again, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{relay.KindEndpointContain}, Limit: 1,
		LeaseSeconds: 60})
	if err != nil || len(again.Jobs) != 0 {
		t.Fatalf("terminal host failure was offered again: %+v %v", again, err)
	}
}

// A signed executed report can still say the listener was not stopped. That
// must page the operator just like a host refusal; an accepted job is not a
// verified containment result.
func TestServedContainmentExecutedFailurePagesOperator(t *testing.T) {
	ctx := t.Context()
	h := newRoleHarness(t, []string{mtls.AgentRoleHost}, relay.KindEndpointContain)
	intent := relay.ContainmentIntent{
		TargetID: uuid.NewString(), TargetRevision: uuid.NewString(),
		IdentityID: uuid.NewString(), ExpectedFingerprint: strings.Repeat("a", 64),
		RequiredAgentID: agentRowID(h.tenant, h.agent),
	}
	payload, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	var jobID int64
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, required_agent_role, required_agent_id)
			 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
			h.tenant, relay.KindEndpointContain, payload, "contain:executed-but-failed",
			mtls.AgentRoleHost, intent.RequiredAgentID).Scan(&jobID)
	}); err != nil {
		t.Fatal(err)
	}
	queued, err := h.srv.orch.RecordConnectorDeliveryWithEventID(ctx, h.tenant, uuid.NewString(),
		store.ConnectorDeliveryReceipt{
			ID: uuid.NewString(), OutboxID: &jobID, IdentityID: &intent.IdentityID,
			Destination: relay.KindEndpointContain, Connector: "apache", Target: "qa-host",
			Fingerprint: intent.ExpectedFingerprint, Status: servedstatus.ConnectorContainmentQueued,
			IdempotencyKey: "contain:executed-but-failed",
		})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{relay.KindEndpointContain}, Limit: 1})
	if err != nil || len(claimed.Jobs) != 1 || claimed.Jobs[0].JobID != jobID {
		t.Fatalf("claim exact host containment: %+v %v", claimed, err)
	}
	job := claimed.Jobs[0]
	before := transport.ProbeTranscript{Address: "127.0.0.1:443", ServerName: "qa-host",
		Vantage: transport.VantageLocal, ExpectedFingerprint: intent.ExpectedFingerprint,
		ObservedFingerprint: intent.ExpectedFingerprint, Reached: true, ObservedAtUnix: time.Now().Unix()}
	after := before
	after.ObservedAtUnix++
	report := relay.ContainmentReport{
		TargetID: intent.TargetID, TargetRevision: intent.TargetRevision,
		IdentityID: intent.IdentityID, ExpectedFingerprint: intent.ExpectedFingerprint,
		Action: "stop-apache", State: relay.ContainmentFailed,
		Before: before, After: []transport.ProbeTranscript{after, after},
	}
	detail, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	result, err := h.client.ReportJobResult(ctx, h.report(t, jobID, job.Attempt,
		transport.JobOutcomeExecuted, string(detail), report.Digest()))
	if err != nil || !result.Accepted {
		t.Fatalf("report signed unsuccessful stop: %+v %v", result, err)
	}
	read, err := h.store.GetConnectorDeliveryReceipt(ctx, h.tenant, queued.ID)
	if err != nil || read.Status != servedstatus.ConnectorContainmentFailed || read.Attempts != job.Attempt {
		t.Fatalf("signed unsuccessful stop had no exact failure receipt: %+v %v", read, err)
	}
	var alertBody []byte
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT payload FROM outbox WHERE tenant_id=$1 AND destination=$2 AND idempotency_key=$3`,
			h.tenant, notify.DestinationContainment, "containment-failed:"+queued.ID).Scan(&alertBody)
	}); err != nil {
		t.Fatalf("signed unsuccessful stop had no critical alert: %v", err)
	}
	var alert notify.Alert
	if err := json.Unmarshal(alertBody, &alert); err != nil || alert.Kind != notify.KindEndpointContainmentFailed ||
		alert.IdentityID != intent.IdentityID || alert.DeploymentReceiptID != queued.ID ||
		alert.CertificateFingerprint != intent.ExpectedFingerprint || alert.Severity != notify.AlertSeverityCritical {
		t.Fatalf("executed failure alert lost exact incident: %+v %v", alert, err)
	}
}
