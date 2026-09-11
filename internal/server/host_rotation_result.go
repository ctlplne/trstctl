// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
)

// recordHostRotationResult derives completion only after the exact host claim
// has been retired. Both the request path and crash recovery use retained,
// per-attempt events, never a mutable latest-delivery row or a new observation time.
func (a *agentService) recordHostRotationResult(ctx context.Context, tenantID string, jobID int64) error {
	if a.store == nil {
		return errors.New("host rotation store is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return a.store.WithHostRotationResultLock(ctx, tenantID, jobID, func(lockCtx context.Context) error {
		if a.log == nil {
			return a.recordHostRotationResultLocked(lockCtx, tenantID, jobID)
		}
		return a.log.WithHistoryRead(lockCtx, func(readCtx context.Context) error { return a.recordHostRotationResultLocked(readCtx, tenantID, jobID) })
	})
}

func (a *agentService) recordHostRotationResultLocked(ctx context.Context, tenantID string, jobID int64) error {
	if a.store == nil {
		return errors.New("host rotation store is not configured")
	}
	job, err := a.store.GetHostRotationJob(ctx, tenantID, jobID)
	if err != nil {
		return err
	}
	if job.Destination != agentJobKindEndpointRenew {
		return nil
	}
	var intent RelayDeployIntent
	if json.Unmarshal(job.Payload, &intent) != nil || intent.RotationRunID == "" {
		// First issuance and legacy jobs have no run binding. Never guess one.
		return nil
	}
	if job.CompletedAt == nil || (job.Status != "delivered" && job.Status != "failed") {
		// A failed attempt returned to the queue is still ongoing work.
		return nil
	}
	if a.orch == nil || a.log == nil {
		return errors.New("host rotation result receiver is not configured")
	}
	run, err := a.store.GetRotationRun(ctx, tenantID, intent.RotationRunID)
	if err != nil {
		return err
	}
	if run.IdentityID != intent.IdentityID || job.IdempotencyKey != "host-renew:renew:"+run.IdempotencyKey {
		return errors.New("host rotation differs from its queued run binding")
	}
	predecessor, err := a.store.GetCertificate(ctx, tenantID, intent.PredecessorCertificateID)
	if err != nil || predecessor.Fingerprint != run.PredecessorFingerprint {
		return errors.New("host rotation differs from its queued predecessor")
	}
	evidence, err := a.hostRotationEvidence(ctx, tenantID, job, run)
	if err != nil {
		return err
	}
	eventKey := fmt.Sprintf("%s:attempt:%d", job.IdempotencyKey, job.Attempt)
	event := evidence.Delivery
	if event.ID != evidenceID("connector-delivery-agent-event", tenantID, eventKey, job.ID) || event.Type != projections.EventConnectorDeliveryRecorded {
		return errors.New("retained delivery event identity differs")
	}
	var delivery projections.ConnectorDeliveryRecorded
	if err := json.Unmarshal(event.Data, &delivery); err != nil {
		return err
	}
	if delivery.OutboxID == nil || *delivery.OutboxID != job.ID || delivery.Attempts != job.Attempt ||
		delivery.IdentityID == nil || *delivery.IdentityID != run.IdentityID || delivery.IdempotencyKey != job.IdempotencyKey ||
		delivery.Connector != intent.Connector || delivery.Target != intent.Target || delivery.Fingerprint == "" {
		return errors.New("retained delivery differs from the retired host rotation")
	}
	cert, err := a.store.GetCertificateByFingerprint(ctx, tenantID, delivery.Fingerprint)
	if err != nil || cert.ReplacesID == nil || *cert.ReplacesID != predecessor.ID ||
		!strings.HasPrefix(cert.IssuanceIdempotencyKey, fmt.Sprintf("agentcsr:%d:%d:", job.ID, job.Attempt)) {
		return errors.New("host rotation successor was not issued for this job and predecessor")
	}
	custodyID := orchestrator.CertificateCustodyAttestationEventID(tenantID, delivery.Fingerprint, job.ID, job.Attempt)
	signed := evidence.Custody
	if signed.ID != custodyID || signed.Type != projections.EventCertificateCustodyAttested {
		return errors.New("retained custody event identity differs")
	}
	var custody projections.CertificateCustodyAttested
	if err := json.Unmarshal(signed.Data, &custody); err != nil {
		return err
	}
	if custody.JobID != job.ID || custody.Attempt != job.Attempt || custody.Fingerprint != delivery.Fingerprint ||
		custody.ReceiptSignature == "" || custody.ReceiptSignerFingerprint == "" || custody.Agent == "" {
		return errors.New("retained custody receipt differs from the retired host rotation")
	}
	// This canonical statement was verified before AttestCertificateCustody was
	// appended. Match its signed authority and outcome to the same retained event.
	fields := map[string]string{"tenant": tenantID, "job": fmt.Sprint(job.ID), "attempt": fmt.Sprint(job.Attempt),
		"agent": custody.Agent, "credential_fingerprint": delivery.Fingerprint}
	for key, value := range fields {
		if !strings.Contains(custody.ReceiptStatement, "\n"+key+"="+value+"\n") {
			return errors.New("retained signed statement differs from the retired host rotation")
		}
	}
	outcome := ""
	for _, value := range []string{transport.JobOutcomeExecuted, transport.JobOutcomeVerified, transport.JobOutcomeVerifyFailed} {
		if strings.Contains(custody.ReceiptStatement, "\noutcome="+value+"\n") {
			outcome = value
		}
	}
	expectedReason := map[string]string{transport.JobOutcomeExecuted: "agent_delivered", transport.JobOutcomeVerified: "agent_delivered_and_verified", transport.JobOutcomeVerifyFailed: "agent_delivered_verification_failed"}[outcome]
	if expectedReason == "" || delivery.Reason != expectedReason {
		return errors.New("retained signed outcome differs from the delivery event")
	}
	run.Status, run.Error = "succeeded", ""
	run.SuccessorFingerprint = delivery.Fingerprint
	run.RollbackRef = "restore certificate fingerprint " + predecessor.Fingerprint + " for " + intent.Target
	if outcome == transport.JobOutcomeVerifyFailed || (intent.VerifyAddress != "" && outcome != transport.JobOutcomeVerified) {
		run.Status, run.Error = "failed", "host renewal did not verify the configured endpoint"
	}
	if job.Status == "failed" {
		run.Status, run.Error = "failed", "host deployment completed but its lifecycle transition was refused"
	}
	run.CompletedAt = job.CompletedAt
	eventID := evidenceID("host-rotation-result", tenantID, eventKey, job.ID)
	return a.orch.RecordRotationResultWithEventID(ctx, tenantID, eventID, run, evidence.Terminal)
}
