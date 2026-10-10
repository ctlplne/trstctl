// SPDX-License-Identifier: BUSL-1.1

package pqcmigration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

// HostAgentHooks is the PQC-specific adapter at the core agent channel. The
// edition attach seam supplies it; the channel itself knows no migration
// semantics. Both methods open the same tenant-sealed, AAD-bound outbox intent.
type HostAgentHooks struct {
	Store        *store.Store
	Log          *events.Log
	Progress     *ProgressProjection
	Key          seal.KeyWrapper
	TenantCrypto tenantseal.Access
}

func strictHostPostureJSON(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > 64<<10 {
		return errors.New("pqcmigration: signed host posture report exceeds bound")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return errors.New("pqcmigration: signed host posture report has trailing data")
	}
	return nil
}

func (h HostAgentHooks) open(ctx context.Context, tenantID, destination, idempotencyKey string, payload []byte) (relay.PQCPostureIntent, pqcMigrationTLSPosturePayload, pqcMigrationTLSRollbackPayload, error) {
	var intent relay.PQCPostureIntent
	var forward pqcMigrationTLSPosturePayload
	var rollback pqcMigrationTLSRollbackPayload
	if destination == relay.KindPQCPosture {
		wrapped, err := openTLSPostureOutboxForTenant(ctx, h.TenantCrypto, h.Key, tenantID, destination, idempotencyKey, payload, &forward)
		if err != nil {
			return intent, forward, rollback, err
		}
		if forward.RunID != wrapped.RunID || forward.AssetID != wrapped.AssetID || forward.TargetRevision != wrapped.TargetRevision || forward.RequiredAgentID == "" {
			return intent, forward, rollback, errors.New("pqcmigration: sealed host posture metadata mismatch")
		}
		intent, err = hostPQCPostureIntent(forward, forward.RequiredAgentID)
		return intent, forward, rollback, err
	}
	if destination != relay.KindPQCPostureRollback {
		return intent, forward, rollback, errors.New("pqcmigration: unknown host posture job")
	}
	wrapped, err := openTLSPostureOutboxForTenant(ctx, h.TenantCrypto, h.Key, tenantID, destination, idempotencyKey, payload, &rollback)
	if err != nil {
		return intent, forward, rollback, err
	}
	if rollback.RunID != wrapped.RunID || len(rollback.Restores) == 0 || rollback.RequiredAgentID == "" ||
		rollback.Restores[0].AssetID != wrapped.AssetID || rollback.Mutation.TargetRevision != wrapped.TargetRevision || rollback.Mutation.ExpectedPrevious == nil {
		return intent, forward, rollback, errors.New("pqcmigration: sealed host rollback metadata mismatch")
	}
	first := rollback.Restores[0]
	forward = pqcMigrationTLSPosturePayload{
		RunID: rollback.RunID, AssetID: first.AssetID, FindingKind: first.FindingKind,
		TargetID: rollback.Mutation.TargetID, TargetRevision: rollback.Mutation.TargetRevision,
		Target: rollback.Mutation.Target, Connector: rollback.Mutation.Connector,
		TargetConfig: rollback.Mutation.TargetConfig, Desired: *rollback.Mutation.ExpectedPrevious,
		RequiredAgentID: rollback.RequiredAgentID,
	}
	intent, err = hostPQCPostureIntent(forward, rollback.RequiredAgentID)
	return intent, forward, rollback, err
}

// OpenJob projects only the host-executable, reference-only intent. The sealed
// durable payload never travels to the agent, which has no tenant data key.
func (h HostAgentHooks) OpenJob(ctx context.Context, tenantID, destination, idempotencyKey string, payload []byte) ([]byte, error) {
	intent, _, _, err := h.open(ctx, tenantID, destination, idempotencyKey, payload)
	if err != nil {
		return nil, err
	}
	if err := h.checkAssignedTarget(ctx, tenantID, intent); err != nil {
		return nil, err
	}
	return json.Marshal(intent)
}

func (h HostAgentHooks) checkAssignedTarget(ctx context.Context, tenantID string, intent relay.PQCPostureIntent) error {
	if h.Store == nil {
		return errors.New("pqcmigration: host posture store is unavailable")
	}
	target, err := h.Store.GetDeploymentTarget(ctx, tenantID, intent.TargetID)
	if err != nil {
		return err
	}
	assigned, err := h.Store.ValidateHostTargetAssignment(ctx, tenantID, target.Type, target.Config)
	if err != nil {
		return err
	}
	if !target.Enabled || target.RevisionID != intent.TargetRevision || target.Type != intent.Connector ||
		assigned != intent.RequiredAgentID {
		return errors.New("pqcmigration: host posture target revision or assignment changed")
	}
	return nil
}

// RecordResult runs after the mTLS peer, current lease and detached signature
// have been verified, before claim retirement. Any projection failure keeps the
// signed original report retryable. No agent-provided free text is appended.
func (h HostAgentHooks) RecordResult(ctx context.Context, tenantID, agentID string, claim store.AgentJobResultClaim,
	req *transport.ReportJobResultRequest, canonicalStatement, signerFingerprint string) error {
	if h.Store == nil {
		return errors.New("pqcmigration: host posture idempotency store is unavailable")
	}
	_, err := orchestrator.NewIdempotency(h.Store).Do(ctx, tenantID,
		"pqc-host-posture-report:"+claim.IdempotencyKey, func(scoped context.Context) ([]byte, error) {
			if err := h.recordResult(scoped, tenantID, agentID, claim, req, canonicalStatement, signerFingerprint); err != nil {
				return nil, err
			}
			return []byte("recorded"), nil
		})
	return err
}

func (h HostAgentHooks) recordResult(ctx context.Context, tenantID, agentID string, claim store.AgentJobResultClaim,
	req *transport.ReportJobResultRequest, canonicalStatement, signerFingerprint string) error {
	intent, forward, rollback, err := h.open(ctx, tenantID, claim.Destination, claim.IdempotencyKey, claim.Payload)
	if err != nil {
		return err
	}
	if agentID != intent.RequiredAgentID {
		return errors.New("pqcmigration: signed report came from a different enrolled host")
	}
	if err := h.checkAssignedTarget(ctx, tenantID, intent); err != nil {
		return err
	}
	handler := &outboxHandler{store: h.Store, log: h.Log, progress: h.Progress}
	if req.Outcome == transport.JobOutcomeFailed || req.Outcome == transport.JobOutcomeVerifyFailed {
		status := TLSFindingFailed
		if claim.Destination == relay.KindPQCPostureRollback {
			status = TLSFindingRollbackFailed
		}
		return handler.appendProjected(ctx, tenantID, EventTLSFindingFailed, TLSFindingFailure{
			RunID: intent.RunID, AssetID: intent.AssetID, FindingKind: intent.FindingKind,
			TargetID: intent.TargetID, Connector: intent.Connector,
			Reason: "assigned host reported posture mutation or served-state verification failure", Status: status,
		})
	}
	if req.Outcome != transport.JobOutcomeVerified {
		return errors.New("pqcmigration: host posture needs a verified signed report")
	}
	var result relay.PQCPostureReport
	if err := strictHostPostureJSON([]byte(req.Detail), &result); err != nil {
		return err
	}
	if err := relay.ValidatePQCPostureReport(intent, result, req.EvidenceDigest, claim.Destination); err != nil {
		return err
	}
	signed := struct {
		AgentID                  string
		JobID                    int64
		Attempt                  int
		EvidenceDigest           string
		ReceiptStatement         string
		ReceiptSignature         string
		ReceiptSignerFingerprint string
	}{agentID, req.JobID, req.Attempt, req.EvidenceDigest, canonicalStatement, base64.StdEncoding.EncodeToString(req.Signature), signerFingerprint}
	if signed.ReceiptStatement == "" || signed.ReceiptSignature == "" || signed.ReceiptSignerFingerprint == "" {
		return errors.New("pqcmigration: durable signed host readback is incomplete")
	}
	if claim.Destination == relay.KindPQCPosture {
		if !connector.EqualTLSPosture(result.Receipt.Observed, forward.Desired) {
			return errors.New("pqcmigration: host posture readback differs from sealed intent")
		}
		// The event log and idempotency ledger are separate durable systems. A
		// crash after append and before ledger commit must replay this one signed
		// outcome, not append a second completion or a new predecessor.
		if prior, found, err := handler.completedTLSFinding(ctx, tenantID, forward, claim.Payload); err != nil {
			return err
		} else if found {
			if prior.EvidenceDigest != req.EvidenceDigest ||
				!connector.EqualTLSPosture(prior.Receipt.Previous, result.Receipt.Previous) ||
				!connector.EqualTLSPosture(prior.Receipt.Observed, result.Receipt.Observed) ||
				prior.Served == nil || *prior.Served != result.Served {
				return errors.New("pqcmigration: host posture retry conflicts with recorded signed effect")
			}
			return nil
		}
		if previous, found, err := handler.preparedTLSPosture(ctx, tenantID, forward); err != nil {
			return err
		} else if found {
			if !connector.EqualTLSPosture(previous, result.Receipt.Previous) {
				return errors.New("pqcmigration: host posture retry changed the durable predecessor")
			}
		} else if err := handler.appendProjected(ctx, tenantID, EventTLSFindingPrepared, TLSFindingPrepared{
			RunID: forward.RunID, AssetID: forward.AssetID, FindingKind: forward.FindingKind,
			TargetID: forward.TargetID, TargetRevision: forward.TargetRevision,
			Connector: forward.Connector, Previous: result.Receipt.Previous,
		}); err != nil {
			return err
		}
		forward.TargetConfig = nil
		forward.SealedOutboxPayload = append(json.RawMessage(nil), claim.Payload...)
		return handler.appendProjected(ctx, tenantID, EventTLSFindingCompleted, TLSFindingCompleted{
			Intent: forward, Receipt: result.Receipt, Served: &result.Served,
			AgentID: signed.AgentID, JobID: signed.JobID, Attempt: signed.Attempt,
			EvidenceDigest: signed.EvidenceDigest, ReceiptStatement: signed.ReceiptStatement,
			ReceiptSignature: signed.ReceiptSignature, ReceiptSignerFingerprint: signed.ReceiptSignerFingerprint,
		})
	}
	if !connector.EqualTLSPosture(result.Receipt.Observed, rollback.Mutation.Desired) {
		return errors.New("pqcmigration: host rollback readback differs from sealed predecessor")
	}
	if h.Log == nil {
		return errors.New("pqcmigration: host rollback requires durable event history")
	}
	var recorded *TLSFindingRollbackCompleted
	if err := h.Log.Replay(ctx, 0, func(ev events.Event) error {
		if ev.TenantID != tenantID || ev.Type != EventTLSFindingRollbackCompleted {
			return nil
		}
		var prior TLSFindingRollbackCompleted
		if err := json.Unmarshal(ev.Data, &prior); err != nil {
			return err
		}
		if prior.RunID != rollback.RunID || prior.Receipt.TargetID != intent.TargetID {
			return nil
		}
		if recorded != nil && (recorded.EvidenceDigest != prior.EvidenceDigest ||
			!connector.EqualTLSPosture(recorded.Receipt.Observed, prior.Receipt.Observed)) {
			return errors.New("pqcmigration: conflicting host rollback completions")
		}
		recorded = &prior
		return nil
	}); err != nil {
		return err
	}
	if recorded != nil {
		if recorded.EvidenceDigest != req.EvidenceDigest ||
			!connector.EqualTLSPosture(recorded.Receipt.Previous, result.Receipt.Previous) ||
			!connector.EqualTLSPosture(recorded.Receipt.Observed, result.Receipt.Observed) ||
			recorded.Served == nil || *recorded.Served != result.Served {
			return errors.New("pqcmigration: host rollback retry conflicts with recorded signed effect")
		}
		return nil
	}
	return handler.appendProjected(ctx, tenantID, EventTLSFindingRollbackCompleted, TLSFindingRollbackCompleted{
		RunID: rollback.RunID, Restores: rollback.Restores, Receipt: result.Receipt, Served: &result.Served,
		AgentID: signed.AgentID, JobID: signed.JobID, Attempt: signed.Attempt,
		EvidenceDigest: signed.EvidenceDigest, ReceiptStatement: signed.ReceiptStatement,
		ReceiptSignature: signed.ReceiptSignature, ReceiptSignerFingerprint: signed.ReceiptSignerFingerprint,
	})
}
