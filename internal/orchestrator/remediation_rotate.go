// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/discovery/sourcecatalog"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// DestinationRotateVerification is the credential-rotate playbook's internal
// control-plane command (owner decision, batch 14). The playbook issues the
// replacement and returns; this command waits, without spending its retry
// budget, for the replacement's signed and verified delivery, then marks the
// replacement deployed and revokes the original. Past the run's deadline, or
// when the endpoint does not serve the replacement, the original stays valid
// and a finding names the replacement and its target.
const DestinationRotateVerification = "remediation.rotate.verify"

// Credential-rotate run states. A running run owns its replacement's deployed
// edge; executed and failed are terminal.
const (
	RotateRunRunning  = "running"
	RotateRunExecuted = "executed"
	RotateRunFailed   = "failed"

	RotatePhaseAwaitingVerification = "replacement_awaiting_verification"
	RotatePhaseVerifiedAndRevoked   = "replacement_verified_and_original_revoked"
	RotatePhaseUnverifiedKept       = "replacement_unverified_original_kept"
	RotatePhaseVerifyFailedKept     = "replacement_verify_failed_original_kept"
	RotatePhaseIssuanceRefused      = "replacement_issuance_refused"

	// RotateReplacementRunAttribute names the run on its replacement identity,
	// so issuance and host results leave the deployed edge to the run.
	RotateReplacementRunAttribute = "remediation_rotate_run_id"
)

// RotateVerificationCommand names one run. The run projection owns the
// identities, reason and deadline, so the outbox body cannot substitute them.
type RotateVerificationCommand struct {
	RunID string `json:"run_id"`
}

// RotateVerificationIdempotencyKey is stable across restart reconciliation.
func RotateVerificationIdempotencyKey(runID string) string {
	return "remediation-rotate:" + runID
}

func rotateRunEventID(tenantID, runID, status, phase string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID,
		[]byte("remediation-rotate-run\x00"+tenantID+"\x00"+runID+"\x00"+status+"\x00"+phase)).String()
}

func rotateVerificationEntry(tenantID, runID string) (Entry, error) {
	body, err := json.Marshal(RotateVerificationCommand{RunID: runID})
	if err != nil {
		return Entry{}, err
	}
	return Entry{
		TenantID: tenantID, Destination: DestinationRotateVerification,
		IdempotencyKey: RotateVerificationIdempotencyKey(runID),
		EffectLane:     DestinationRotateVerification + ":" + runID,
		Payload:        body, RequiredAgentRole: "control_plane",
	}, nil
}

// RecordRotatePlaybookRun records one state of a credential-rotate run under a
// retry-stable event ID. A running run enqueues its verification command in
// the same transaction (AN-6); boot reconciliation recreates a lost one.
func (o *Orchestrator) RecordRotatePlaybookRun(ctx context.Context, tenantID string, r store.RemediationPlaybookRun) (store.RemediationPlaybookRun, error) {
	if r.ID == "" || r.Action != "rotate" || r.Phase == "" ||
		(r.Status != RotateRunRunning && r.Status != RotateRunExecuted && r.Status != RotateRunFailed) {
		return store.RemediationPlaybookRun{}, errors.New("orchestrator: credential-rotate run is incomplete")
	}
	if o.outbox == nil {
		return store.RemediationPlaybookRun{}, errors.New("orchestrator: credential-rotate outbox is not configured")
	}
	payload, err := json.Marshal(projections.RemediationPlaybookRunRecorded{
		ID: r.ID, PlaybookID: r.PlaybookID, TargetIdentityID: r.TargetIdentityID,
		InventoryID: r.InventoryID, Status: r.Status, Phase: r.Phase, Action: r.Action,
		Reason: r.Reason, Connector: r.Connector, Target: r.Target,
		ConnectorDeliveryID: r.ConnectorDeliveryID, ScopeDelta: r.ScopeDelta,
		EvidenceRefs: r.EvidenceRefs, RollbackRefs: r.RollbackRefs,
		IdempotencyKey: r.IdempotencyKey, TerminalReason: r.TerminalReason, CreatedBy: r.CreatedBy,
	})
	if err != nil {
		return store.RemediationPlaybookRun{}, err
	}
	entry, err := rotateVerificationEntry(tenantID, r.ID)
	if err != nil {
		return store.RemediationPlaybookRun{}, err
	}
	next := events.Event{ID: rotateRunEventID(tenantID, r.ID, r.Status, r.Phase),
		Type: projections.EventRemediationPlaybookRunRecorded, TenantID: tenantID, Data: payload}
	var ev events.Event
	if err := o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		if ev, err = o.log.Append(ctx, next); err != nil {
			return err
		}
		if ev.ID != next.ID || ev.Type != next.Type || ev.TenantID != tenantID || !bytes.Equal(ev.Data, payload) {
			return fmt.Errorf("%w: canonical credential-rotate run event differs", store.ErrIdempotencyConflict)
		}
		if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
			return err
		}
		if r.Status != RotateRunRunning {
			return nil
		}
		_, err = o.outbox.EnqueueIfAbsent(ctx, tx, entry)
		return err
	}); err != nil {
		return store.RemediationPlaybookRun{}, err
	}
	return o.store.GetRemediationPlaybookRun(ctx, tenantID, r.ID)
}

// RotationUnverifiedFindingKind is the discovery finding kind recorded when a
// credential-rotate run ends without the replacement's signed, verified
// delivery: the original credential stays valid and in service.
const RotationUnverifiedFindingKind = "rotation-replacement-unverified"

var rotationFindingSourceNamespace = uuid.MustParse("3b0f6f1e-6a43-4c39-9d0e-6f1f8d2b7a10")

// RotationUnverified is one credential-rotate run that kept its original.
type RotationUnverified struct {
	RunID                 string
	OriginalIdentityID    string
	ReplacementIdentityID string
	Connector             string
	Target                string
	Outcome               string // RotatePhaseUnverifiedKept or RotatePhaseVerifyFailedKept
	Detail                string
	ObservedAt            time.Time
}

// RecordRotationUnverified records one finding under the product's own
// credential-rotate source, in a run of its own keyed by the remediation run,
// so a retried command converges on the same events.
func (o *Orchestrator) RecordRotationUnverified(ctx context.Context, tenantID string, f RotationUnverified) error {
	if f.RunID == "" || f.OriginalIdentityID == "" || f.ReplacementIdentityID == "" || f.ObservedAt.IsZero() ||
		(f.Outcome != RotatePhaseUnverifiedKept && f.Outcome != RotatePhaseVerifyFailedKept) {
		return errors.New("orchestrator: unverified rotation finding is incomplete")
	}
	key := RotateVerificationIdempotencyKey(f.RunID)
	sourceID := uuid.NewSHA1(rotationFindingSourceNamespace, []byte(tenantID+"\x00credential-rotate")).String()
	if _, err := o.UpsertDiscoverySource(ctx, tenantID, store.DiscoverySource{
		ID: sourceID, Kind: "remediation_rotation", Name: sourcecatalog.RemediationRotationSourcePrefix + "credential-rotate",
		Config: json.RawMessage(`{"check":"replacement_delivery_verification"}`),
	}); err != nil {
		return err
	}
	runID := uuid.NewSHA1(rotationFindingSourceNamespace, []byte(tenantID+"\x00"+key)).String()
	queued, err := json.Marshal(projections.DiscoveryRunQueued{ID: runID, SourceID: sourceID, RequestedBy: "system:credential-rotate"})
	if err != nil {
		return err
	}
	if _, err := o.emitPreparedExact(ctx, events.Event{ID: DiscoveryRelayEventID(tenantID, key, "rotation-run-queued"),
		Type: projections.EventDiscoveryRunQueued, TenantID: tenantID, Data: queued}); err != nil {
		return err
	}
	if err := o.StartDiscoveryRunWithEventID(ctx, tenantID, runID, DiscoveryRelayEventID(tenantID, key, "rotation-run-started")); err != nil {
		return err
	}
	meta, err := json.Marshal(map[string]any{
		"remediation_run_id": f.RunID, "original_identity_id": f.OriginalIdentityID,
		"replacement_identity_id": f.ReplacementIdentityID, "connector": f.Connector, "target": f.Target,
		"outcome": f.Outcome, "reason": f.Detail,
	})
	if err != nil {
		return err
	}
	ref := strings.TrimSpace(f.Target)
	if ref == "" {
		ref = "identity/" + f.ReplacementIdentityID
	}
	if _, err := o.RecordDiscoveryFindingWithEventID(ctx, tenantID, DiscoveryRelayEventID(tenantID, key, "rotation-finding"), store.DiscoveryFinding{
		RunID: runID, SourceID: sourceID, Kind: RotationUnverifiedFindingKind, Ref: ref,
		Provenance: "remediation-run:" + f.RunID, RiskScore: 70, Metadata: meta, DiscoveredAt: f.ObservedAt,
	}); err != nil {
		return err
	}
	return o.CompleteDiscoveryRunWithEventID(ctx, tenantID, DiscoveryRelayEventID(tenantID, key, "rotation-run-completed"),
		store.DiscoveryRun{ID: runID, Status: "succeeded", Targets: 1, Discovered: 1})
}
