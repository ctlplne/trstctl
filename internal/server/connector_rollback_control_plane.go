// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/servedstatus"
	"trstctl.com/trstctl/internal/store"
)

// Control-plane execution of a connector rollback (A58).
//
// The cloud certificate stores run their deploys on the control plane's
// egress-guarded client, so a re-bind for one of them runs there too: the
// orchestrator stamps the row control_plane, no agent can claim it, and this
// dispatcher performs the family-specific re-bind through the same registry
// factory the deploy used. The receipt it records is the same shape and the
// same deterministic id an agent's signed result would produce, so operators,
// purge and takedown read one evidence chain regardless of where the rollback
// ran. Appliance re-binds and host restores are untouched: their rows keep
// their agent role and this handler defers them.

// routeConnectorRollback hands a control_plane row to the in-process executor
// and leaves every agent-owned row pending for the agent that must run it.
func (d *issuanceDispatcher) routeConnectorRollback(ctx context.Context, m orchestrator.Message) error {
	if m.RequiredAgentRole == string(connector.VantageControlPlane) {
		return d.handleControlPlaneConnectorRollback(ctx, m)
	}
	// A59: a cloud store's row stamped for a relay still runs here while the
	// tenant has no relay enrolled; an appliance row never does.
	var req controlPlaneRollbackCommand
	if m.RequiredAgentRole == "network" && json.Unmarshal(m.Payload, &req) == nil {
		fallback, err := d.cloudRowFallsBackToControlPlane(ctx, m.TenantID, req.Connector)
		if err != nil {
			return orchestrator.DeferDelivery(fmt.Errorf("server: check network relay before %s rollback: %w", req.Connector, err))
		}
		if fallback {
			return d.handleControlPlaneConnectorRollback(ctx, m)
		}
	}
	// DeferDelivery is attempt-budget-neutral: it proves no receiver I/O
	// began, so the row re-pends indefinitely and stays claimable by the
	// agent that is actually supposed to run it. Without this the default
	// branch would burn the row's attempt budget and dead-letter work the
	// API already reported as queued.
	return orchestrator.DeferDelivery(fmt.Errorf(
		"server: %s executes on a relay, not the control plane", m.Destination))
}

// controlPlaneRollbackCommand is the durable rollback command as the
// orchestrator enqueued it: connector, target and predecessor, no key.
type controlPlaneRollbackCommand struct {
	Connector              string          `json:"connector"`
	Target                 string          `json:"target"`
	TargetID               string          `json:"target_id"`
	IdentityID             string          `json:"identity_id"`
	TargetConfig           json.RawMessage `json:"target_config"`
	PredecessorFingerprint string          `json:"predecessor_fingerprint"`
	PredecessorSerial      string          `json:"predecessor_serial"`
	SuccessorFingerprint   string          `json:"successor_fingerprint"`
}

func (d *issuanceDispatcher) handleControlPlaneConnectorRollback(ctx context.Context, m orchestrator.Message) error {
	var req controlPlaneRollbackCommand
	if err := json.Unmarshal(m.Payload, &req); err != nil {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: decode connector rollback command: %w", err))
	}
	if m.IdempotencyKey == "" {
		return orchestrator.DefiniteNoEffect(errors.New("server: connector.rollback requires an idempotency key"))
	}
	var identityID *string
	if value := strings.TrimSpace(req.IdentityID); value != "" {
		identityID = &value
	}
	// The same deterministic id the agent result path derives, so a rollback
	// that ran on the control plane and one an agent reported converge on
	// one receipt row per command rather than one per attempt.
	receipt := connectorDeliveryEvidence{
		ID:             uuid.NewSHA1(rollbackReceiptNamespace, []byte(m.TenantID+"\x00"+m.IdempotencyKey)).String(),
		OutboxID:       outboxPtr(m.ID),
		IdentityID:     identityID,
		Destination:    orchestrator.DestinationConnectorRollback,
		Connector:      nonempty(req.Connector, "unconfigured"),
		Target:         nonempty(req.Target, "unconfigured"),
		Fingerprint:    req.PredecessorFingerprint,
		Attempts:       m.Attempts,
		IdempotencyKey: m.IdempotencyKey + ":rollback-result",
	}
	refuse := func(reason string, cause error) error {
		receipt.Detail = "the control plane declined before contacting the provider: " + reason
		if err := d.recordConnectorDelivery(ctx, m.TenantID, receipt, servedstatus.ConnectorRollbackRefused, "rollback_refused"); err != nil {
			return errors.Join(cause, err)
		}
		return orchestrator.DefiniteNoEffect(cause)
	}
	if d.connectorRegistry == nil || !d.connectorRegistry.Has(req.Connector) {
		return refuse(transport.RollbackRefusedNotExecutable, errors.New("server: the configured native connector is not loaded on this control plane"))
	}
	if d.connectorDeployVantage(req.Connector) != connector.VantageControlPlane && !connector.ControlPlaneCarriesNatively(req.Connector) {
		// Routing disagreement is not a reason to run someone else's work.
		return orchestrator.DeferDelivery(fmt.Errorf("server: %s rollback executes at its target vantage, not the control plane", req.Connector))
	}
	if !connector.CanRollback(req.Connector) {
		return refuse(transport.RollbackRefusedCannotRebind, connector.ErrRollbackUnsupported)
	}
	if strings.TrimSpace(req.PredecessorFingerprint) == "" {
		return refuse(transport.RollbackRefusedNoPredecessor, connector.ErrNoPredecessorInstalled)
	}
	// The durable command is rechecked against the current inventory the way
	// an agent's claim is: a predecessor revoked since the request, or an
	// identity retired since, must not be restored.
	if d.store != nil {
		if err := d.store.CheckConnectorRollbackPayload(ctx, m.TenantID, m.Payload); err != nil {
			if errors.Is(err, store.ErrUnsafeRollback) {
				return refuse(transport.RollbackRefusedAuthorization, err)
			}
			return orchestrator.DeferDelivery(fmt.Errorf("server: check rollback authorization: %w", err))
		}
	}
	// A result already committed for this exact command means the re-bind
	// happened; a crash after that commit must not run it twice.
	if done, err := d.hasCommittedRollbackResult(ctx, m.TenantID, receipt); err != nil {
		return err
	} else if done {
		return nil
	}

	payload := connector.DeployPayload{
		IdentityID: req.IdentityID, TargetID: req.TargetID, Connector: req.Connector, Target: req.Target,
		TargetConfig: append(json.RawMessage(nil), req.TargetConfig...), TenantID: m.TenantID,
	}
	if len(payload.TargetConfig) == 0 && req.TargetID != "" && d.store != nil {
		configured, err := d.store.GetDeploymentTarget(ctx, m.TenantID, req.TargetID)
		if err != nil {
			return orchestrator.DeferDelivery(fmt.Errorf("server: load deployment target for rollback: %w", err))
		}
		payload.TargetRevision = configured.RevisionID
		payload.TargetConfig = append(json.RawMessage(nil), configured.Config...)
	}
	effect := func(ctx context.Context) ([]byte, error) {
		result, err := d.connectorRegistry.Rollback(ctx, payload, connector.Rollback{
			Target: req.Target, PredecessorFingerprint: req.PredecessorFingerprint,
		})
		switch {
		case errors.Is(err, connector.ErrRollbackUnsupported):
			return nil, refuse(transport.RollbackRefusedCannotRebind, err)
		case errors.Is(err, connector.ErrRollbackNotConfigured):
			return nil, refuse(connector.ErrRollbackNotConfigured.Error(), err)
		case errors.Is(err, connector.ErrNoPredecessorInstalled):
			// The provider was reached and said the predecessor is gone. That
			// is a failure against the target, recorded as such, and it will
			// fail the same way on every retry.
			receipt.Detail = "the control plane reached the provider and the rollback did not succeed: " + transport.RollbackFailedPredecessorGone
			if recordErr := d.recordConnectorDelivery(ctx, m.TenantID, receipt, servedstatus.ConnectorRollbackFailed, "rollback_failed"); recordErr != nil {
				return nil, errors.Join(err, recordErr)
			}
			return nil, err
		case err != nil:
			receipt.Detail = "the control plane reached the provider and the rollback did not succeed: " + transport.RollbackFailedAtTarget + " (" + err.Error() + ")"
			if recordErr := d.recordConnectorDelivery(ctx, m.TenantID, receipt, servedstatus.ConnectorRollbackFailed, "rollback_failed"); recordErr != nil {
				return nil, errors.Join(err, recordErr)
			}
			return nil, err
		}
		receipt.Detail = "the control plane re-pointed " + req.Target + " to the predecessor certificate serial " + req.PredecessorSerial +
			" (fingerprint " + req.PredecessorFingerprint + ") through the " + req.Connector + " API. No key was uploaded. " +
			"The predecessor certificate was confirmed present in the provider before the re-bind. " +
			"Consumers that read the binding by version are not re-pointed by this operation."
		if result.LegacyObject {
			receipt.Detail = "the control plane re-bound " + req.Target + " to the object installed under its target-derived name; its contents were not re-read."
		}
		if err := d.recordConnectorDelivery(ctx, m.TenantID, receipt, servedstatus.ConnectorRolledBack, "rolled_back"); err != nil {
			return nil, err
		}
		return []byte("rolled_back:" + req.Connector), nil
	}
	// A re-bind is an at-most-once mutation of the provider: claim before I/O
	// and never guess that replaying it is harmless.
	_, err := d.idem.DoAtMostOnceEffect(ctx, m.TenantID, "rollback:"+m.IdempotencyKey, effect)
	return err
}

// hasCommittedRollbackResult accepts only the deterministic rolled_back receipt
// for this exact command.
func (d *issuanceDispatcher) hasCommittedRollbackResult(ctx context.Context, tenantID string, want connectorDeliveryEvidence) (bool, error) {
	if d.store == nil {
		return false, nil
	}
	got, err := d.store.GetConnectorDeliveryReceipt(ctx, tenantID, want.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("server: reconcile rollback receipt: %w", err)
	}
	if got.Status != servedstatus.ConnectorRolledBack {
		return false, nil
	}
	if !sameOutboxID(got.OutboxID, want.OutboxID) || got.Destination != want.Destination ||
		got.IdempotencyKey != want.IdempotencyKey || got.Connector != want.Connector ||
		got.Target != want.Target || !strings.EqualFold(got.Fingerprint, want.Fingerprint) {
		return false, fmt.Errorf("server: rollback receipt %s does not match its outbox binding", want.ID)
	}
	return true, nil
}
