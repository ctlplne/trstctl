// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/servedstatus"
	"trstctl.com/trstctl/internal/store"
)

// The target-vantage connector test (epic D5/F27).
//
// The console's test button used to record that a target's configuration
// parsed. That was true and nearly useless — it could not tell an operator
// whether the appliance was reachable or whether the credential still worked.
// This queues a real zero-write preview at the same execution vantage as deploy:
// the bound host/network agent for local and appliance targets, or the bounded
// control-plane outbox worker for the three cloud stores. It resolves everything
// a deploy needs, validates the target, describes what would change, and changes
// nothing.
//
// It returns (nil, nil) rather than an error when an agent-owned target has no
// enabled connector.test claimant. That is the honest fallback: the route then
// records local config validation instead of queueing work that cannot run.

// connectorTestEnqueuer builds the API's dry-run enqueuer over the served job
// ledger. Agent-owned tests must be enabled by the operator like any other
// claimable kind. Control-plane previews are outbox work, not agent claims, and
// therefore do not depend on the agent claimable-kind switch.
func (s *Server) connectorTestEnqueuer(claimable map[string]bool) func(context.Context, string, store.DeploymentTarget, string) (*store.ConnectorDeliveryReceipt, error) {
	return func(ctx context.Context, tenantID string, target store.DeploymentTarget, idempotencyKey string) (*store.ConnectorDeliveryReceipt, error) {
		if s.outbox == nil || s.store == nil || s.orch == nil {
			return nil, nil
		}
		// A target whose connector no agent can execute would queue work that
		// never drains. The census answers that before anything is enqueued.
		if s.connectorRegistry == nil {
			return nil, nil
		}
		vantage := s.connectorRegistry.TargetVantageFor(target.Type)
		if vantage != connector.VantageControlPlane && !claimable["connector.test"] {
			// Agent-owned tests are an explicit operator choice. A disabled claim
			// kind keeps the historical honest local fallback instead of queueing
			// work no agent is permitted to claim.
			return nil, nil
		}

		// The test payload carries the same shape a deploy does, minus any
		// credential: the relay redeems for itself. There is no cert or key
		// here — a dry-run proves the path, not the certificate.
		payload, err := json.Marshal(connector.DeployPayload{
			Connector:      target.Type,
			Target:         target.Name,
			TargetID:       target.ID,
			TargetRevision: target.RevisionID,
			TargetConfig:   append(json.RawMessage(nil), target.Config...),
		})
		if err != nil {
			return nil, fmt.Errorf("server: encode connector test payload: %w", err)
		}
		idemKey := "connector-test:" + target.ID + ":" + idempotencyKey
		requiredRole := agentRoleForVantage(vantage)

		if err := s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			_, err := s.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
				TenantID:          tenantID,
				Destination:       "connector.test",
				IdempotencyKey:    idemKey,
				Payload:           payload,
				EffectLane:        "connector.test:target:" + target.ID,
				RequiredAgentRole: requiredRole,
			})
			return err
		}); err != nil {
			return nil, err
		}

		// The receipt says QUEUED, not tested. The result arrives when the relay
		// reports; claiming a result now would be the same defect this epic
		// exists to fix, one status further along.
		detail := "a dry-run was queued for the " + requiredRole +
			" agent bound to this target; it will resolve credentials, probe the endpoint, and report a mutation plan without changing anything"
		if vantage == connector.VantageControlPlane {
			detail = "an effect-free provider preview was queued on the control-plane outbox; it will use the exact target revision and one-attempt credential lease to authenticate with a read-only provider operation, then report what a later deploy would change"
		}
		receipt, err := s.orch.RecordConnectorDelivery(ctx, tenantID, store.ConnectorDeliveryReceipt{
			Destination: "connector.test", Connector: target.Type, Target: target.Name,
			Status: servedstatus.ConnectorTestQueued, Attempts: 0, Reason: "dry_run_queued",
			Detail:         detail,
			IdempotencyKey: idemKey,
		})
		if err != nil {
			return nil, err
		}
		return &receipt, nil
	}
}

// routeConnectorTest keeps the central outbox dispatcher small and makes the
// execution boundary explicit: only control-plane rows run here. Host and
// network rows stay pending until the correctly enrolled agent claims them.
func (d *issuanceDispatcher) routeConnectorTest(ctx context.Context, m orchestrator.Message) error {
	if m.RequiredAgentRole == string(connector.VantageControlPlane) {
		return d.handleControlPlaneConnectorTest(ctx, m)
	}
	return orchestrator.DeferDelivery(fmt.Errorf(
		"server: %s executes on a target-vantage agent, not the control plane", m.Destination))
}

// handleControlPlaneConnectorTest runs the three cloud-store previews that have
// no host or network-relay vantage. The request handler only enqueues this row;
// all provider I/O occurs here on the bounded outbox worker (AN-6).
func (d *issuanceDispatcher) handleControlPlaneConnectorTest(ctx context.Context, m orchestrator.Message) error {
	var payload connector.DeployPayload
	if err := json.Unmarshal(m.Payload, &payload); err != nil {
		return fmt.Errorf("server: decode connector preview payload: %w", err)
	}
	payload.TenantID = m.TenantID
	receipt := connectorDeliveryEvidence{
		ID:             evidenceID("connector-preview", m.TenantID, m.IdempotencyKey+":result", m.ID),
		OutboxID:       outboxPtr(m.ID),
		Destination:    m.Destination,
		Connector:      nonempty(payload.Connector, "unconfigured"),
		Target:         nonempty(payload.Target, "unconfigured"),
		Attempts:       m.Attempts,
		IdempotencyKey: m.IdempotencyKey + ":result",
	}
	recordBlocked := func(reason string) error {
		receipt.Detail = reason
		return d.recordConnectorDelivery(ctx, m.TenantID, receipt, servedstatus.ConnectorTestBlocked, "dry_run_blocked")
	}
	if m.IdempotencyKey == "" {
		return recordBlocked("preview stopped before target contact: the queued command has no stable idempotency key")
	}
	if d.connectorRegistry == nil || !d.connectorRegistry.Has(payload.Connector) {
		return recordBlocked("preview stopped before target contact: the configured native connector is not loaded")
	}
	if d.connectorDeployVantage(payload.Connector) != connector.VantageControlPlane {
		return orchestrator.DeferDelivery(fmt.Errorf("server: %s connector preview executes at its target vantage, not the control plane", payload.Connector))
	}
	plan, err := d.connectorRegistry.Preview(ctx, payload)
	if err != nil {
		// A preview is an interactive verdict, not a deployment retry loop. The
		// terminal blocked receipt carries the actionable redacted cause and the
		// outbox row can be acknowledged because no mutation was attempted.
		return recordBlocked("preview blocked: " + err.Error())
	}
	receipt.Detail = plan.Detail + ". A later authorized deploy would: " + strings.Join(plan.WouldMutate, "; ")
	return d.recordConnectorDelivery(ctx, m.TenantID, receipt, servedstatus.ConnectorTestPlanned, "dry_run_planned")
}

// dryRunReceipt turns a relay's reported plan into a delivery receipt.
//
// The status distinguishes what an operator actually asked: would a deploy work
// here? A plan whose steps all passed records dry_run_planned; one that stopped
// records dry_run_blocked with the failing step's reason. Neither claims a
// deploy happened, because none did — the dry-run path never invokes a
// connector's Deploy at all.
func (s *Server) dryRunReceipt(ctx context.Context, tenantID, agentName, idempotencyKey, planJSON string) {
	if s.orch == nil {
		return
	}
	var plan struct {
		Connector string `json:"connector"`
		Target    string `json:"target"`
		Endpoint  string `json:"endpoint"`
		Ready     bool   `json:"ready"`
		Steps     []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
			Detail string `json:"detail"`
		} `json:"steps"`
		WouldMutate []string `json:"would_mutate"`
	}
	if err := json.Unmarshal([]byte(planJSON), &plan); err != nil {
		// A relay that reported something this cannot read is a version skew,
		// not a test result. Recording it as either outcome would be a guess.
		return
	}

	receiptStatus := servedstatus.ConnectorTestBlocked
	reason := "dry_run_blocked"
	detail := "a real deploy would not proceed"
	for _, step := range plan.Steps {
		if step.Status == "failed" {
			// The failing step's own words are the useful part: "connection
			// refused" and "password reference was not redeemed" send an
			// operator to different places. They name references and endpoints,
			// never values — the relay's plan carries no credential.
			detail = step.Name + ": " + step.Detail
			break
		}
	}
	if plan.Ready {
		receiptStatus = servedstatus.ConnectorTestPlanned
		reason = "dry_run_planned"
		detail = "a real deploy would proceed. It would: " + strings.Join(plan.WouldMutate, "; ")
	}

	if _, err := s.orch.RecordConnectorDelivery(ctx, tenantID, store.ConnectorDeliveryReceipt{
		Destination: "connector.test", Connector: plan.Connector, Target: plan.Target,
		Status: receiptStatus, Attempts: 1, Reason: reason, Detail: detail,
		// A distinct key from the queueing receipt: both belong in the evidence
		// chain, because "we asked" and "here is the answer" are different facts.
		IdempotencyKey: idempotencyKey + ":result",
	}); err != nil {
		return
	}
}
