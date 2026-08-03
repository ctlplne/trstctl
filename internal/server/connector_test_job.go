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

// The relay-executed target test (epic D5).
//
// The console's test button used to record that a target's configuration
// parsed. That was true and nearly useless — it could not tell an operator
// whether the appliance was reachable or whether the credential still worked.
// This queues a real dry-run for the relay bound to that target: resolve
// everything a deploy needs, probe the endpoint, describe what would change,
// change nothing.
//
// It returns (nil, nil) rather than an error when no relay can take the work.
// That is the honest fallback: the route then records the local
// config-validated answer it always did, instead of queueing a job that would
// sit unclaimed while an operator waited for a result that was never coming.

// connectorTestEnqueuer builds the API's dry-run enqueuer over the served job
// ledger. The kind must be enabled by the operator like any other claimable
// kind, so enabling deploys and enabling tests stay separate decisions.
func (s *Server) connectorTestEnqueuer(claimable map[string]bool) func(context.Context, string, store.DeploymentTarget, string) (*store.ConnectorDeliveryReceipt, error) {
	return func(ctx context.Context, tenantID string, target store.DeploymentTarget, idempotencyKey string) (*store.ConnectorDeliveryReceipt, error) {
		if !claimable["connector.test"] || s.outbox == nil || s.store == nil || s.orch == nil {
			return nil, nil
		}
		// A target whose connector no agent can execute would queue work that
		// never drains. The census answers that before anything is enqueued.
		if s.connectorRegistry == nil {
			return nil, nil
		}
		vantage := s.connectorRegistry.TargetVantageFor(target.Type)
		if vantage == connector.VantageControlPlane {
			// Cloud stores have no relay and never will; the local answer is the
			// only honest one for them.
			return nil, nil
		}

		// The test payload carries the same shape a deploy does, minus any
		// credential: the relay redeems for itself. There is no cert or key
		// here — a dry-run proves the path, not the certificate.
		payload, err := json.Marshal(connector.DeployPayload{
			Connector:    target.Type,
			Target:       target.Name,
			TargetID:     target.ID,
			TargetConfig: append(json.RawMessage(nil), target.Config...),
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
		receipt, err := s.orch.RecordConnectorDelivery(ctx, tenantID, store.ConnectorDeliveryReceipt{
			Destination: "connector.test", Connector: target.Type, Target: target.Name,
			Status: servedstatus.ConnectorTestQueued, Attempts: 0, Reason: "dry_run_queued",
			Detail: "a dry-run was queued for the " + requiredRole +
				" agent bound to this target; it will resolve credentials, probe the endpoint, and report a mutation plan without changing anything",
			IdempotencyKey: idemKey,
		})
		if err != nil {
			return nil, err
		}
		return &receipt, nil
	}
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
