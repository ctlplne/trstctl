// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/sshtrustrollout"
	"trstctl.com/trstctl/internal/store"
)

func SSHTrustFleetRolloutID(tenantID, approvalRequestID string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("ssh-trust-fleet\x00"+tenantID+"\x00"+approvalRequestID)).String()
}
func SSHTrustFleetJobKey(rolloutID, agentID string) string {
	return "ssh-trust-fleet:" + rolloutID + ":" + agentID
}

// StartSSHTrustFleet consumes one exact approval beside the rollout projection
// and all host-bound outbox intents. A retained source heals the append/SQL gap.
func (o *Orchestrator) StartSSHTrustFleet(ctx context.Context, tenantID string, started projections.SSHTrustFleetStarted) error {
	if o == nil || o.log == nil || o.store == nil || o.outbox == nil {
		return errors.New("SSH trust fleet execution is not configured")
	}
	if err := projections.ValidateSSHTrustFleetStarted(started); err != nil {
		return err
	}
	if started.ID != SSHTrustFleetRolloutID(tenantID, started.Approval.RequestID) {
		return errors.New("SSH trust rollout ID differs from its approved command")
	}
	raw, err := json.Marshal(started)
	if err != nil {
		return err
	}
	return o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		canonical, found, err := o.log.EventByID(ctx, started.ID)
		if err != nil {
			return err
		}
		if !found {
			now := time.Now().UTC()
			if _, err := o.store.ValidateOperationApprovalUseTx(ctx, tx, tenantID, started.Approval, now); err != nil {
				return err
			}
			if err := o.store.ValidateSSHTrustFleetReadyTx(ctx, tx, tenantID, started.Plan, now); err != nil {
				return err
			}
			canonical, err = o.log.Append(ctx, events.Event{ID: started.ID, TenantID: tenantID, Type: projections.EventSSHTrustFleetStarted, Data: raw})
			if err != nil {
				return err
			}
		}
		if canonical.ID != started.ID || canonical.Type != projections.EventSSHTrustFleetStarted || canonical.TenantID != tenantID || canonical.SchemaVersion != 1 {
			return fmt.Errorf("%w: SSH trust source envelope changed", store.ErrIdempotencyConflict)
		}
		matches, err := operationApprovalEventDataMatches(canonical, raw, tenantID, started.Approval.Requester)
		if err != nil {
			return err
		}
		if !matches {
			return fmt.Errorf("%w: SSH trust approved command changed", store.ErrIdempotencyConflict)
		}
		if err := validateOperationApprovalBoundActor(canonical.Actor, tenantID, started.Approval.Requester); err != nil {
			return err
		}
		if err := o.proj.ApplyTx(ctx, tx, canonical); err != nil {
			return err
		}
		// Build from the first source's bytes, including after a privacy rewrite.
		var retained projections.SSHTrustFleetStarted
		if err := json.Unmarshal(canonical.Data, &retained); err != nil {
			return err
		}
		_, err = o.enqueueSSHTrustFleetTx(ctx, tx, tenantID, retained)
		return err
	})
}

func (o *Orchestrator) enqueueSSHTrustFleetTx(ctx context.Context, tx pgx.Tx, tenantID string, started projections.SSHTrustFleetStarted) (int, error) {
	inserted := 0
	for _, host := range started.Plan.Hosts {
		if host.State != "ready" {
			continue
		}
		command := sshtrustrollout.Command{RolloutID: started.ID, AgentID: host.AgentID, PublicCAKey: started.Plan.PublicCAKey, CAFingerprint: started.Plan.CAFingerprint, PlanDigest: started.PlanDigest, ReadinessDigest: host.ReadinessDigest, ExpiresAt: started.Plan.ExpiresAt}
		if err := command.Validate(); err != nil {
			return inserted, err
		}
		payload, err := json.Marshal(command)
		if err != nil {
			return inserted, err
		}
		added, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{TenantID: tenantID, Destination: sshtrustrollout.Destination, IdempotencyKey: SSHTrustFleetJobKey(started.ID, host.AgentID), Payload: payload, EffectLane: "ssh-trust-host:" + host.AgentID, RequiredAgentRole: "host", RequiredAgentID: host.AgentID})
		if err != nil {
			return inserted, err
		}
		if added {
			inserted++
		}
	}
	return inserted, nil
}

func (o *Orchestrator) reconcileSSHTrustFleet(ctx context.Context, event events.Event) (int, error) {
	var started projections.SSHTrustFleetStarted
	if err := json.Unmarshal(event.Data, &started); err != nil {
		return 0, err
	}
	if event.SchemaVersion != 1 || event.ID != started.ID || started.ID != SSHTrustFleetRolloutID(event.TenantID, started.Approval.RequestID) {
		return 0, errors.New("SSH trust retained source envelope differs")
	}
	if err := projections.ValidateSSHTrustFleetStarted(started); err != nil {
		return 0, err
	}
	var count int
	err := o.store.WithTenant(ctx, event.TenantID, func(tx pgx.Tx) error {
		var err error
		count, err = o.enqueueSSHTrustFleetTx(ctx, tx, event.TenantID, started)
		return err
	})
	return count, err
}

// RecordSSHTrustFleetObservation retains the signature-checked result using
// one deterministic source per exact job attempt. A conflicting retry cannot
// replace failed facts with an invented successful effect.
func (o *Orchestrator) RecordSSHTrustFleetObservation(ctx context.Context, tenantID, eventID string, observed projections.SSHTrustFleetObserved) error {
	if err := projections.ValidateSSHTrustFleetObserved(observed); err != nil {
		return err
	}
	raw, err := json.Marshal(observed)
	if err != nil {
		return err
	}
	return o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		canonical, found, err := o.log.EventByID(ctx, eventID)
		if err != nil {
			return err
		}
		if !found {
			canonical, err = o.log.Append(ctx, events.Event{ID: eventID, TenantID: tenantID, Type: projections.EventSSHTrustFleetObserved, Data: raw})
			if err != nil {
				return err
			}
		}
		if canonical.ID != eventID || canonical.Type != projections.EventSSHTrustFleetObserved || canonical.TenantID != tenantID || canonical.SchemaVersion != 1 {
			return fmt.Errorf("%w: SSH trust receipt source envelope changed", store.ErrIdempotencyConflict)
		}
		var first projections.SSHTrustFleetObserved
		if err := json.Unmarshal(canonical.Data, &first); err != nil {
			return err
		}
		firstFacts, err := json.Marshal(first.Report)
		if err != nil {
			return err
		}
		newFacts, err := json.Marshal(observed.Report)
		if err != nil {
			return err
		}
		// Re-signing a retained report after reconnect may change the signature,
		// signing timestamp or leaf fingerprint. The first valid proof remains
		// canonical; none of its exact execution facts may change.
		if first.JobID != observed.JobID || first.Attempt != observed.Attempt || first.EvidenceDigest != observed.EvidenceDigest || !bytes.Equal(firstFacts, newFacts) {
			return fmt.Errorf("%w: SSH trust receipt facts changed", store.ErrIdempotencyConflict)
		}
		return o.proj.ApplyTx(ctx, tx, canonical)
	})
}
