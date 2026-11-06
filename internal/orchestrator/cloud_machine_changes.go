// SPDX-License-Identifier: BUSL-1.1
package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/cloudentitlements/change"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func cloudChangeEventID(tenantID, id, phase string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("cloud-machine-change\x00"+tenantID+"\x00"+id+"\x00"+phase)).String()
}
func cloudChangeEntry(tenantID, id string) (Entry, error) {
	raw, err := json.Marshal(struct {
		ID string `json:"id"`
	}{id})
	if err != nil {
		return Entry{}, err
	}
	return Entry{TenantID: tenantID, Destination: change.Destination, Payload: raw, IdempotencyKey: "cloud-change:" + id, EffectLane: change.Destination + ":" + id, RequiredAgentRole: "control_plane"}, nil
}
func (o *Orchestrator) ProposeCloudMachineChange(ctx context.Context, tenantID, id, requester string, intent change.Intent, required int) (change.Record, error) {
	if id == "" || requester == "" || required < 1 || required > 5 {
		return change.Record{}, errors.New("incomplete cloud change proposal")
	}
	digest, err := change.Digest(intent)
	if err != nil {
		return change.Record{}, err
	}
	approval, err := o.EnsureOperationApprovalRequest(ctx, tenantID, OperationApprovalIntent{ResourceKind: "cloud_machine", ResourceID: id, ResourceName: intent.PrincipalARN, Action: intent.Action, Requester: requester, FromState: intent.FindingFingerprint, ToState: digest, TargetVersion: 1, Reason: intent.Reason, EvidenceRefs: []string{"discovery-finding:" + intent.FindingID, "cloud-intent-sha256:" + digest}, RequiredApprovals: required, TTL: time.Hour})
	if err != nil {
		return change.Record{}, err
	}
	value := change.Record{ID: id, TenantID: tenantID, Intent: intent, State: change.AwaitingApproval, ApprovalRequestID: approval.ID, IntentDigest: approval.IntentDigest, RequestedBy: requester, CreatedAt: approval.CreatedAt, UpdatedAt: approval.CreatedAt, ExpiresAt: approval.ExpiresAt}
	raw, err := json.Marshal(projections.CloudMachineChangeProposed{Record: value})
	if err != nil {
		return change.Record{}, err
	}
	if _, err = o.emitPreparedExact(ctx, events.Event{ID: cloudChangeEventID(tenantID, id, "proposed"), TenantID: tenantID, Type: projections.EventCloudMachineChangeProposed, Data: raw}); err != nil {
		return change.Record{}, err
	}
	return o.store.GetCloudMachineChange(ctx, tenantID, id)
}

// ExecuteCloudMachineChange consumes the exact one-shot approval and enqueues
// the external intent in the same tenant transaction as queued state.
func (o *Orchestrator) ExecuteCloudMachineChange(ctx context.Context, tenantID, id, requester string) (change.Record, error) {
	if o.outbox == nil {
		return change.Record{}, errors.New("cloud change outbox is not configured")
	}
	value, err := o.store.GetCloudMachineChange(ctx, tenantID, id)
	if err != nil {
		return value, err
	}
	if value.RequestedBy != requester {
		return value, store.ErrAccessChangeActorUnauthorized
	}
	if value.State != change.AwaitingApproval {
		return value, nil
	}
	entry, err := cloudChangeEntry(tenantID, id)
	if err != nil {
		return value, err
	}
	eventID := cloudChangeEventID(tenantID, id, "queued")
	retained, found, err := o.log.EventByID(ctx, eventID)
	if err != nil {
		return value, err
	}
	var next events.Event
	if found {
		var payload projections.CloudMachineChangeProgressed
		if retained.TenantID != tenantID || retained.Type != projections.EventCloudMachineChangeProgressed || json.Unmarshal(retained.Data, &payload) != nil || payload.ID != id || payload.State != change.Queued || payload.Approval == nil || payload.Approval.RequestID != value.ApprovalRequestID || payload.Approval.IntentDigest != value.IntentDigest {
			return value, store.ErrIdempotencyConflict
		}
		next = retained
	} else {
		approval, err := o.store.GetOperationApproval(ctx, tenantID, value.ApprovalRequestID)
		if err != nil {
			return value, err
		}
		use, err := store.OperationApprovalUseFromRequest(approval)
		if err != nil {
			return value, err
		}
		payload := projections.CloudMachineChangeProgressed{ID: id, State: change.Queued, Approval: &use, At: time.Now().UTC()}
		raw, err := json.Marshal(payload)
		if err != nil {
			return value, err
		}
		next = events.Event{ID: eventID, Type: projections.EventCloudMachineChangeProgressed, TenantID: tenantID, Data: raw}
	}
	err = o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		current, err := o.store.GetCloudMachineChangeTx(ctx, tx, tenantID, id)
		if err != nil {
			return err
		}
		if current.State != change.AwaitingApproval {
			return nil
		}

		// Re-read the immutable queue event under the plan lock. Another attempt
		// may have appended it before its database transaction was lost.
		canonical, retainedNow, err := o.log.EventByID(ctx, eventID)
		if err != nil {
			return err
		}
		var payload projections.CloudMachineChangeProgressed
		if retainedNow {
			if canonical.TenantID != tenantID || canonical.Type != projections.EventCloudMachineChangeProgressed || json.Unmarshal(canonical.Data, &payload) != nil || payload.ID != id || payload.State != change.Queued || payload.Approval == nil || payload.Approval.RequestID != current.ApprovalRequestID || payload.Approval.IntentDigest != current.IntentDigest {
				return store.ErrIdempotencyConflict
			}
			next = canonical
		} else {
			if json.Unmarshal(next.Data, &payload) != nil || payload.Approval == nil {
				return store.ErrIdempotencyConflict
			}
			payload.At = time.Now().UTC()
			raw, err := json.Marshal(payload)
			if err != nil {
				return err
			}
			next.Data = raw
			next.Time = payload.At
		}
		if _, err := o.store.ValidateOperationApprovalUseTx(ctx, tx, tenantID, *payload.Approval, next.Time); err != nil {
			return err
		}

		ev, err := o.log.Append(ctx, next)
		if err != nil {
			return err
		}
		if !bytes.Equal(ev.Data, next.Data) || ev.ID != next.ID || ev.TenantID != tenantID {
			return store.ErrIdempotencyConflict
		}
		if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
			return err
		}
		_, err = o.outbox.EnqueueIfAbsent(ctx, tx, entry)
		return err
	})
	if err != nil {
		return value, err
	}
	return o.store.GetCloudMachineChange(ctx, tenantID, id)
}

func (o *Orchestrator) RecoverCloudMachineChangeResult(ctx context.Context, tenantID, id string) (bool, error) {
	event, found, err := o.log.EventByID(ctx, cloudChangeEventID(tenantID, id, "result"))
	if err != nil || !found {
		return found, err
	}
	var payload projections.CloudMachineChangeProgressed
	if event.TenantID != tenantID || event.Type != projections.EventCloudMachineChangeProgressed || json.Unmarshal(event.Data, &payload) != nil || payload.ID != id || (payload.State != change.Verified && payload.State != change.Failed) || payload.Result == nil {
		return true, store.ErrIdempotencyConflict
	}
	_, err = o.emitPreparedExact(ctx, event)
	return true, err
}
func (o *Orchestrator) RecordCloudMachineChangeResult(ctx context.Context, tenantID, id, state string, result change.Result) error {
	if found, err := o.RecoverCloudMachineChangeResult(ctx, tenantID, id); err != nil || found {
		return err
	}
	if state != change.Verified && state != change.Failed {
		return errors.New("invalid cloud change result")
	}
	raw, err := json.Marshal(projections.CloudMachineChangeProgressed{ID: id, State: state, Result: &result, At: result.CheckedAt})
	if err != nil {
		return err
	}
	_, err = o.emitPreparedExact(ctx, events.Event{ID: cloudChangeEventID(tenantID, id, "result"), TenantID: tenantID, Type: projections.EventCloudMachineChangeProgressed, Data: raw})
	return err
}

// ReconcileCloudMachineChanges restores outbox intents from retained approval
// events after a lost database transaction or read-model rebuild. It never
// creates fresh authority for an awaiting proposal.
func (o *Orchestrator) ReconcileCloudMachineChanges(ctx context.Context) (int, error) {
	if o.outbox == nil {
		return 0, nil
	}
	tenants, err := o.store.ListTenants(ctx)
	if err != nil {
		return 0, err
	}
	healed := 0
	for _, tenant := range tenants {
		after := ""
		for {
			plans, err := o.store.ListCloudMachineChanges(ctx, tenant.TenantID, after, 100)
			if err != nil {
				return healed, err
			}
			for _, plan := range plans {
				after = plan.ID
				switch plan.State {
				case change.AwaitingApproval:
					_, found, err := o.log.EventByID(ctx, cloudChangeEventID(tenant.TenantID, plan.ID, "queued"))
					if err != nil {
						return healed, err
					}
					if !found {
						continue
					}
					if _, err := o.ExecuteCloudMachineChange(ctx, tenant.TenantID, plan.ID, plan.RequestedBy); err != nil {
						return healed, err
					}
					healed++
				case change.Queued, change.Preparing, change.WaitingAdoption:
					if found, err := o.RecoverCloudMachineChangeResult(ctx, tenant.TenantID, plan.ID); err != nil {
						return healed, err
					} else if found {
						healed++
						continue
					}
					if plan.State == change.Preparing || plan.State == change.WaitingAdoption {
						err := o.withTenantCommand(ctx, tenant.TenantID, func(ctx context.Context, tx pgx.Tx) error {
							current, err := o.store.GetCloudMachineChangeTx(ctx, tx, tenant.TenantID, plan.ID)
							if err != nil {
								return err
							}
							return o.store.EnsureCloudMachinePhaseOutboxTx(ctx, tx, tenant.TenantID, plan.ID, current.State)
						})
						if err != nil {
							return healed, err
						}
						continue
					}
					entry, err := cloudChangeEntry(tenant.TenantID, plan.ID)
					if err != nil {
						return healed, err
					}
					err = o.withTenantCommand(ctx, tenant.TenantID, func(ctx context.Context, tx pgx.Tx) error {
						current, err := o.store.GetCloudMachineChangeTx(ctx, tx, tenant.TenantID, plan.ID)
						if err != nil {
							return err
						}
						if current.State != change.Queued {
							return nil
						}
						_, err = o.outbox.EnqueueIfAbsent(ctx, tx, entry)
						return err
					})
					if err != nil {
						return healed, err
					}
				}
			}
			if len(plans) < 100 {
				break
			}
		}
	}
	return healed, nil
}

// RecoverCloudMachineReplacementPhase resumes the retained event before any new
// receiver I/O. Native preparation and waiting use separate durable deliveries.
func (o *Orchestrator) RecoverCloudMachineReplacementPhase(ctx context.Context, tenantID, id, state string) (bool, error) {
	event, found, err := o.log.EventByID(ctx, cloudChangeEventID(tenantID, id, state))
	if err != nil || !found {
		return found, err
	}
	var payload projections.CloudMachineChangeProgressed
	if event.TenantID != tenantID || event.Type != projections.EventCloudMachineChangeProgressed || json.Unmarshal(event.Data, &payload) != nil || payload.ID != id || payload.State != state || payload.Result == nil {
		return true, store.ErrIdempotencyConflict
	}
	_, err = o.emitPreparedExact(ctx, event)
	return true, err
}
func (o *Orchestrator) RecordCloudMachineReplacementPhase(ctx context.Context, tenantID, id, state string, result change.Result) error {
	if state != change.Preparing && state != change.WaitingAdoption {
		return errors.New("invalid cloud replacement phase")
	}
	if found, err := o.RecoverCloudMachineReplacementPhase(ctx, tenantID, id, state); err != nil || found {
		return err
	}
	raw, err := json.Marshal(projections.CloudMachineChangeProgressed{ID: id, State: state, Result: &result, At: result.CheckedAt})
	if err != nil {
		return err
	}
	_, err = o.emitPreparedExact(ctx, events.Event{ID: cloudChangeEventID(tenantID, id, state), TenantID: tenantID, Type: projections.EventCloudMachineChangeProgressed, Data: raw})
	return err
}
