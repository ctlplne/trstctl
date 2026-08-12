// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const MaxOwnershipExceptionTTL = 30 * 24 * time.Hour

var ownershipReattestationEventNamespace = uuid.MustParse("2d08f73a-3a9c-53a5-92f1-4d5b44aa0044")

// CreateOwnerRecord is the v2 owner command. The source-compatible CreateOwner
// wrapper remains for older embedders, while every served API write uses this
// complete event shape.
func (o *Orchestrator) CreateOwnerRecord(ctx context.Context, owner store.Owner) (store.Owner, error) {
	owner.ID = uuid.NewString()
	if err := validateOwnerRecord(owner); err != nil {
		return store.Owner{}, err
	}
	chain, _ := store.OwnerEscalationChain(owner.EscalationChain)
	payload, err := json.Marshal(projections.OwnerCreated{
		ID: owner.ID, Kind: string(owner.Kind), Name: strings.TrimSpace(owner.Name), Email: strings.TrimSpace(owner.Email),
		ApplicationID: strings.TrimSpace(owner.ApplicationID), Service: strings.TrimSpace(owner.Service),
		BusinessUnit: strings.TrimSpace(owner.BusinessUnit), Environment: strings.TrimSpace(owner.Environment),
		EscalationChain: chain,
	})
	if err != nil {
		return store.Owner{}, err
	}
	ev, err := o.emitVersioned(ctx, projections.EventOwnerCreated, owner.TenantID, projections.OwnerDepthEventSchemaVersion, payload)
	if err != nil {
		return store.Owner{}, err
	}
	created, err := o.store.GetOwner(ctx, owner.TenantID, owner.ID)
	if err != nil {
		return store.Owner{}, err
	}
	created.CreatedAt = ev.Time
	return created, nil
}

func (o *Orchestrator) UpdateOwnerRecord(ctx context.Context, owner store.Owner) (store.Owner, error) {
	var updated store.Owner
	err := o.store.WithProjectionLock(ctx, func(lockCtx context.Context) error {
		if _, err := o.store.GetOwner(lockCtx, owner.TenantID, owner.ID); err != nil {
			return err
		}
		if err := validateOwnerRecord(owner); err != nil {
			return err
		}
		chain, _ := store.OwnerEscalationChain(owner.EscalationChain)
		payload, err := json.Marshal(projections.OwnerUpdated{
			ID: owner.ID, Kind: string(owner.Kind), Name: strings.TrimSpace(owner.Name), Email: strings.TrimSpace(owner.Email),
			ApplicationID: strings.TrimSpace(owner.ApplicationID), Service: strings.TrimSpace(owner.Service),
			BusinessUnit: strings.TrimSpace(owner.BusinessUnit), Environment: strings.TrimSpace(owner.Environment),
			EscalationChain: chain,
		})
		if err != nil {
			return err
		}
		if _, err := o.emitVersioned(lockCtx, projections.EventOwnerUpdated, owner.TenantID, projections.OwnerDepthEventSchemaVersion, payload); err != nil {
			return err
		}
		updated, err = o.store.GetOwner(lockCtx, owner.TenantID, owner.ID)
		return err
	})
	return updated, err
}

func validateOwnerRecord(owner store.Owner) error {
	switch owner.Kind {
	case store.OwnerUser, store.OwnerTeam, store.OwnerWorkload, store.OwnerService, store.OwnerVendor:
	default:
		return fmt.Errorf("orchestrator: unsupported owner kind %q", owner.Kind)
	}
	if strings.TrimSpace(owner.Name) == "" {
		return errors.New("orchestrator: owner name is required")
	}
	for label, value := range map[string]string{
		"name": owner.Name, "email": owner.Email, "application_id": owner.ApplicationID,
		"service": owner.Service, "business_unit": owner.BusinessUnit, "environment": owner.Environment,
	} {
		if len(value) > 512 {
			return fmt.Errorf("orchestrator: owner %s is too long", label)
		}
	}
	_, err := store.OwnerEscalationChain(owner.EscalationChain)
	return err
}

// AttestOwnership records a human decision bound to the current readiness model.
func (o *Orchestrator) AttestOwnership(ctx context.Context, tenantID, ownerID, attestedBy string) (store.Owner, error) {
	attestedBy = strings.TrimSpace(attestedBy)
	if attestedBy == "" {
		return store.Owner{}, errors.New("orchestrator: ownership attestation requires an authenticated principal")
	}
	var attested store.Owner
	err := o.store.WithProjectionLock(ctx, func(lockCtx context.Context) error {
		owner, err := o.store.GetOwner(lockCtx, tenantID, ownerID)
		if err != nil {
			return err
		}
		if !owner.OwnershipComplete() {
			return errors.New("orchestrator: ownership attestation requires application_id and environment")
		}
		digest, err := store.OwnerModelDigest(owner)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		payload, err := json.Marshal(projections.OwnershipAttested{
			OwnerID: ownerID, AttestedBy: attestedBy, AttestedAt: now, ModelDigest: digest,
		})
		if err != nil {
			return err
		}
		if _, err := o.emitPrepared(lockCtx, events.Event{
			Type: projections.EventOwnershipAttested, TenantID: tenantID, Time: now, Data: payload,
		}); err != nil {
			return err
		}
		attested, err = o.store.GetOwner(lockCtx, tenantID, ownerID)
		return err
	})
	return attested, err
}

func (o *Orchestrator) GrantOwnershipException(
	ctx context.Context,
	tenantID, identityID, reason, grantedBy string,
	expiresAt time.Time,
) (store.OwnershipException, error) {
	reason, grantedBy = strings.TrimSpace(reason), strings.TrimSpace(grantedBy)
	if reason == "" || grantedBy == "" {
		return store.OwnershipException{}, errors.New("orchestrator: ownership exception requires an authenticated grantor and reason")
	}
	var granted store.OwnershipException
	err := o.store.WithProjectionLock(ctx, func(lockCtx context.Context) error {
		if _, err := o.store.GetIdentity(lockCtx, tenantID, identityID); err != nil {
			return err
		}
		now := time.Now().UTC()
		expiresAt = expiresAt.UTC()
		if !expiresAt.After(now) || expiresAt.After(now.Add(MaxOwnershipExceptionTTL)) {
			return fmt.Errorf("orchestrator: ownership exception expiry must be in the next %s", MaxOwnershipExceptionTTL)
		}
		id := uuid.NewString()
		payload, err := json.Marshal(projections.OwnershipExceptionGranted{
			ID: id, IdentityID: identityID, Reason: reason, GrantedBy: grantedBy,
			GrantedAt: now, ExpiresAt: expiresAt,
		})
		if err != nil {
			return err
		}
		if _, err := o.emitPrepared(lockCtx, events.Event{
			Type: projections.EventOwnershipExceptionGranted, TenantID: tenantID, Time: now, Data: payload,
		}); err != nil {
			return err
		}
		granted, err = o.store.GetOwnershipException(lockCtx, tenantID, id)
		return err
	})
	return granted, err
}

func (o *Orchestrator) RevokeOwnershipException(
	ctx context.Context,
	tenantID, identityID, exceptionID, reason, revokedBy string,
) (store.OwnershipException, error) {
	reason, revokedBy = strings.TrimSpace(reason), strings.TrimSpace(revokedBy)
	if reason == "" || revokedBy == "" {
		return store.OwnershipException{}, errors.New("orchestrator: ownership exception revocation requires an authenticated principal and reason")
	}
	var revoked store.OwnershipException
	err := o.store.WithProjectionLock(ctx, func(lockCtx context.Context) error {
		exception, err := o.store.GetOwnershipException(lockCtx, tenantID, exceptionID)
		if err != nil {
			return err
		}
		if exception.IdentityID != identityID {
			return pgx.ErrNoRows
		}
		if exception.RevokedAt != nil {
			revoked = exception
			return nil
		}
		now := time.Now().UTC()
		payload, err := json.Marshal(projections.OwnershipExceptionRevoked{
			ID: exceptionID, RevokedBy: revokedBy, Reason: reason, RevokedAt: now,
		})
		if err != nil {
			return err
		}
		if _, err := o.emitPrepared(lockCtx, events.Event{
			Type: projections.EventOwnershipExceptionRevoked, TenantID: tenantID, Time: now, Data: payload,
		}); err != nil {
			return err
		}
		revoked, err = o.store.GetOwnershipException(lockCtx, tenantID, exceptionID)
		return err
	})
	return revoked, err
}

// QueueOwnershipReattestation turns one stale verification edge into one event
// and notification intent in the same PostgreSQL transaction. The row lock makes
// the bounded scheduler safe under two leaders racing the same candidate.
func (o *Orchestrator) QueueOwnershipReattestation(
	ctx context.Context,
	tenantID, ownerID string,
	cadence time.Duration,
) (bool, error) {
	if cadence <= 0 || o.outbox == nil {
		return false, nil
	}
	queued := false
	err := o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		now := time.Now().UTC()
		owner, claim, err := o.store.ClaimOwnershipReattestationCandidateTx(ctx, tx, tenantID, ownerID, now, cadence)
		if err != nil || !claim {
			return err
		}
		chain, err := store.OwnerEscalationChain(owner.EscalationChain)
		if err != nil {
			return err
		}
		dueAt := now
		verifiedMarker := "never"
		if owner.OwnershipVerifiedAt != nil {
			dueAt = owner.OwnershipVerifiedAt.UTC().Add(cadence)
			verifiedMarker = owner.OwnershipVerifiedAt.UTC().Format(time.RFC3339Nano)
		}
		payloadObject := projections.OwnerReattestationRequested{
			OwnerID: owner.ID, VerifiedFor: owner.OwnershipVerifiedAt, DueAt: dueAt,
			RequestedAt: now, CadenceSeconds: int(cadence / time.Second),
			OwnerName: owner.Name, OwnerEmail: owner.Email, EscalationRecipients: chain,
		}
		payload, err := json.Marshal(payloadObject)
		if err != nil {
			return err
		}
		eventID := uuid.NewSHA1(ownershipReattestationEventNamespace,
			[]byte(tenantID+"\x00"+owner.ID+"\x00"+verifiedMarker)).String()
		event, err := o.log.Append(ctx, events.Event{
			ID: eventID, Type: projections.EventOwnerReattestationRequested,
			TenantID: tenantID, Time: now, Data: payload,
		})
		if err != nil {
			return err
		}
		var canonical projections.OwnerReattestationRequested
		if err := json.Unmarshal(event.Data, &canonical); err != nil {
			return err
		}
		if err := o.proj.ApplyTx(ctx, tx, event); err != nil {
			return err
		}
		entry, err := ownershipReattestationOutboxEntry(event.TenantID, event.ID, canonical)
		if err != nil {
			return err
		}
		inserted, err := o.outbox.EnqueueIfAbsent(ctx, tx, entry)
		queued = inserted
		return err
	})
	return queued, err
}

func ownershipReattestationOutboxEntry(
	tenantID, eventID string,
	payload projections.OwnerReattestationRequested,
) (Entry, error) {
	recipients := make([]notify.AlertRecipient, 0, 1+len(payload.EscalationRecipients))
	if payload.OwnerEmail != "" {
		recipients = append(recipients, notify.AlertRecipient{
			Kind: "owner", Subject: payload.OwnerID, DisplayName: payload.OwnerName, Email: payload.OwnerEmail,
		})
	}
	for _, recipient := range payload.EscalationRecipients {
		recipients = append(recipients, notify.AlertRecipient{Kind: "escalation", Subject: recipient, Email: recipient})
	}
	alert := notify.Alert{
		Kind: notify.KindOwnershipReattestation, TenantID: tenantID,
		OwnerID: payload.OwnerID, OwnerName: payload.OwnerName, OwnerEmail: payload.OwnerEmail,
		Detail:   "ownership attestation is due; confirm the application and environment before the next steady-state deployment",
		Severity: notify.AlertSeverityWarning, EscalationRecipients: recipients,
	}
	encoded, err := json.Marshal(alert)
	if err != nil {
		return Entry{}, err
	}
	return Entry{
		TenantID: tenantID, Destination: notify.DestinationOwnership,
		IdempotencyKey: "ownership-reattestation:" + eventID, Payload: encoded,
	}, nil
}

// ReconcileOwnership records one owner's reconciliation against an external
// source as one event. Applied values and refused conflicts stay atomic so a
// crash cannot leave provenance and the ownership row disagreeing.
func (o *Orchestrator) ReconcileOwnership(ctx context.Context, tenantID string, in projections.OwnershipReconciled) error {
	return o.reconcileOwnership(ctx, tenantID, "", in)
}

// ReconcileOwnershipFromRelay binds a relay replay to one deterministic event.
func (o *Orchestrator) ReconcileOwnershipFromRelay(ctx context.Context, tenantID, resultKey string, in projections.OwnershipReconciled) error {
	eventID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(
		"cmdb-relay-result\x00"+tenantID+"\x00"+resultKey+"\x00"+in.OwnerID,
	)).String()
	return o.reconcileOwnership(ctx, tenantID, eventID, in)
}

func (o *Orchestrator) reconcileOwnership(ctx context.Context, tenantID, eventID string, in projections.OwnershipReconciled) error {
	if len(in.Applied) == 0 && len(in.Conflicts) == 0 {
		return nil
	}
	if in.ObservedAt.IsZero() {
		in.ObservedAt = time.Now().UTC()
	}
	payload, err := json.Marshal(in)
	if err != nil {
		return err
	}
	if eventID == "" {
		_, err = o.emit(ctx, projections.EventOwnershipReconciled, tenantID, payload)
	} else {
		_, err = o.emitPrepared(ctx, events.Event{
			ID: eventID, Type: projections.EventOwnershipReconciled, TenantID: tenantID, Data: payload,
		})
	}
	return err
}

// ConfigureCMDBSchedule records a tenant's standing instruction to re-read its
// CMDB. TokenRef is a reference name, never a token value.
func (o *Orchestrator) ConfigureCMDBSchedule(ctx context.Context, tenantID string, in projections.CMDBScheduleConfigured) error {
	payload, err := json.Marshal(in)
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventCMDBScheduleConfigured, tenantID, payload)
	return err
}

// ResolveOwnershipConflict closes an ownership disagreement with attributable
// reasoning. A bare "resolved" flag is not usable evidence.
func (o *Orchestrator) ResolveOwnershipConflict(ctx context.Context, tenantID, id, by, resolution string) error {
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("orchestrator: no conflict named")
	}
	if strings.TrimSpace(by) == "" {
		return fmt.Errorf("orchestrator: a resolution needs the operator who made it; an unattributed judgement cannot be questioned later")
	}
	if strings.TrimSpace(resolution) == "" {
		return fmt.Errorf("orchestrator: a resolution needs a reason. Closing a disagreement without saying which side was right leaves the next reader exactly where they started")
	}
	payload, err := json.Marshal(projections.OwnershipConflictResolved{
		ID: id, ResolvedBy: strings.TrimSpace(by),
		Resolution: strings.TrimSpace(resolution), ResolvedAt: time.Now().UTC(),
	})
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventOwnershipConflictResolved, tenantID, payload)
	return err
}
