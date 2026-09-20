// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/ownership"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const MaxOwnershipExceptionTTL = 30 * 24 * time.Hour

var ErrCMDBSweepInProgress = errors.New("orchestrator: CMDB schedule has an incomplete sweep")

var ownershipReattestationEventNamespace = uuid.MustParse("2d08f73a-3a9c-53a5-92f1-4d5b44aa0044")
var cmdbSweepEventNamespace = uuid.MustParse("0f235a4f-5938-5bd4-a6a8-e26bf50856ab")

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

// AssignOwnership records one attributed decision for up to 100 canonical NHI
// inventory records. The projector owns every read-model write; this command
// only validates the durable owner and appends the immutable source event.
func (o *Orchestrator) AssignOwnership(
	ctx context.Context,
	tenantID, ownerID string,
	inventoryIDs []string,
	reason, assignedBy string,
) (projections.OwnershipAssigned, error) {
	ownerID, reason, assignedBy = strings.TrimSpace(ownerID), strings.TrimSpace(reason), strings.TrimSpace(assignedBy)
	if ownerID == "" || reason == "" || assignedBy == "" {
		return projections.OwnershipAssigned{}, errors.New("orchestrator: ownership assignment requires an owner, authenticated principal, and reason")
	}
	if len(reason) > projections.MaxOwnershipAssignmentReasonLength || len(assignedBy) > projections.MaxOwnershipAssignmentPrincipalLength {
		return projections.OwnershipAssigned{}, errors.New("orchestrator: ownership assignment reason or principal is too long")
	}
	if len(inventoryIDs) == 0 || len(inventoryIDs) > projections.MaxOwnershipAssignmentAssets {
		return projections.OwnershipAssigned{}, errors.New("orchestrator: ownership assignment requires between 1 and 100 assets")
	}
	canonical := make([]string, 0, len(inventoryIDs))
	seen := make(map[string]bool, len(inventoryIDs))
	for _, inventoryID := range inventoryIDs {
		inventoryID = strings.TrimSpace(inventoryID)
		parts := strings.SplitN(inventoryID, "/", 2)
		if len(inventoryID) > projections.MaxOwnershipAssignmentInventoryIDLength || len(parts) != 2 ||
			len(parts[0]) > projections.MaxOwnershipAssignmentSourceLength || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return projections.OwnershipAssigned{}, fmt.Errorf("orchestrator: invalid ownership inventory id %q", inventoryID)
		}
		if seen[inventoryID] {
			return projections.OwnershipAssigned{}, fmt.Errorf("orchestrator: duplicate ownership inventory id %q", inventoryID)
		}
		seen[inventoryID] = true
		canonical = append(canonical, inventoryID)
	}
	sort.Strings(canonical)
	var assignment projections.OwnershipAssigned
	err := o.store.WithProjectionLock(ctx, func(lockCtx context.Context) error {
		if _, err := o.store.GetOwner(lockCtx, tenantID, ownerID); err != nil {
			return err
		}
		// The API first proves that every canonical ID is in the tenant's served
		// NHI inventory. Recheck native rows while holding the projection lock so
		// an identity/certificate deletion cannot win between that read and event
		// append, leaving an immutable event that the projector cannot apply.
		for _, inventoryID := range canonical {
			if ref, ok := strings.CutPrefix(inventoryID, "identity/"); ok {
				if _, err := o.store.GetIdentity(lockCtx, tenantID, ref); err != nil {
					return err
				}
				continue
			}
			if ref, ok := strings.CutPrefix(inventoryID, "certificate/"); ok {
				if _, err := o.store.GetCertificate(lockCtx, tenantID, ref); err != nil {
					return err
				}
			}
		}
		now := time.Now().UTC()
		assignment = projections.OwnershipAssigned{
			OwnerID: ownerID, InventoryIDs: canonical, Reason: reason, AssignedBy: assignedBy, AssignedAt: now,
		}
		payload, err := json.Marshal(assignment)
		if err != nil {
			return err
		}
		_, err = o.emitPrepared(lockCtx, events.Event{
			Type: projections.EventOwnershipAssigned, TenantID: tenantID, Time: now, Data: payload,
		})
		return err
	})
	return assignment, err
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
	var recipients []notify.AlertRecipient
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
		"cmdb-relay-result-v2\x00"+tenantID+"\x00"+resultKey+"\x00"+in.SourceRef+"\x00"+in.OwnerID,
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
	return o.store.WithProjectionLock(ctx, func(lockCtx context.Context) error {
		if current, found, loadErr := o.store.GetCMDBReconcileSchedule(lockCtx, tenantID); loadErr != nil {
			return loadErr
		} else if found && current.CurrentSweepID != "" && !current.CoverageComplete {
			return ErrCMDBSweepInProgress
		}
		_, err := o.emit(lockCtx, projections.EventCMDBScheduleConfigured, tenantID, payload)
		return err
	})
}

const cmdbSyncDestination = "cmdb.sync"

// QueueCMDBSweep commits the first-page checkpoint and network-relay intent in
// one tenant transaction. The event append remains the recovery authority for
// the narrow append/SQL crash window; ReconcileOutbox derives the same command.
func (o *Orchestrator) QueueCMDBSweep(
	ctx context.Context,
	tenantID string,
	intent ownership.CMDBSyncIntent,
	dispatchedAt time.Time,
) error {
	if dispatchedAt.IsZero() || intent.AfterSysID != "" || intent.ReadCount != 0 {
		return fmt.Errorf("orchestrator: invalid initial CMDB sweep checkpoint")
	}
	payload, err := json.Marshal(projections.CMDBSweepDispatched{Intent: intent, DispatchedAt: dispatchedAt.UTC()})
	if err != nil {
		return err
	}
	eventID := uuid.NewSHA1(cmdbSweepEventNamespace, []byte("dispatch\x00"+tenantID+"\x00"+intent.SweepID)).String()
	return o.store.WithProjectionLock(ctx, func(lockCtx context.Context) error {
		return o.emitCMDBEventWithContinuation(lockCtx, events.Event{
			ID: eventID, Type: projections.EventCMDBSweepDispatched, TenantID: tenantID, Data: payload,
		}, &intent)
	})
}

// ResumeCMDBSweep recreates a missing current-page outbox row from the exact
// projected checkpoint. It changes no domain state; it is the scheduler-side
// equivalent of boot ReconcileOutbox.
func (o *Orchestrator) ResumeCMDBSweep(ctx context.Context, tenantID string, intent ownership.CMDBSyncIntent) error {
	if o.outbox == nil {
		return fmt.Errorf("orchestrator: CMDB sweep outbox is not configured")
	}
	entry, err := cmdbSweepOutboxEntry(tenantID, intent)
	if err != nil {
		return err
	}
	return o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := o.store.ValidateCMDBSweepIntentTx(ctx, tx, tenantID, intent); err != nil {
			return err
		}
		_, err := o.outbox.EnqueueIfAbsent(ctx, tx, entry)
		return err
	})
}

// RecordCMDBSweepPage records the page checkpoint and, for a full page, its
// exact next command atomically. A retried signed receipt uses the same event ID
// and converges without advancing counts twice.
func (o *Orchestrator) RecordCMDBSweepPage(
	ctx context.Context,
	tenantID, resultKey string,
	page projections.CMDBSweepPageObserved,
) error {
	if err := validateCMDBSweepPageEvent(tenantID, resultKey, page); err != nil {
		return err
	}
	payload, err := json.Marshal(page)
	if err != nil {
		return err
	}
	eventID := uuid.NewSHA1(cmdbSweepEventNamespace,
		[]byte("page\x00"+tenantID+"\x00"+resultKey)).String()
	return o.emitCMDBEventWithContinuation(ctx, events.Event{
		ID: eventID, Type: projections.EventCMDBSweepPageObserved, TenantID: tenantID, Data: payload,
	}, page.NextIntent)
}

// RecordCMDBSweepFailure makes a failed relay attempt visible without moving
// the cursor. Each claim attempt has a distinct deterministic event identity.
func (o *Orchestrator) RecordCMDBSweepFailure(
	ctx context.Context,
	tenantID, resultKey string,
	attempt int,
	intent ownership.CMDBSyncIntent,
	failedAt time.Time,
	detail string,
) error {
	detail = strings.TrimSpace(detail)
	if resultKey == "" || attempt <= 0 || failedAt.IsZero() || detail == "" {
		return fmt.Errorf("orchestrator: invalid CMDB sweep failure receipt")
	}
	if _, err := cmdbSweepOutboxEntry(tenantID, intent); err != nil {
		return err
	}
	payload, err := json.Marshal(projections.CMDBSweepFailed{
		SweepID: intent.SweepID, AfterSysID: intent.AfterSysID,
		FailedAt: failedAt.UTC(), Detail: detail,
	})
	if err != nil {
		return err
	}
	eventID := uuid.NewSHA1(cmdbSweepEventNamespace,
		[]byte(fmt.Sprintf("failure\x00%s\x00%s\x00%d", tenantID, resultKey, attempt))).String()
	event, err := o.emitPrepared(ctx, events.Event{
		ID: eventID, Type: projections.EventCMDBSweepFailed, TenantID: tenantID, Data: payload,
	})
	if err != nil {
		return err
	}
	if event.ID != eventID || event.Type != projections.EventCMDBSweepFailed ||
		event.TenantID != tenantID || !bytes.Equal(event.Data, payload) {
		return fmt.Errorf("%w: canonical CMDB sweep failure event differs", store.ErrIdempotencyConflict)
	}
	return nil
}

func (o *Orchestrator) emitCMDBEventWithContinuation(
	ctx context.Context,
	next events.Event,
	continuation *ownership.CMDBSyncIntent,
) error {
	if o.outbox == nil {
		return fmt.Errorf("orchestrator: CMDB sweep outbox is not configured")
	}
	var continuationEntry *Entry
	if continuation != nil {
		entry, err := cmdbSweepOutboxEntry(next.TenantID, *continuation)
		if err != nil {
			return err
		}
		continuationEntry = &entry
	}
	return o.store.WithTenant(ctx, next.TenantID, func(tx pgx.Tx) error {
		event, err := o.log.Append(ctx, next)
		if err != nil {
			return err
		}
		if event.ID != next.ID || event.Type != next.Type || event.TenantID != next.TenantID ||
			!bytes.Equal(event.Data, next.Data) {
			return fmt.Errorf("%w: canonical CMDB sweep event differs", store.ErrIdempotencyConflict)
		}
		if err := o.proj.ApplyTx(ctx, tx, event); err != nil {
			return err
		}
		if continuationEntry == nil {
			return nil
		}
		_, err = o.outbox.EnqueueIfAbsent(ctx, tx, *continuationEntry)
		return err
	})
}

func cmdbSweepOutboxEntry(tenantID string, intent ownership.CMDBSyncIntent) (Entry, error) {
	sweepID, sweepErr := uuid.Parse(intent.SweepID)
	if sweepErr != nil || sweepID == uuid.Nil || intent.PageLimit <= 0 || intent.PageLimit > 500 ||
		intent.ReadCount < 0 || (intent.ExpectedCount != nil && *intent.ExpectedCount < intent.ReadCount) ||
		(intent.AfterSysID == "" && intent.ReadCount != 0) || (intent.AfterSysID != "" && intent.ReadCount == 0) ||
		!strings.HasPrefix(strings.TrimSpace(intent.TokenRef), "secret://") {
		return Entry{}, fmt.Errorf("orchestrator: invalid CMDB sweep intent")
	}
	if _, err := ownership.CMDBPageEndpoint(intent.InstanceURL, intent.CIQuery, intent.PageLimit, intent.AfterSysID); err != nil {
		return Entry{}, err
	}
	payload, err := json.Marshal(intent)
	if err != nil {
		return Entry{}, err
	}
	cursor := intent.AfterSysID
	if cursor == "" {
		cursor = "start"
	}
	return Entry{
		TenantID: tenantID, Destination: cmdbSyncDestination,
		IdempotencyKey: "cmdb-sync:" + tenantID + ":" + intent.SweepID + ":" + cursor,
		Payload:        payload, RequiredAgentRole: "network",
	}, nil
}

// validateCMDBSweepPageEvent keeps malformed data out of the immutable log.
// The projector validates again inside PostgreSQL, but that is too late: an
// append succeeds before its SQL transaction, so a bad event would poison every
// later rebuild even though the live request returned an error.
func validateCMDBSweepPageEvent(tenantID, resultKey string, page projections.CMDBSweepPageObserved) error {
	if strings.TrimSpace(resultKey) == "" || page.ObservedAt.IsZero() || page.Unattributed < 0 ||
		page.Unattributed > len(page.Observations) {
		return fmt.Errorf("orchestrator: invalid CMDB page event")
	}
	if _, err := cmdbSweepOutboxEntry(tenantID, page.Intent); err != nil {
		return err
	}
	pageSize := len(page.Observations)
	if pageSize > page.Intent.PageLimit || page.ReadCount != page.Intent.ReadCount+pageSize ||
		(page.ExpectedCount != nil && *page.ExpectedCount < page.ReadCount) ||
		(page.Complete && pageSize >= page.Intent.PageLimit) ||
		(!page.Complete && pageSize != page.Intent.PageLimit) {
		return fmt.Errorf("orchestrator: invalid bounded CMDB page progress")
	}
	previous := page.Intent.AfterSysID
	for _, observation := range page.Observations {
		if !ownership.ValidCMDBSourceRef(observation.SourceRef) ||
			(previous != "" && observation.SourceRef <= previous) {
			return fmt.Errorf("orchestrator: invalid CMDB page source order")
		}
		previous = observation.SourceRef
	}
	if page.Complete {
		if page.NextIntent != nil {
			return fmt.Errorf("orchestrator: terminal CMDB page carries a continuation")
		}
		return nil
	}
	if page.NextIntent == nil || page.NextIntent.InstanceURL != page.Intent.InstanceURL ||
		page.NextIntent.CIQuery != page.Intent.CIQuery || page.NextIntent.TokenRef != page.Intent.TokenRef ||
		page.NextIntent.PageLimit != page.Intent.PageLimit || page.NextIntent.SweepID != page.Intent.SweepID ||
		page.NextIntent.AfterSysID != previous || page.NextIntent.ReadCount != page.ReadCount ||
		!sameCMDBExpectedCount(page.NextIntent.ExpectedCount, page.ExpectedCount) {
		return fmt.Errorf("orchestrator: CMDB page continuation does not match its committed boundary")
	}
	return nil
}

func sameCMDBExpectedCount(left, right *int) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
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
