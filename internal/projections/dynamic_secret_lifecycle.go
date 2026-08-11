// SPDX-License-Identifier: MPL-2.0

package projections

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

type dynamicSecretLifecycleLease struct {
	source              events.Event
	epoch               string
	idempotencyKey      string
	requestBinding      string
	provider            string
	role                string
	expiresAt           time.Time
	hardExpiresAt       time.Time
	backendRef          string
	prepared            *events.Event
	issued              *events.Event
	issuanceFailed      *events.Event
	revocationRequested *events.Event
	revocationCompleted *events.Event
	revocationFailed    *events.Event
	sequences           map[uint64]struct{}
}

type dynamicSecretLifecycleOperation struct {
	source         events.Event
	epoch          string
	requestBinding string
	action         string
	leaseID        string
	completed      *events.Event
	sequences      map[uint64]struct{}
}

type dynamicSecretTenantLifecycle struct {
	registered bool
	offboarded bool
	leases     map[string]*dynamicSecretLifecycleLease
	operations map[string]*dynamicSecretLifecycleOperation
}

// dynamicSecretLifecycleAuthority classifies retained v1 history against tenant
// offboards before any rebuild, catch-up, snapshot tail, or live tail applies it.
// V2 is self-fencing through tenant_epoch. V1 has no epoch, so the classifier
// remembers public lease/operation IDs erased by an offboard and treats any later
// duplicate as inert even when it was physically appended after re-registration.
type dynamicSecretLifecycleAuthority struct {
	head                 uint64
	skipSequences        map[uint64]struct{}
	lifecycles           map[string]dynamicSecretTenantLifecycle
	erasedLeaseIDs       map[string]struct{}
	erasedLeaseEpochs    map[string]struct{}
	erasedOperationIDs   map[string]struct{}
	erasedOperationEpoch map[string]struct{}
	seenByIdentity       map[string]events.Event
}

func newDynamicSecretLifecycleAuthority() *dynamicSecretLifecycleAuthority {
	return &dynamicSecretLifecycleAuthority{
		skipSequences:        map[uint64]struct{}{},
		lifecycles:           map[string]dynamicSecretTenantLifecycle{},
		erasedLeaseIDs:       map[string]struct{}{},
		erasedLeaseEpochs:    map[string]struct{}{},
		erasedOperationIDs:   map[string]struct{}{},
		erasedOperationEpoch: map[string]struct{}{},
		seenByIdentity:       map[string]events.Event{},
	}
}

func classifyDynamicSecretLifecycle(ctx context.Context, log *events.Log) (*dynamicSecretLifecycleAuthority, error) {
	var authority *dynamicSecretLifecycleAuthority
	err := log.WithHistoryRead(ctx, func(readCtx context.Context) error {
		head, err := log.LastSequence(readCtx)
		if err != nil {
			return err
		}
		authority, err = classifyDynamicSecretLifecycleThrough(readCtx, log, head)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("projections: classify retained dynamic-secret lifecycle: %w", err)
	}
	return authority, nil
}

func classifyDynamicSecretLifecycleThrough(
	ctx context.Context,
	log *events.Log,
	head uint64,
) (*dynamicSecretLifecycleAuthority, error) {
	authority := newDynamicSecretLifecycleAuthority()
	authority.head = head
	if err := log.ReplayThrough(ctx, 0, head, func(event events.Event) error {
		_, err := authority.observe(event)
		return err
	}); err != nil {
		return nil, err
	}
	return authority, nil
}

func (a *dynamicSecretLifecycleAuthority) skip(event events.Event) (bool, error) {
	if event.Sequence <= a.head {
		_, skip := a.skipSequences[event.Sequence]
		return skip, nil
	}
	skip, err := a.observe(event)
	if err == nil && event.Sequence > a.head {
		a.head = event.Sequence
	}
	return skip, err
}

func (a *dynamicSecretLifecycleAuthority) observe(event events.Event) (bool, error) {
	if event.Sequence == 0 || event.Sequence > uint64(1<<63-1) {
		if isDynamicSecretLifecycleEvent(event) {
			return false, fmt.Errorf("projections: dynamic-secret lifecycle event sequence is outside PostgreSQL bigint")
		}
		return false, nil
	}
	if !isDynamicSecretLifecycleEvent(event) {
		return false, nil
	}
	if isDynamicSecretTransitionEventType(event.Type) && event.Time.IsZero() {
		return false, fmt.Errorf("projections: %s event timestamp is empty", event.Type)
	}

	lifecycle := a.lifecycles[event.TenantID]
	if lifecycle.leases == nil {
		lifecycle.leases = map[string]*dynamicSecretLifecycleLease{}
	}
	if lifecycle.operations == nil {
		lifecycle.operations = map[string]*dynamicSecretLifecycleOperation{}
	}

	skip := false
	switch event.Type {
	case EventTenantRegistered:
		if !lifecycle.registered || lifecycle.offboarded {
			lifecycle = dynamicSecretTenantLifecycle{
				registered: true,
				leases:     map[string]*dynamicSecretLifecycleLease{},
				operations: map[string]*dynamicSecretLifecycleOperation{},
			}
		}
	case EventTenantOffboarded:
		for leaseID, lease := range lifecycle.leases {
			a.erasedLeaseIDs[dynamicSecretLifecycleKey(event.TenantID, leaseID)] = struct{}{}
			if lease.epoch != "" {
				a.erasedLeaseEpochs[dynamicSecretLifecycleEpochKey(event.TenantID, lease.epoch, leaseID)] = struct{}{}
			}
			for sequence := range lease.sequences {
				a.skipSequences[sequence] = struct{}{}
			}
		}
		for operationID, operation := range lifecycle.operations {
			a.erasedOperationIDs[dynamicSecretLifecycleKey(event.TenantID, operationID)] = struct{}{}
			if operation.epoch != "" {
				a.erasedOperationEpoch[dynamicSecretLifecycleEpochKey(event.TenantID, operation.epoch, operationID)] = struct{}{}
			}
			for sequence := range operation.sequences {
				a.skipSequences[sequence] = struct{}{}
			}
		}
		lifecycle.leases = map[string]*dynamicSecretLifecycleLease{}
		lifecycle.operations = map[string]*dynamicSecretLifecycleOperation{}
		lifecycle.offboarded = true
	default:
		if err := ValidateSchemaVersion(event); err != nil {
			return false, err
		}
		if prior, ok := a.seenByIdentity[event.ID]; ok {
			if !sameDynamicSecretLifecycleEnvelope(prior, event, false) {
				return false, fmt.Errorf("%w: dynamic-secret event id %q has conflicting retained envelopes", events.ErrConflictingEventIdentity, event.ID)
			}
			a.skipSequences[event.Sequence] = struct{}{}
			skip = true
			break
		}
		a.seenByIdentity[event.ID] = event
		var err error
		skip, err = a.observeTransition(event, &lifecycle)
		if err != nil {
			return false, err
		}
		if skip {
			a.skipSequences[event.Sequence] = struct{}{}
		}
	}
	a.lifecycles[event.TenantID] = lifecycle
	return skip, nil
}

func (a *dynamicSecretLifecycleAuthority) observeTransition(
	event events.Event,
	lifecycle *dynamicSecretTenantLifecycle,
) (bool, error) {
	schema := schemaVersionOf(event)
	switch event.Type {
	case EventDynamicSecretLeasePending:
		var payload DynamicSecretLeasePending
		if err := decode(event, &payload); err != nil {
			return false, err
		}
		if payload.ID == "" || payload.IdempotencyKey == "" || payload.Provider == "" ||
			payload.Role == "" || payload.ExpiresAt.IsZero() || payload.HardExpiresAt.IsZero() {
			return false, fmt.Errorf("projections: %s payload is incomplete", event.Type)
		}
		if err := validateDynamicSecretLifecycleIdentity(event, payload.TenantEpoch, "issue-requested", payload.ID); err != nil {
			return false, err
		}
		if lifecycle.offboarded || a.erasedLease(event.TenantID, payload.TenantEpoch, payload.ID, schema) {
			return true, nil
		}
		if prior := lifecycle.leases[payload.ID]; prior != nil {
			if !sameDynamicSecretLifecycleEnvelope(prior.source, event, true) {
				return false, fmt.Errorf("%w: dynamic-secret lease %s has conflicting pending sources", store.ErrIdempotencyConflict, payload.ID)
			}
			return true, nil
		}
		lifecycle.leases[payload.ID] = &dynamicSecretLifecycleLease{
			source: event, epoch: payload.TenantEpoch,
			idempotencyKey: payload.IdempotencyKey, requestBinding: payload.RequestBinding,
			provider: payload.Provider, role: payload.Role,
			expiresAt: payload.ExpiresAt, hardExpiresAt: payload.HardExpiresAt,
			sequences: map[uint64]struct{}{event.Sequence: {}},
		}
		return false, nil
	case EventDynamicSecretLeasePrepared:
		var payload DynamicSecretLeasePrepared
		if err := decode(event, &payload); err != nil {
			return false, err
		}
		if payload.ID == "" || payload.Provider == "" || len(payload.SealedPreparation) == 0 {
			return false, fmt.Errorf("projections: %s payload is incomplete", event.Type)
		}
		if err := validateDynamicSecretLifecycleIdentity(event, payload.TenantEpoch, "provider-prepared", payload.ID); err != nil {
			return false, err
		}
		lease, skip, err := a.dynamicSecretLeaseForTransition(event, lifecycle, payload.TenantEpoch, payload.ID)
		if err != nil || skip {
			return skip, err
		}
		if lease.provider != payload.Provider {
			return false, fmt.Errorf("%w: dynamic-secret preparation does not own its pending command", store.ErrIdempotencyConflict)
		}
		return recordDynamicSecretSingleton(event, &lease.prepared, lease.sequences, "preparation")
	case EventDynamicSecretLeaseIssued:
		var payload DynamicSecretLeaseIssued
		if err := decode(event, &payload); err != nil {
			return false, err
		}
		if payload.ID == "" || payload.IdempotencyKey == "" || payload.Provider == "" || payload.Role == "" ||
			payload.BackendRef == "" || len(payload.SealedCredential) == 0 ||
			payload.ExpiresAt.IsZero() || payload.HardExpiresAt.IsZero() {
			return false, fmt.Errorf("projections: %s payload is incomplete", event.Type)
		}
		if err := validateDynamicSecretLifecycleIdentity(event, payload.TenantEpoch, "provider-issued", payload.ID); err != nil {
			return false, err
		}
		lease, skip, err := a.dynamicSecretLeaseForTransition(event, lifecycle, payload.TenantEpoch, payload.ID)
		if err != nil || skip {
			return skip, err
		}
		if lease.idempotencyKey != payload.IdempotencyKey || lease.requestBinding != payload.RequestBinding ||
			lease.provider != payload.Provider || lease.role != payload.Role ||
			!samePostgresTime(lease.expiresAt, payload.ExpiresAt) ||
			!samePostgresTime(lease.hardExpiresAt, payload.HardExpiresAt) {
			return false, fmt.Errorf("%w: dynamic-secret issued result does not own its pending command", store.ErrIdempotencyConflict)
		}
		if lease.issuanceFailed != nil {
			return false, fmt.Errorf("%w: dynamic-secret lease %s has both issued and failed outcomes", store.ErrIdempotencyConflict, payload.ID)
		}
		duplicate, err := recordDynamicSecretSingleton(event, &lease.issued, lease.sequences, "issued result")
		if err == nil && !duplicate {
			lease.backendRef = payload.BackendRef
			lease.expiresAt = payload.ExpiresAt
		}
		return duplicate, err
	case EventDynamicSecretLeaseIssuanceFailed:
		var payload DynamicSecretLeaseIssuanceFailure
		if err := decode(event, &payload); err != nil {
			return false, err
		}
		if payload.ID == "" || payload.Error == "" {
			return false, fmt.Errorf("projections: %s payload is incomplete", event.Type)
		}
		if err := validateDynamicSecretLifecycleIdentity(event, payload.TenantEpoch, "provider-issue-failed", payload.ID); err != nil {
			return false, err
		}
		lease, skip, err := a.dynamicSecretLeaseForTransition(event, lifecycle, payload.TenantEpoch, payload.ID)
		if err != nil || skip {
			return skip, err
		}
		if lease.issued != nil {
			return false, fmt.Errorf("%w: dynamic-secret lease %s has both issued and failed outcomes", store.ErrIdempotencyConflict, payload.ID)
		}
		return recordDynamicSecretSingleton(event, &lease.issuanceFailed, lease.sequences, "issuance failure")
	case EventDynamicSecretLeaseRenewed:
		var payload DynamicSecretLeaseRenewed
		if err := decode(event, &payload); err != nil {
			return false, err
		}
		if payload.ID == "" || payload.ExpiresAt.IsZero() ||
			(schema >= DynamicSecretEventSchemaVersion && payload.OperationID == "") {
			return false, fmt.Errorf("projections: %s payload is incomplete", event.Type)
		}
		if err := validateDynamicSecretLifecycleIdentity(event, payload.TenantEpoch, "lease-renewed", payload.OperationID); err != nil {
			return false, err
		}
		lease, skip, err := a.dynamicSecretLeaseForTransition(event, lifecycle, payload.TenantEpoch, payload.ID)
		if err != nil || skip {
			return skip, err
		}
		if lease.issued == nil || payload.ExpiresAt.After(lease.hardExpiresAt) {
			return false, fmt.Errorf("%w: dynamic-secret renewal does not own an active bounded lease", store.ErrIdempotencyConflict)
		}
		lease.expiresAt = payload.ExpiresAt
		lease.sequences[event.Sequence] = struct{}{}
		return false, nil
	case EventDynamicSecretLeaseRevocationRequested:
		var payload DynamicSecretLeaseRevocationRequested
		if err := decode(event, &payload); err != nil {
			return false, err
		}
		if payload.ID == "" || payload.Provider == "" || payload.BackendRef == "" ||
			(schema >= DynamicSecretEventSchemaVersion && payload.OperationID == "") {
			return false, fmt.Errorf("projections: %s payload is incomplete", event.Type)
		}
		if err := validateDynamicSecretLifecycleIdentity(event, payload.TenantEpoch, "lease-revocation-requested", payload.OperationID); err != nil {
			return false, err
		}
		lease, skip, err := a.dynamicSecretLeaseForTransition(event, lifecycle, payload.TenantEpoch, payload.ID)
		if err != nil || skip {
			return skip, err
		}
		if lease.issued == nil || lease.provider != payload.Provider || lease.backendRef != payload.BackendRef {
			return false, fmt.Errorf("%w: dynamic-secret revocation does not own its issued result", store.ErrIdempotencyConflict)
		}
		return recordDynamicSecretSingleton(event, &lease.revocationRequested, lease.sequences, "revocation request")
	case EventDynamicSecretLeaseRevocationCompleted:
		var payload DynamicSecretLeaseRevocationCompleted
		if err := decode(event, &payload); err != nil {
			return false, err
		}
		if payload.ID == "" {
			return false, fmt.Errorf("projections: %s payload is incomplete", event.Type)
		}
		if err := validateDynamicSecretLifecycleIdentity(event, payload.TenantEpoch, "provider-revocation-completed", payload.ID); err != nil {
			return false, err
		}
		lease, skip, err := a.dynamicSecretLeaseForTransition(event, lifecycle, payload.TenantEpoch, payload.ID)
		if err != nil || skip {
			return skip, err
		}
		if lease.revocationRequested == nil || lease.revocationFailed != nil {
			return false, fmt.Errorf("%w: dynamic-secret revocation completion has no live request or contradicts failure", store.ErrIdempotencyConflict)
		}
		return recordDynamicSecretSingleton(event, &lease.revocationCompleted, lease.sequences, "revocation completion")
	case EventDynamicSecretLeaseRevocationFailed:
		var payload DynamicSecretLeaseFailure
		if err := decode(event, &payload); err != nil {
			return false, err
		}
		if payload.ID == "" || payload.Error == "" {
			return false, fmt.Errorf("projections: %s payload is incomplete", event.Type)
		}
		if err := validateDynamicSecretLifecycleIdentity(event, payload.TenantEpoch, "provider-revocation-failed", payload.ID); err != nil {
			return false, err
		}
		lease, skip, err := a.dynamicSecretLeaseForTransition(event, lifecycle, payload.TenantEpoch, payload.ID)
		if err != nil || skip {
			return skip, err
		}
		if lease.revocationRequested == nil || lease.revocationCompleted != nil {
			return false, fmt.Errorf("%w: dynamic-secret revocation failure has no live request or contradicts completion", store.ErrIdempotencyConflict)
		}
		return recordDynamicSecretSingleton(event, &lease.revocationFailed, lease.sequences, "revocation failure")
	case EventDynamicSecretOperationRequested:
		var payload DynamicSecretOperationRequested
		if err := decode(event, &payload); err != nil {
			return false, err
		}
		if payload.OperationID == "" || payload.IdempotencyKey == "" || payload.RequestBinding == "" ||
			payload.Action == "" || payload.LeaseID == "" || len(payload.Response) == 0 {
			return false, fmt.Errorf("projections: %s payload is incomplete", event.Type)
		}
		if err := validateDynamicSecretLifecycleIdentity(event, payload.TenantEpoch, "operation-requested", payload.OperationID); err != nil {
			return false, err
		}
		if lifecycle.offboarded || a.erasedOperation(event.TenantID, payload.TenantEpoch, payload.OperationID, schema) {
			return true, nil
		}
		lease := lifecycle.leases[payload.LeaseID]
		if lease == nil || !sameDynamicSecretEpoch(schema, payload.TenantEpoch, lease.epoch) {
			return false, fmt.Errorf("%w: dynamic-secret operation has no lease in its tenant lifecycle", store.ErrIdempotencyConflict)
		}
		if prior := lifecycle.operations[payload.OperationID]; prior != nil {
			if !sameDynamicSecretLifecycleEnvelope(prior.source, event, true) {
				return false, fmt.Errorf("%w: dynamic-secret operation %s has conflicting request sources", store.ErrIdempotencyConflict, payload.OperationID)
			}
			return true, nil
		}
		lifecycle.operations[payload.OperationID] = &dynamicSecretLifecycleOperation{
			source: event, epoch: payload.TenantEpoch, requestBinding: payload.RequestBinding,
			action: payload.Action, leaseID: payload.LeaseID,
			sequences: map[uint64]struct{}{event.Sequence: {}},
		}
		return false, nil
	case EventDynamicSecretOperationCompleted:
		var payload DynamicSecretOperationCompleted
		if err := decode(event, &payload); err != nil {
			return false, err
		}
		if payload.OperationID == "" || payload.RequestBinding == "" || payload.Action == "" || payload.LeaseID == "" {
			return false, fmt.Errorf("projections: %s payload is incomplete", event.Type)
		}
		if err := validateDynamicSecretLifecycleIdentity(event, payload.TenantEpoch, "operation-completed", payload.OperationID); err != nil {
			return false, err
		}
		if lifecycle.offboarded || a.erasedOperation(event.TenantID, payload.TenantEpoch, payload.OperationID, schema) {
			return true, nil
		}
		operation := lifecycle.operations[payload.OperationID]
		if operation == nil || !sameDynamicSecretEpoch(schema, payload.TenantEpoch, operation.epoch) ||
			operation.requestBinding != payload.RequestBinding || operation.action != payload.Action || operation.leaseID != payload.LeaseID {
			return false, fmt.Errorf("%w: dynamic-secret operation completion does not own its request", store.ErrIdempotencyConflict)
		}
		return recordDynamicSecretSingleton(event, &operation.completed, operation.sequences, "operation completion")
	default:
		return false, nil
	}
}

func (a *dynamicSecretLifecycleAuthority) dynamicSecretLeaseForTransition(
	event events.Event,
	lifecycle *dynamicSecretTenantLifecycle,
	epoch, leaseID string,
) (*dynamicSecretLifecycleLease, bool, error) {
	schema := schemaVersionOf(event)
	if lifecycle.offboarded || a.erasedLease(event.TenantID, epoch, leaseID, schema) {
		return nil, true, nil
	}
	lease := lifecycle.leases[leaseID]
	if lease == nil {
		return nil, false, fmt.Errorf("%w: dynamic-secret transition %s has no pending command in its tenant lifecycle", store.ErrIdempotencyConflict, event.Type)
	}
	if !sameDynamicSecretEpoch(schema, epoch, lease.epoch) {
		if _, erased := a.erasedLeaseEpochs[dynamicSecretLifecycleEpochKey(event.TenantID, epoch, leaseID)]; erased {
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("%w: dynamic-secret transition %s crosses tenant epochs", store.ErrIdempotencyConflict, event.Type)
	}
	return lease, false, nil
}

func (a *dynamicSecretLifecycleAuthority) erasedLease(tenantID, epoch, leaseID string, schema int) bool {
	if schema < DynamicSecretEventSchemaVersion {
		_, erased := a.erasedLeaseIDs[dynamicSecretLifecycleKey(tenantID, leaseID)]
		return erased
	}
	_, erased := a.erasedLeaseEpochs[dynamicSecretLifecycleEpochKey(tenantID, epoch, leaseID)]
	return erased
}

func (a *dynamicSecretLifecycleAuthority) erasedOperation(tenantID, epoch, operationID string, schema int) bool {
	if schema < DynamicSecretEventSchemaVersion {
		_, erased := a.erasedOperationIDs[dynamicSecretLifecycleKey(tenantID, operationID)]
		return erased
	}
	_, erased := a.erasedOperationEpoch[dynamicSecretLifecycleEpochKey(tenantID, epoch, operationID)]
	return erased
}

func validateDynamicSecretLifecycleIdentity(event events.Event, epoch, purpose, commandID string) error {
	if schemaVersionOf(event) < DynamicSecretEventSchemaVersion {
		return nil
	}
	if event.ID == "" || event.TenantID == "" || epoch == "" || commandID == "" ||
		event.ID != store.DynamicSecretEventID(event.TenantID, epoch, purpose, commandID) {
		return fmt.Errorf("%w: %s event identity is not canonical", store.ErrIdempotencyConflict, event.Type)
	}
	return nil
}

func recordDynamicSecretSingleton(
	event events.Event,
	current **events.Event,
	sequences map[uint64]struct{},
	label string,
) (bool, error) {
	if *current != nil {
		if !sameDynamicSecretLifecycleEnvelope(**current, event, true) {
			return false, fmt.Errorf("%w: dynamic-secret %s has conflicting retained results", store.ErrIdempotencyConflict, label)
		}
		return true, nil
	}
	copyEvent := event
	*current = &copyEvent
	sequences[event.Sequence] = struct{}{}
	return false, nil
}

func sameDynamicSecretEpoch(schema int, eventEpoch, sourceEpoch string) bool {
	return schema < DynamicSecretEventSchemaVersion || eventEpoch != "" && eventEpoch == sourceEpoch
}

// ignoreIdentity permits byte-exact legacy duplicates that were appended with a
// second random event ID. Time, schema, data, actor, type, and tenant must still
// match; a legacy result A/B pair therefore fails closed.
func sameDynamicSecretLifecycleEnvelope(left, right events.Event, ignoreIdentity bool) bool {
	left.Sequence = 0
	right.Sequence = 0
	if ignoreIdentity {
		left.ID = ""
		right.ID = ""
	}
	return left.ID == right.ID && left.Type == right.Type && left.TenantID == right.TenantID &&
		left.Time.Equal(right.Time) && left.SchemaVersion == right.SchemaVersion &&
		bytes.Equal(left.Data, right.Data) && reflect.DeepEqual(left.Actor, right.Actor)
}

func dynamicSecretLifecycleKey(tenantID, id string) string {
	return tenantID + "\x1f" + id
}

func dynamicSecretLifecycleEpochKey(tenantID, epoch, id string) string {
	return tenantID + "\x1f" + epoch + "\x1f" + id
}

func isDynamicSecretLifecycleEvent(event events.Event) bool {
	switch event.Type {
	case EventTenantRegistered, EventTenantOffboarded:
		return true
	default:
		return isDynamicSecretTransitionEventType(event.Type)
	}
}

func isDynamicSecretTransitionEventType(eventType string) bool {
	switch eventType {
	case EventDynamicSecretLeasePending,
		EventDynamicSecretLeasePrepared,
		EventDynamicSecretLeaseIssued,
		EventDynamicSecretLeaseIssuanceFailed,
		EventDynamicSecretLeaseRenewed,
		EventDynamicSecretLeaseRevocationRequested,
		EventDynamicSecretLeaseRevocationCompleted,
		EventDynamicSecretLeaseRevocationFailed,
		EventDynamicSecretOperationRequested,
		EventDynamicSecretOperationCompleted:
		return true
	default:
		return false
	}
}
