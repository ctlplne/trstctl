// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func dynamicSecretRevocationRequest(record store.DynamicSecretLease, operationID string) projections.DynamicSecretLeaseRevocationRequestedV3 {
	return projections.DynamicSecretLeaseRevocationRequestedV3{
		TenantEpoch: record.TenantEpoch, OperationID: operationID, ID: record.ID, Provider: record.Provider,
	}
}

func (l *durableDynamicSecretLifecycle) recoverDynamicSecretRevocation(
	ctx context.Context, record store.DynamicSecretLease, operationID string,
) (bool, error) {
	initialID := dynamicSecretEventID(l.tenantID, record.TenantEpoch, "lease-revocation-requested", operationID)
	retryID := dynamicSecretEventID(l.tenantID, record.TenantEpoch, "lease-revocation-retry-requested", operationID)
	initial, initialFound, err := l.log.EventByID(ctx, initialID)
	if err != nil {
		return false, err
	}
	retry, retryFound, err := l.log.EventByID(ctx, retryID)
	if err != nil {
		return false, err
	}
	if initialFound && retryFound {
		return false, fmt.Errorf("%w: revoke operation has conflicting request kinds", store.ErrIdempotencyConflict)
	}
	var retained events.Event
	switch {
	case initialFound:
		retained = initial
		if retained.Type != projections.EventDynamicSecretLeaseRevocationRequested {
			return false, store.ErrIdempotencyConflict
		}
	case retryFound:
		retained = retry
		if retained.Type != projections.EventDynamicSecretLeaseRevocationRetryRequested {
			return false, store.ErrIdempotencyConflict
		}
	default:
		return false, nil
	}
	source, err := projections.DecodeDynamicSecretRevocationSource(retained)
	if err != nil {
		return false, err
	}
	var expectedActor *events.Actor
	if actor, ok := events.ActorFromContext(ctx); ok {
		expectedActor = &actor
	}
	if retained.TenantID != l.tenantID || retained.Time.IsZero() || !reflect.DeepEqual(retained.Actor, expectedActor) ||
		source.TenantEpoch != record.TenantEpoch || source.LeaseID != record.ID || source.Provider != record.Provider ||
		source.OperationID != operationID || (source.LegacyRef != "" && source.LegacyRef != record.BackendRef) {
		return false, fmt.Errorf("%w: retained revoke request differs from the bound operation", store.ErrIdempotencyConflict)
	}
	if err := projections.ValidateRetainedDynamicSecretRevocationSource(ctx, l.log, retained); err != nil {
		return false, err
	}
	if l.afterCanonicalAppend != nil {
		if err := l.afterCanonicalAppend(retained); err != nil {
			return false, err
		}
	}
	if record.State == store.DynamicSecretLeaseRevoked {
		if !retryFound {
			return true, nil
		}
		if record.RevokeOutboxID != nil {
			projected, row, readErr := l.store.GetDynamicSecretRevocationOutboxRow(ctx, l.tenantID, *record.RevokeOutboxID)
			secret.Wipe(row.Payload)
			if readErr == nil && projected.TenantEpoch == record.TenantEpoch && projected.LeaseID == record.ID &&
				projected.Provider == record.Provider && projected.AttemptID == operationID {
				return true, nil
			}
		}
		item := store.DynamicSecretRevokeOutboxBinding{
			TenantEpoch: record.TenantEpoch, LeaseID: record.ID, Provider: record.Provider, AttemptID: operationID,
		}
		if _, found, err := retainedDynamicSecretRevocationOutcome(ctx, l.log, l.tenantID, item); err != nil || found {
			return found, err
		}
	}
	return true, projections.New(l.store).Apply(ctx, retained)
}

func (l *durableDynamicSecretLifecycle) publishDynamicSecretRevocationIntent(
	ctx context.Context, record store.DynamicSecretLease, eventID, eventType string, payload any,
) error {
	position, err := l.log.ObserveAppendSubject(ctx, l.tenantID, eventType)
	if err != nil {
		return err
	}
	if found, err := l.recoverUnprojectedRevocationIntent(ctx, record); err != nil || found {
		return err
	}
	err = l.appendAndProjectID(ctx, eventID, eventType, payload, position)
	if errors.Is(err, events.ErrAppendPositionChanged) {
		return store.ErrResourceAdmissionBusy
	}
	return err
}

// An append can outlive its SQL transaction. The lease publication lock
// prevents a second writer, and this check recovers any retained decision
// before a new operation can choose another attempt.
func (l *durableDynamicSecretLifecycle) recoverUnprojectedRevocationIntent(
	ctx context.Context, record store.DynamicSecretLease,
) (bool, error) {
	if record.RevocationStatus == store.DynamicSecretRevocationCompleted {
		return false, nil
	}
	sequence := record.RevocationEventSequence
	from := sequence + 1
	if sequence == 0 && record.State == store.DynamicSecretLeaseActive {
		issued, found, err := l.log.EventByID(ctx,
			dynamicSecretEventID(l.tenantID, record.TenantEpoch, "provider-issued", record.ID))
		if err != nil {
			return false, err
		}
		if found {
			from = issued.Sequence + 1
		}
	}
	head, err := l.log.LastSequence(ctx)
	if err != nil {
		return false, err
	}
	if head < sequence {
		return false, store.ErrIdempotencyConflict
	}
	request, observed, err := findRetainedDynamicSecretRevocationIntent(ctx, l.log, record, from, head)
	if err != nil || request.Sequence == 0 {
		return false, err
	}
	if err := projections.ValidateRetainedDynamicSecretRevocationSource(ctx, l.log, request); err != nil {
		return false, err
	}
	if sequence == 0 && record.RevokeOutboxID != nil {
		// A coordinated backup taken before the watermark column may already
		// carry the projected request and its settled or pending outbox row.
		existing, row, err := l.store.GetDynamicSecretRevocationOutboxRow(ctx, l.tenantID, *record.RevokeOutboxID)
		defer secret.Wipe(row.Payload)
		if err != nil {
			return false, err
		}
		if existing.TenantEpoch != record.TenantEpoch || existing.LeaseID != record.ID || existing.Provider != record.Provider {
			return false, store.ErrIdempotencyConflict
		}
		if existing.AttemptID == observed {
			return false, nil
		}
	}
	return true, projections.New(l.store).Apply(ctx, request)
}

func findRetainedDynamicSecretRevocationIntent(
	ctx context.Context, log *events.Log, record store.DynamicSecretLease, from, through uint64,
) (events.Event, string, error) {
	var request events.Event
	var attempt string
	if from > through {
		return request, attempt, nil
	}
	err := log.ReplayTenantTypesThrough(ctx, record.TenantID, from, through, []string{
		projections.EventDynamicSecretLeaseRevocationRequested, projections.EventDynamicSecretLeaseRevocationRetryRequested,
	}, func(e events.Event) error {
		var identity struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(e.Data, &identity); err != nil {
			return store.ErrIdempotencyConflict
		}
		if identity.ID != record.ID {
			return nil
		}
		source, err := projections.DecodeDynamicSecretRevocationSource(e)
		if err != nil {
			return err
		}
		if source.TenantEpoch != "" && source.TenantEpoch != record.TenantEpoch {
			return nil
		}
		if source.Provider != record.Provider || e.Time.IsZero() || e.SensitiveErased ||
			source.LegacyRef != "" && source.LegacyRef != record.BackendRef {
			return store.ErrIdempotencyConflict
		}
		request, attempt = e, ""
		if e.Type == projections.EventDynamicSecretLeaseRevocationRetryRequested {
			attempt = source.OperationID
		}
		return nil
	})
	return request, attempt, err
}

func (l *durableDynamicSecretLifecycle) failedRevocationPredecessor(ctx context.Context, record store.DynamicSecretLease) (string, error) {
	if record.RevokeOutboxID == nil {
		return "", errors.New("dynsecret: failed revocation has no provider command")
	}
	predecessor, row, err := l.store.GetDynamicSecretRevocationOutboxRow(ctx, l.tenantID, *record.RevokeOutboxID)
	defer secret.Wipe(row.Payload)
	if err != nil {
		return "", err
	}
	if predecessor.TenantEpoch != record.TenantEpoch || predecessor.LeaseID != record.ID ||
		predecessor.Provider != record.Provider || (predecessor.RefSource == "" && predecessor.BackendRef != record.BackendRef) {
		return "", fmt.Errorf("%w: failed predecessor does not own the issued lease", store.ErrIdempotencyConflict)
	}
	outcome, found, err := retainedDynamicSecretRevocationOutcome(ctx, l.log, l.tenantID, predecessor)
	if err != nil {
		return "", err
	}
	if !found || outcome.Type != projections.EventDynamicSecretLeaseRevocationFailed {
		return "", fmt.Errorf("%w: failed predecessor lacks a retained failure", store.ErrIdempotencyConflict)
	}
	if predecessor.AttemptID == "" {
		return store.DynamicSecretInitialRevokeAttempt, nil
	}
	return predecessor.AttemptID, nil
}

// retainedDynamicSecretRevocationOutcome verifies the existing terminal
// envelope without deriving a new result or losing its revocation method.
func retainedDynamicSecretRevocationOutcome(
	ctx context.Context, log *events.Log, tenantID string, item store.DynamicSecretRevokeOutboxBinding,
) (events.Event, bool, error) {
	commandID := item.LeaseID
	if item.AttemptID != "" {
		commandID = item.AttemptID
	}
	completeID := dynamicSecretEventID(tenantID, item.TenantEpoch, "provider-revocation-completed", commandID)
	failedID := dynamicSecretEventID(tenantID, item.TenantEpoch, "provider-revocation-failed", commandID)
	completed, completedFound, err := log.EventByID(ctx, completeID)
	if err != nil {
		return events.Event{}, false, err
	}
	failed, failedFound, err := log.EventByID(ctx, failedID)
	if err != nil {
		return events.Event{}, false, err
	}
	if completedFound && failedFound {
		return events.Event{}, false, fmt.Errorf("%w: revoke attempt has conflicting outcomes", store.ErrIdempotencyConflict)
	}
	verify := func(e events.Event, eventType string, identity string) bool {
		return e.ID == identity && e.Type == eventType && e.TenantID == tenantID &&
			e.SchemaVersion == projections.DynamicSecretEventSchemaVersion && !e.Time.IsZero() && !e.SensitiveErased
	}
	switch {
	case completedFound:
		var payload projections.DynamicSecretLeaseRevocationCompleted
		if !verify(completed, projections.EventDynamicSecretLeaseRevocationCompleted, completeID) ||
			!canonicalDynamicSecretOutcome(completed.Data, &payload) || payload.TenantEpoch != item.TenantEpoch ||
			payload.ID != item.LeaseID || payload.AttemptID != item.AttemptID || !store.ValidDynamicSecretRevocationMethod(payload.Method) {
			return events.Event{}, false, store.ErrIdempotencyConflict
		}
		return completed, true, nil
	case failedFound:
		var payload projections.DynamicSecretLeaseFailure
		if !verify(failed, projections.EventDynamicSecretLeaseRevocationFailed, failedID) ||
			!canonicalDynamicSecretOutcome(failed.Data, &payload) || payload.TenantEpoch != item.TenantEpoch ||
			payload.ID != item.LeaseID || payload.AttemptID != item.AttemptID || payload.Error == "" {
			return events.Event{}, false, store.ErrIdempotencyConflict
		}
		return failed, true, nil
	default:
		return events.Event{}, false, nil
	}
}

func canonicalDynamicSecretOutcome(raw []byte, out any) bool {
	if json.Unmarshal(raw, out) != nil {
		return false
	}
	canonical, err := json.Marshal(out)
	return err == nil && bytes.Equal(canonical, raw)
}

func (d *secretIntegrationOutboxDispatcher) dynamicSecretRevokeReference(
	ctx context.Context, tenantID string, provider dynsecret.Provider, record store.DynamicSecretLease,
) (string, error) {
	kind := dynsecret.HostedReferenceProviderType(provider)
	id := dynamicSecretEventID(tenantID, record.TenantEpoch, "provider-issued", record.ID)
	event, found, err := d.log.EventByID(ctx, id)
	if err != nil {
		return "", err
	}
	if kind == "" && (!found || event.SchemaVersion != projections.DynamicSecretHostedIssuedSchemaVersion) &&
		!strings.Contains(record.BackendRef, "/") {
		// Every hosted adapter stores binding/id, including the legacy writers.
		return record.BackendRef, nil
	}
	recovery := errors.New("server: hosted revocation needs verified public reference evidence or vendor-admin recovery")
	legacy := !found
	if legacy {
		event, found, err = projections.FindLegacyDynamicSecretIssuedSource(ctx, d.log, tenantID, record.ID)
		if err != nil {
			return "", err
		}
	}
	if !found || event.ID == "" || (!legacy && event.ID != id) || event.Time.IsZero() ||
		event.TenantID != tenantID || event.SensitiveErased {
		return "", recovery
	}
	issued, attestedKind, err := projections.DecodeDynamicSecretIssuedSource(event)
	epochMatches := issued.TenantEpoch == record.TenantEpoch
	if legacy {
		epochMatches = issued.TenantEpoch == "" && dynamicSecretPersistedTimeEqual(record.IssuedAt, event.Time)
	}
	if err != nil || !epochMatches || issued.ID != record.ID ||
		issued.Provider != record.Provider || issued.Role != record.Role || issued.BackendRef != record.BackendRef ||
		issued.IdempotencyKey != record.IdempotencyKey || issued.RequestBinding != record.RequestBinding {
		return "", recovery
	}
	reference, err := dynsecret.NormalizeHostedReference(provider, record.Role, record.BackendRef)
	if err != nil {
		return "", recovery
	}
	if attestedKind != "" {
		if kind != attestedKind || reference != record.BackendRef {
			return "", recovery
		}
		return reference, nil
	}
	switch kind {
	case "litellm":
		return reference, nil
	case "openrouter", "cloudflare-r2":
		// These older issued documents omit original fields that could
		// authenticate. The adapter could not prove the full ID check then.
		return "", recovery
	}
	opened, err := openTenantValue(ctx, d.tenantCrypto, d.kek, tenantID, issued.SealedCredential,
		dynamicSecretCredentialAAD(tenantID, issued.ID, issued.Provider))
	if err != nil || len(opened) == 0 {
		secret.Wipe(opened)
		return "", recovery
	}
	locked, err := secret.NewFrom(opened)
	secret.Wipe(opened)
	if err != nil {
		return "", recovery
	}
	defer locked.Destroy()
	if kind == "" {
		if dynsecret.LegacyHostedCredentialDocument(locked.Bytes()) {
			return "", recovery
		}
		return reference, nil
	}
	if err := dynsecret.ValidateIssuedHostedReference(provider, record.Role, reference, locked.Bytes()); err != nil {
		return "", recovery
	}
	return reference, nil
}
