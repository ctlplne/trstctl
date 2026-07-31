// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

var (
	dynamicSecretLeaseNamespace     = uuid.MustParse("f4ca4708-7319-5c77-a50c-ad13185a86e8")
	dynamicSecretOperationNamespace = uuid.MustParse("c5cb64fd-788f-51c2-9ed2-4623d2bafee8")
	dynamicSecretEventNamespace     = uuid.MustParse("908f1994-a04c-506c-8471-71897e290a4a")
)

const (
	dynamicSecretIssuePollInterval = 25 * time.Millisecond
	dynamicSecretIssueWaitLimit    = 30 * time.Second
)

type maximumTTLProvider interface {
	dynsecret.Provider
	MaximumTTL() time.Duration
}

// durableDynamicSecretLifecycle is the production lease implementation. Its
// relational state is rebuilt from immutable events, and revocation events
// project the outbox intent in the same PostgreSQL transaction as lease state.
type durableDynamicSecretLifecycle struct {
	tenantID  string
	store     *store.Store
	log       *events.Log
	kek       seal.KeyWrapper
	crypto    tenantseal.Access
	outbox    *orchestrator.Outbox
	wake      func()
	providers map[string]dynsecret.Provider
}

func newDurableDynamicSecretLifecycle(tenantID string, providers []dynsecret.Provider, st *store.Store, log *events.Log, kek seal.KeyWrapper, outbox *orchestrator.Outbox, wake func(), tenantCrypto ...tenantseal.Access) (*durableDynamicSecretLifecycle, error) {
	if tenantID == "" || st == nil || log == nil || kek == nil || outbox == nil || wake == nil {
		return nil, errors.New("server: durable dynamic-secret lifecycle requires tenant, store, event log, KEK, outbox, and dispatcher wake")
	}
	registry := make(map[string]dynsecret.Provider, len(providers))
	for _, provider := range providers {
		if provider != nil && provider.Name() != "" {
			registry[provider.Name()] = provider
		}
	}
	if len(registry) == 0 {
		return nil, errors.New("server: durable dynamic-secret lifecycle has no tenant providers")
	}
	var access tenantseal.Access
	if len(tenantCrypto) > 0 {
		access = tenantCrypto[0]
	}
	return &durableDynamicSecretLifecycle{tenantID: tenantID, store: st, log: log, kek: kek, crypto: access, outbox: outbox, wake: wake, providers: registry}, nil
}

func (l *durableDynamicSecretLifecycle) Issue(ctx context.Context, providerID, role string, ttl time.Duration, idempotencyKey string) (dynsecret.Lease, []byte, error) {
	material := []byte(providerID + "\x00" + role + "\x00" + ttl.String())
	return l.issue(ctx, providerID, role, ttl, idempotencyKey, "legacy:"+crypto.SHA256Hex(material))
}

// IssueBound persists the API's authenticated principal + canonical command
// digest on the lease itself. The idempotency response cache is retained for a
// bounded window, while an active provider credential may outlive that window;
// the lease binding prevents a later caller from reopening it after cache GC.
func (l *durableDynamicSecretLifecycle) IssueBound(ctx context.Context, providerID, role string, ttl time.Duration, idempotencyKey, requestBinding string) (dynsecret.Lease, []byte, error) {
	if requestBinding == "" {
		return dynsecret.Lease{}, nil, errors.New("dynsecret: authenticated request binding is required")
	}
	return l.issue(ctx, providerID, role, ttl, idempotencyKey, requestBinding)
}

func (l *durableDynamicSecretLifecycle) issue(ctx context.Context, providerID, role string, ttl time.Duration, idempotencyKey, requestBinding string) (dynsecret.Lease, []byte, error) {
	if idempotencyKey == "" {
		return dynsecret.Lease{}, nil, errors.New("dynsecret: idempotency key is required")
	}
	if role == "" || ttl <= 0 {
		return dynsecret.Lease{}, nil, errors.New("dynsecret: role and positive TTL are required")
	}

	leaseID := "lease-" + uuid.NewSHA1(dynamicSecretLeaseNamespace, []byte(l.tenantID+"\x00"+idempotencyKey)).String()
	operationID := "issue:" + leaseID
	op, opErr := l.store.GetDynamicSecretOperationByIdempotencyKey(ctx, l.tenantID, idempotencyKey)
	operationFound := opErr == nil
	switch {
	case operationFound:
		if !dynamicSecretOperationMatches(op, operationID, idempotencyKey, requestBinding, "issue", leaseID) {
			return dynsecret.Lease{}, nil, dynamicSecretIdempotencyConflict()
		}
	case !store.IsNotFound(opErr):
		return dynsecret.Lease{}, nil, opErr
	}

	record, err := l.store.GetDynamicSecretLease(ctx, l.tenantID, leaseID)
	found := err == nil
	switch {
	case found:
		if record.IdempotencyKey != idempotencyKey || record.Provider != providerID || record.Role != role || record.RequestBinding != requestBinding {
			return dynsecret.Lease{}, nil, dynamicSecretIdempotencyConflict()
		}
		if record.State == store.DynamicSecretLeaseActive {
			credential, err := l.openCredential(ctx, record)
			return dynamicLeaseFromStore(record), credential, err
		}
		if record.State == store.DynamicSecretLeaseRevoked {
			return dynamicLeaseFromStore(record), nil, fmt.Errorf("%w %q", dynsecret.ErrLeaseNotActive, record.ID)
		}
		if record.State == store.DynamicSecretLeaseFailed || (operationFound && op.Status == store.DynamicSecretOperationFailed) {
			return dynsecret.Lease{}, nil, fmt.Errorf("dynsecret: prior issuance under this idempotency key failed; use a new key")
		}
	case !store.IsNotFound(err):
		return dynsecret.Lease{}, nil, err
	case operationFound:
		return dynsecret.Lease{}, nil, errors.New("dynsecret: durable issue command has no projected lease")
	}

	provider := l.providers[providerID]
	if provider == nil {
		return dynsecret.Lease{}, nil, fmt.Errorf("%w %q", dynsecret.ErrUnknownProvider, providerID)
	}
	if !found {
		maxTTL := ttl
		if bounded, ok := provider.(maximumTTLProvider); ok {
			maxTTL = bounded.MaximumTTL()
		}
		if maxTTL <= 0 || ttl > maxTTL {
			return dynsecret.Lease{}, nil, fmt.Errorf("dynsecret: requested TTL %s exceeds provider maximum %s", ttl, maxTTL)
		}
		// PostgreSQL timestamptz persists microseconds. Canonicalize the immutable
		// command before it enters the event log/outbox so its binding has one
		// representation across append, projection, restart, and worker delivery.
		now := time.Now().UTC().Truncate(time.Microsecond)
		pending := projections.DynamicSecretLeasePending{
			ID: leaseID, IdempotencyKey: idempotencyKey, RequestBinding: requestBinding, Provider: providerID, Role: role,
			ExpiresAt:     now.Add(ttl).Truncate(time.Microsecond),
			HardExpiresAt: now.Add(maxTTL).Truncate(time.Microsecond),
		}
		if err := l.appendAndProjectID(ctx, dynamicSecretEventID(l.tenantID, "issue-requested", operationID), projections.EventDynamicSecretLeasePending, pending); err != nil {
			return dynsecret.Lease{}, nil, err
		}
		op, err = l.store.GetDynamicSecretOperationByIdempotencyKey(ctx, l.tenantID, idempotencyKey)
		if err != nil {
			return dynsecret.Lease{}, nil, err
		}
		if !dynamicSecretOperationMatches(op, operationID, idempotencyKey, requestBinding, "issue", leaseID) {
			return dynsecret.Lease{}, nil, dynamicSecretIdempotencyConflict()
		}
		record, err = l.store.GetDynamicSecretLease(ctx, l.tenantID, leaseID)
		if err != nil {
			return dynsecret.Lease{}, nil, err
		}
	}

	if time.Until(record.HardExpiresAt) <= 0 {
		_ = l.appendAndProject(ctx, projections.EventDynamicSecretLeaseIssuanceFailed, projections.DynamicSecretLeaseFailure{ID: leaseID, Error: "provider credential validity window elapsed before issuance"})
		return dynsecret.Lease{}, nil, errors.New("dynsecret: provider credential validity window elapsed before issuance")
	}
	// The request thread only signals the normal bounded dispatcher and polls this
	// exact tenant/lease projection. It never calls Dispatch, a provider, or any
	// unrelated destination itself (AN-6/AN-7).
	l.wake()
	return l.waitForIssued(ctx, leaseID)
}

func (l *durableDynamicSecretLifecycle) waitForIssued(ctx context.Context, leaseID string) (dynsecret.Lease, []byte, error) {
	waitCtx, cancel := context.WithTimeout(ctx, dynamicSecretIssueWaitLimit)
	defer cancel()
	ticker := time.NewTicker(dynamicSecretIssuePollInterval)
	defer ticker.Stop()

	for {
		record, err := l.store.GetDynamicSecretLease(waitCtx, l.tenantID, leaseID)
		if err != nil {
			return dynsecret.Lease{}, nil, err
		}
		switch record.State {
		case store.DynamicSecretLeaseActive:
			credential, openErr := l.openCredential(waitCtx, record)
			return dynamicLeaseFromStore(record), credential, openErr
		case store.DynamicSecretLeaseFailed:
			return dynsecret.Lease{}, nil, fmt.Errorf("dynsecret: provider issuance failed: %s", record.LastError)
		case store.DynamicSecretLeaseRevoked:
			return dynamicLeaseFromStore(record), nil, fmt.Errorf("%w %q", dynsecret.ErrLeaseNotActive, record.ID)
		case store.DynamicSecretLeasePending:
			outboxRecord, outboxErr := l.outbox.Get(waitCtx, l.tenantID, record.IssueOutboxID)
			if outboxErr != nil {
				return dynsecret.Lease{}, nil, fmt.Errorf("dynsecret: read issue outbox result: %w", outboxErr)
			}
			if outboxRecord.Status == "failed" {
				message := "provider credential creation exhausted its retry budget"
				if outboxRecord.LastError != "" {
					message = outboxRecord.LastError
				}
				if err := l.appendAndProject(waitCtx, projections.EventDynamicSecretLeaseIssuanceFailed, projections.DynamicSecretLeaseFailure{ID: leaseID, Error: message}); err != nil {
					return dynsecret.Lease{}, nil, err
				}
				continue
			}
		default:
			return dynsecret.Lease{}, nil, fmt.Errorf("dynsecret: unsupported projected lease state %q", record.State)
		}

		select {
		case <-waitCtx.Done():
			return dynsecret.Lease{}, nil, fmt.Errorf("dynsecret: provider issuance remains pending: %w", waitCtx.Err())
		case <-ticker.C:
		}
	}
}

func (l *durableDynamicSecretLifecycle) openCredential(ctx context.Context, record store.DynamicSecretLease) ([]byte, error) {
	if len(record.SealedCredential) == 0 {
		return nil, errors.New("dynsecret: active lease has no sealed credential result")
	}
	value, err := openTenantValue(ctx, l.crypto, l.kek, l.tenantID, record.SealedCredential, dynamicSecretCredentialAAD(l.tenantID, record.ID, record.Provider))
	if err != nil {
		return nil, fmt.Errorf("dynsecret: open sealed credential result: %w", err)
	}
	return value, nil
}

func dynamicSecretCredentialAAD(tenantID, leaseID, provider string) []byte {
	return []byte(tenantID + "/dynamic-secret-lease/" + leaseID + "/" + provider)
}

func dynamicSecretPreparationAAD(tenantID, leaseID, provider string) []byte {
	return []byte(tenantID + "/dynamic-secret-lease-preparation/" + leaseID + "/" + provider)
}

func (l *durableDynamicSecretLifecycle) Renew(ctx context.Context, leaseID string, extend time.Duration) (dynsecret.Lease, error) {
	if extend <= 0 {
		return dynsecret.Lease{}, errors.New("dynsecret: positive renewal duration required")
	}
	record, err := l.store.GetDynamicSecretLease(ctx, l.tenantID, leaseID)
	if err != nil {
		return dynsecret.Lease{}, leaseStoreError(err, leaseID)
	}
	if record.State != store.DynamicSecretLeaseActive {
		return dynsecret.Lease{}, fmt.Errorf("%w %q", dynsecret.ErrLeaseNotActive, leaseID)
	}
	next := record.ExpiresAt.Add(extend)
	if next.After(record.HardExpiresAt) {
		return dynsecret.Lease{}, fmt.Errorf("dynsecret: renewal exceeds hard provider expiry %s", record.HardExpiresAt.Format(time.RFC3339))
	}
	if err := l.appendAndProject(ctx, projections.EventDynamicSecretLeaseRenewed, projections.DynamicSecretLeaseRenewed{ID: leaseID, ExpiresAt: next}); err != nil {
		return dynsecret.Lease{}, err
	}
	record.ExpiresAt = next
	return dynamicLeaseFromStore(record), nil
}

// RenewBound gives renewal its own durable authenticated command identity. The
// stored response freezes the expiry returned by the original call, so a replay
// after recorder GC does not accidentally return a later renewal's result.
func (l *durableDynamicSecretLifecycle) RenewBound(ctx context.Context, leaseID string, extend time.Duration, idempotencyKey, requestBinding string) (dynsecret.Lease, error) {
	if extend <= 0 {
		return dynsecret.Lease{}, errors.New("dynsecret: positive renewal duration required")
	}
	if idempotencyKey == "" || requestBinding == "" || leaseID == "" {
		return dynsecret.Lease{}, errors.New("dynsecret: bound renewal requires lease, idempotency key, and authenticated request binding")
	}
	operationID := dynamicSecretOperationID(l.tenantID, idempotencyKey)
	op, err := l.store.GetDynamicSecretOperationByIdempotencyKey(ctx, l.tenantID, idempotencyKey)
	if err == nil {
		if !dynamicSecretOperationMatches(op, operationID, idempotencyKey, requestBinding, "renew", leaseID) {
			return dynsecret.Lease{}, dynamicSecretIdempotencyConflict()
		}
		return l.resumeRenewal(ctx, op)
	}
	if !store.IsNotFound(err) {
		return dynsecret.Lease{}, err
	}

	record, err := l.store.GetDynamicSecretLease(ctx, l.tenantID, leaseID)
	if err != nil {
		return dynsecret.Lease{}, leaseStoreError(err, leaseID)
	}
	if record.State != store.DynamicSecretLeaseActive {
		return dynsecret.Lease{}, fmt.Errorf("%w %q", dynsecret.ErrLeaseNotActive, leaseID)
	}
	next := record.ExpiresAt.Add(extend)
	if next.After(record.HardExpiresAt) {
		return dynsecret.Lease{}, fmt.Errorf("dynsecret: renewal exceeds hard provider expiry %s", record.HardExpiresAt.Format(time.RFC3339))
	}
	response, err := json.Marshal(dynamicSecretOperationResponseFromLease(dynamicLeaseFromStore(record), dynsecret.LeaseActive, next))
	if err != nil {
		return dynsecret.Lease{}, err
	}
	requested := projections.DynamicSecretOperationRequested{
		OperationID: operationID, IdempotencyKey: idempotencyKey, RequestBinding: requestBinding,
		Action: "renew", LeaseID: leaseID, Response: response,
	}
	if err := l.appendAndProjectID(ctx, dynamicSecretEventID(l.tenantID, "operation-requested", operationID), projections.EventDynamicSecretOperationRequested, requested); err != nil {
		if errors.Is(err, store.ErrIdempotencyConflict) {
			return dynsecret.Lease{}, dynamicSecretIdempotencyConflict()
		}
		return dynsecret.Lease{}, err
	}
	op, err = l.store.GetDynamicSecretOperationByIdempotencyKey(ctx, l.tenantID, idempotencyKey)
	if err != nil {
		return dynsecret.Lease{}, err
	}
	if !dynamicSecretOperationMatches(op, operationID, idempotencyKey, requestBinding, "renew", leaseID) {
		return dynsecret.Lease{}, dynamicSecretIdempotencyConflict()
	}
	return l.resumeRenewal(ctx, op)
}

func (l *durableDynamicSecretLifecycle) resumeRenewal(ctx context.Context, op store.DynamicSecretOperation) (dynsecret.Lease, error) {
	response, err := decodeDynamicSecretOperationResponse(op.Response, l.tenantID)
	if err != nil {
		return dynsecret.Lease{}, err
	}
	switch op.Status {
	case store.DynamicSecretOperationCompleted:
		return response, nil
	case store.DynamicSecretOperationFailed:
		return dynsecret.Lease{}, fmt.Errorf("dynsecret: prior renewal failed: %s", op.LastError)
	case store.DynamicSecretOperationPending:
	default:
		return dynsecret.Lease{}, fmt.Errorf("dynsecret: unsupported renewal operation state %q", op.Status)
	}
	record, err := l.store.GetDynamicSecretLease(ctx, l.tenantID, op.LeaseID)
	if err != nil {
		return dynsecret.Lease{}, leaseStoreError(err, op.LeaseID)
	}
	if record.State != store.DynamicSecretLeaseActive {
		return dynsecret.Lease{}, fmt.Errorf("%w %q", dynsecret.ErrLeaseNotActive, op.LeaseID)
	}
	if response.ExpiresAt.After(record.HardExpiresAt) {
		return dynsecret.Lease{}, errors.New("dynsecret: durable renewal result exceeds provider hard expiry")
	}
	if record.ExpiresAt.Before(response.ExpiresAt) {
		if err := l.appendAndProjectID(ctx, dynamicSecretEventID(l.tenantID, "lease-renewed", op.OperationID), projections.EventDynamicSecretLeaseRenewed, projections.DynamicSecretLeaseRenewed{
			ID: op.LeaseID, ExpiresAt: response.ExpiresAt,
		}); err != nil {
			return dynsecret.Lease{}, err
		}
	}
	if err := l.completeDynamicSecretOperation(ctx, op); err != nil {
		return dynsecret.Lease{}, err
	}
	return response, nil
}

func (l *durableDynamicSecretLifecycle) Revoke(ctx context.Context, leaseID string) error {
	record, err := l.store.GetDynamicSecretLease(ctx, l.tenantID, leaseID)
	if err != nil {
		return leaseStoreError(err, leaseID)
	}
	if record.State == store.DynamicSecretLeaseRevoked {
		return nil
	}
	if record.State != store.DynamicSecretLeaseActive {
		return fmt.Errorf("%w %q", dynsecret.ErrLeaseNotActive, leaseID)
	}
	return l.appendAndProject(ctx, projections.EventDynamicSecretLeaseRevocationRequested, projections.DynamicSecretLeaseRevocationRequested{
		ID: record.ID, Provider: record.Provider, BackendRef: record.BackendRef,
	})
}

// RevokeBound persists the caller and full canonical revoke command before the
// lease becomes unusable. Its public result is replayable even after the generic
// HTTP recorder and delivered outbox row have been collected.
func (l *durableDynamicSecretLifecycle) RevokeBound(ctx context.Context, leaseID, idempotencyKey, requestBinding string) (dynsecret.Lease, error) {
	if leaseID == "" || idempotencyKey == "" || requestBinding == "" {
		return dynsecret.Lease{}, errors.New("dynsecret: bound revocation requires lease, idempotency key, and authenticated request binding")
	}
	operationID := dynamicSecretOperationID(l.tenantID, idempotencyKey)
	op, err := l.store.GetDynamicSecretOperationByIdempotencyKey(ctx, l.tenantID, idempotencyKey)
	if err == nil {
		if !dynamicSecretOperationMatches(op, operationID, idempotencyKey, requestBinding, "revoke", leaseID) {
			return dynsecret.Lease{}, dynamicSecretIdempotencyConflict()
		}
		return l.resumeRevocation(ctx, op)
	}
	if !store.IsNotFound(err) {
		return dynsecret.Lease{}, err
	}
	record, err := l.store.GetDynamicSecretLease(ctx, l.tenantID, leaseID)
	if err != nil {
		return dynsecret.Lease{}, leaseStoreError(err, leaseID)
	}
	if record.State != store.DynamicSecretLeaseActive && record.State != store.DynamicSecretLeaseRevoked {
		return dynsecret.Lease{}, fmt.Errorf("%w %q", dynsecret.ErrLeaseNotActive, leaseID)
	}
	response, err := json.Marshal(dynamicSecretOperationResponseFromLease(dynamicLeaseFromStore(record), dynsecret.LeaseRevoked, record.ExpiresAt))
	if err != nil {
		return dynsecret.Lease{}, err
	}
	requested := projections.DynamicSecretOperationRequested{
		OperationID: operationID, IdempotencyKey: idempotencyKey, RequestBinding: requestBinding,
		Action: "revoke", LeaseID: leaseID, Response: response,
	}
	if err := l.appendAndProjectID(ctx, dynamicSecretEventID(l.tenantID, "operation-requested", operationID), projections.EventDynamicSecretOperationRequested, requested); err != nil {
		if errors.Is(err, store.ErrIdempotencyConflict) {
			return dynsecret.Lease{}, dynamicSecretIdempotencyConflict()
		}
		return dynsecret.Lease{}, err
	}
	op, err = l.store.GetDynamicSecretOperationByIdempotencyKey(ctx, l.tenantID, idempotencyKey)
	if err != nil {
		return dynsecret.Lease{}, err
	}
	if !dynamicSecretOperationMatches(op, operationID, idempotencyKey, requestBinding, "revoke", leaseID) {
		return dynsecret.Lease{}, dynamicSecretIdempotencyConflict()
	}
	return l.resumeRevocation(ctx, op)
}

func (l *durableDynamicSecretLifecycle) resumeRevocation(ctx context.Context, op store.DynamicSecretOperation) (dynsecret.Lease, error) {
	response, err := decodeDynamicSecretOperationResponse(op.Response, l.tenantID)
	if err != nil {
		return dynsecret.Lease{}, err
	}
	switch op.Status {
	case store.DynamicSecretOperationCompleted:
		return response, nil
	case store.DynamicSecretOperationFailed:
		return dynsecret.Lease{}, fmt.Errorf("dynsecret: prior revocation failed: %s", op.LastError)
	case store.DynamicSecretOperationPending:
	default:
		return dynsecret.Lease{}, fmt.Errorf("dynsecret: unsupported revoke operation state %q", op.Status)
	}
	record, err := l.store.GetDynamicSecretLease(ctx, l.tenantID, op.LeaseID)
	if err != nil {
		return dynsecret.Lease{}, leaseStoreError(err, op.LeaseID)
	}
	switch record.State {
	case store.DynamicSecretLeaseActive:
		if err := l.appendAndProjectID(ctx, dynamicSecretEventID(l.tenantID, "lease-revocation-requested", op.OperationID), projections.EventDynamicSecretLeaseRevocationRequested, projections.DynamicSecretLeaseRevocationRequested{
			ID: record.ID, Provider: record.Provider, BackendRef: record.BackendRef,
		}); err != nil {
			return dynsecret.Lease{}, err
		}
		l.wake()
	case store.DynamicSecretLeaseRevoked:
		// A crash after projecting the outbox intent lands here. Do not enqueue or
		// call the provider again; complete only this authenticated API command.
		if record.RevocationStatus == store.DynamicSecretRevocationPending {
			l.wake()
		}
	default:
		return dynsecret.Lease{}, fmt.Errorf("%w %q", dynsecret.ErrLeaseNotActive, op.LeaseID)
	}
	if err := l.completeDynamicSecretOperation(ctx, op); err != nil {
		return dynsecret.Lease{}, err
	}
	return response, nil
}

func (l *durableDynamicSecretLifecycle) GetLease(leaseID string) (dynsecret.Lease, error) {
	return l.GetLeaseContext(context.Background(), leaseID)
}

func (l *durableDynamicSecretLifecycle) GetLeaseContext(ctx context.Context, leaseID string) (dynsecret.Lease, error) {
	record, err := l.store.GetDynamicSecretLease(ctx, l.tenantID, leaseID)
	if err != nil {
		return dynsecret.Lease{}, leaseStoreError(err, leaseID)
	}
	return dynamicLeaseFromStore(record), nil
}

func (l *durableDynamicSecretLifecycle) ExpireDue(ctx context.Context, now time.Time) (int, error) {
	records, err := l.store.ListDueDynamicSecretLeases(ctx, l.tenantID, now, 256)
	if err != nil {
		return 0, err
	}
	for _, record := range records {
		if err := l.Revoke(ctx, record.ID); err != nil {
			return 0, err
		}
	}
	return len(records), nil
}

// Revocation delivery is owned by the process-wide PostgreSQL outbox worker.
func (l *durableDynamicSecretLifecycle) RunRevocations(context.Context) (int, error) { return 0, nil }

func (l *durableDynamicSecretLifecycle) appendAndProject(ctx context.Context, eventType string, payload any) error {
	return l.appendAndProjectID(ctx, "", eventType, payload)
}

func (l *durableDynamicSecretLifecycle) appendAndProjectID(ctx context.Context, eventID, eventType string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event, err := l.log.Append(ctx, events.Event{ID: eventID, Type: eventType, TenantID: l.tenantID, Data: data})
	if err != nil {
		return err
	}
	return projections.New(l.store).Apply(ctx, event)
}

type dynamicSecretOperationResponse struct {
	LeaseID   string               `json:"lease_id"`
	Provider  string               `json:"provider"`
	Role      string               `json:"role"`
	State     dynsecret.LeaseState `json:"state"`
	IssuedAt  time.Time            `json:"issued_at"`
	ExpiresAt time.Time            `json:"expires_at"`
}

func dynamicSecretOperationResponseFromLease(lease dynsecret.Lease, state dynsecret.LeaseState, expiresAt time.Time) dynamicSecretOperationResponse {
	return dynamicSecretOperationResponse{
		LeaseID: lease.ID, Provider: lease.Provider, Role: lease.Role,
		State: state, IssuedAt: lease.IssuedAt, ExpiresAt: expiresAt,
	}
}

func decodeDynamicSecretOperationResponse(raw []byte, tenantID string) (dynsecret.Lease, error) {
	var response dynamicSecretOperationResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		return dynsecret.Lease{}, fmt.Errorf("dynsecret: decode durable operation response: %w", err)
	}
	if response.LeaseID == "" || response.Provider == "" || response.Role == "" || response.IssuedAt.IsZero() || response.ExpiresAt.IsZero() || (response.State != dynsecret.LeaseActive && response.State != dynsecret.LeaseRevoked) {
		return dynsecret.Lease{}, errors.New("dynsecret: durable operation response is incomplete")
	}
	return dynsecret.Lease{
		ID: response.LeaseID, TenantID: tenantID, Provider: response.Provider,
		Role: response.Role, State: response.State, IssuedAt: response.IssuedAt,
		ExpiresAt: response.ExpiresAt,
	}, nil
}

func dynamicSecretOperationID(tenantID, idempotencyKey string) string {
	return "dynsecret-op-" + uuid.NewSHA1(dynamicSecretOperationNamespace, []byte(tenantID+"\x00"+idempotencyKey)).String()
}

func dynamicSecretEventID(tenantID, purpose, operationID string) string {
	return "dynsecret-event-" + uuid.NewSHA1(dynamicSecretEventNamespace, []byte(tenantID+"\x00"+purpose+"\x00"+operationID)).String()
}

func dynamicSecretOperationMatches(op store.DynamicSecretOperation, operationID, idempotencyKey, requestBinding, action, leaseID string) bool {
	return op.OperationID == operationID && op.IdempotencyKey == idempotencyKey &&
		op.Action == action && op.LeaseID == leaseID &&
		crypto.ConstantTimeEqual([]byte(op.RequestBinding), []byte(requestBinding))
}

func dynamicSecretIdempotencyConflict() error {
	return fmt.Errorf("%w: dynsecret: idempotency key was already used for a different authenticated command", store.ErrIdempotencyConflict)
}

func (l *durableDynamicSecretLifecycle) completeDynamicSecretOperation(ctx context.Context, op store.DynamicSecretOperation) error {
	return l.appendAndProjectID(ctx, dynamicSecretEventID(l.tenantID, "operation-completed", op.OperationID), projections.EventDynamicSecretOperationCompleted, projections.DynamicSecretOperationCompleted{
		OperationID: op.OperationID, RequestBinding: op.RequestBinding,
		Action: op.Action, LeaseID: op.LeaseID,
	})
}

func dynamicLeaseFromStore(record store.DynamicSecretLease) dynsecret.Lease {
	return dynsecret.Lease{
		ID: record.ID, TenantID: record.TenantID, Provider: record.Provider, Role: record.Role,
		BackendRef: record.BackendRef, State: dynsecret.LeaseState(record.State),
		IssuedAt: record.IssuedAt, ExpiresAt: record.ExpiresAt,
	}
}

func leaseStoreError(err error, leaseID string) error {
	if store.IsNotFound(err) {
		return fmt.Errorf("%w %q", dynsecret.ErrLeaseNotFound, leaseID)
	}
	return err
}
