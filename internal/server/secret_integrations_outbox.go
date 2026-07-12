// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

var secretSyncEventNamespace = uuid.MustParse("8dfda7f4-9293-55f0-b2fe-642a43276964")

// secretIntegrationOutboxDispatcher owns the first-party dynsecret.* and
// secret.sync.* destinations. Keeping this routing explicit prevents the generic
// dispatcher fallback from acknowledging an unknown secret side effect as though
// it had been delivered.
type secretIntegrationOutboxDispatcher struct {
	dynamicProviders DynamicSecretProviderRegistry
	syncTargets      SecretSyncTargetRegistry
	kek              seal.KeyWrapper
	store            *store.Store
	log              *events.Log

	// Test-only crash seam. Runtime proof uses it to interrupt the worker after a
	// version-creating receiver commits but before the delivered event/outbox ACK.
	// Production leaves it nil.
	afterSecretSyncDelivery func(context.Context, secretSyncOutboxPayload) error
}

func queueSecretSyncEvent(ctx context.Context, st *store.Store, log *events.Log, kek seal.KeyWrapper, tenantID, secretName string, secretVersion int, target, remoteKey, idempotencyKey, requestBinding string, value []byte) error {
	if st == nil || log == nil || kek == nil {
		return errors.New("server: durable secret sync requires store, event log, and KEK")
	}
	if tenantID == "" || secretName == "" || secretVersion <= 0 || target == "" || remoteKey == "" || idempotencyKey == "" || requestBinding == "" {
		return errors.New("server: durable secret sync command is incomplete")
	}
	jobID := store.DurableSecretSyncJobID(tenantID, idempotencyKey)
	command := store.SecretSyncJob{
		ID: jobID, TenantID: tenantID, SecretName: secretName, SecretVersion: int64(secretVersion),
		Target: target, RemoteKey: remoteKey, ValueDigest: crypto.SHA256Hex(value),
		IdempotencyKey: "secret.sync." + target + ":" + idempotencyKey, RequestBinding: requestBinding,
	}
	if existing, err := st.GetSecretSyncJob(ctx, tenantID, jobID); err == nil {
		if !store.SecretSyncCommandMatches(existing, command) {
			return fmt.Errorf("%w: secret-sync idempotency key already binds another authenticated command", store.ErrIdempotencyConflict)
		}
		return nil
	} else if !store.IsNotFound(err) {
		return err
	}
	sealed, err := seal.Seal(kek, value, secretSyncAAD(tenantID, target, jobID, remoteKey))
	if err != nil {
		return err
	}
	payload := projections.SecretSyncQueued{
		ID: jobID, SecretName: secretName, SecretVersion: int64(secretVersion),
		Target: target, RemoteKey: remoteKey, ValueDigest: command.ValueDigest,
		IdempotencyKey: command.IdempotencyKey, RequestBinding: requestBinding, Sealed: sealed,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	eventID := "secret-sync-event-" + uuid.NewSHA1(secretSyncEventNamespace, []byte("queued\x00"+tenantID+"\x00"+jobID)).String()
	event, err := log.Append(ctx, events.Event{ID: eventID, Type: projections.EventSecretSyncQueued, TenantID: tenantID, Data: data})
	if err != nil {
		return err
	}
	if err := projections.New(st).Apply(ctx, event); err != nil {
		return err
	}
	stored, err := st.GetSecretSyncJob(ctx, tenantID, jobID)
	if err != nil {
		return err
	}
	if !store.SecretSyncCommandMatches(stored, command) {
		return fmt.Errorf("%w: secret-sync idempotency key already binds another authenticated command", store.ErrIdempotencyConflict)
	}
	return nil
}

// Deliver returns handled=false only for a destination outside this subsystem.
// A recognized but unconfigured/invalid destination is handled with an error so
// the outbox retains it for operator-visible retry instead of marking it done.
func (d *secretIntegrationOutboxDispatcher) Deliver(ctx context.Context, m orchestrator.Message) (handled bool, err error) {
	switch {
	case m.Destination == dynamicSecretIssueDestination:
		return true, d.issueDynamicSecret(ctx, m)
	case m.Destination == dynamicSecretRevokeDestination:
		return true, d.revokeDynamicSecret(ctx, m)
	case strings.HasPrefix(m.Destination, secretSyncDestinationPrefix):
		return true, d.deliverSecretSync(ctx, m)
	case strings.HasPrefix(m.Destination, "dynsecret.") || strings.HasPrefix(m.Destination, "secret.sync"):
		return true, fmt.Errorf("server: unsupported first-party secret integration outbox destination %q", m.Destination)
	default:
		return false, nil
	}
}

// DeliverTerminalFailure projects the terminal state for a secret integration
// before the generic outbox marks its row failed. It deliberately records a
// closed-set message rather than cause.Error(): an upstream may echo a credential
// in its response body, and neither the event log nor PostgreSQL may retain that
// text (AN-8).
func (d *secretIntegrationOutboxDispatcher) DeliverTerminalFailure(ctx context.Context, m orchestrator.Message, _ error) (handled bool, err error) {
	const terminal = "external delivery exhausted its retry budget"
	switch {
	case m.Destination == dynamicSecretIssueDestination:
		var command projections.DynamicSecretIssueCommand
		if err := json.Unmarshal(m.Payload, &command); err != nil || command.ID == "" {
			return true, errors.New("server: terminal dynamic-secret issuance payload is invalid")
		}
		if d.store != nil {
			record, err := d.store.GetDynamicSecretLease(ctx, m.TenantID, command.ID)
			if err != nil {
				return true, err
			}
			if m.IdempotencyKey != "dynsecret.issue:"+command.ID || record.IssueOutboxID != m.ID || record.IdempotencyKey != command.IdempotencyKey || record.RequestBinding != command.RequestBinding || record.Provider != command.Provider || record.Role != command.Role || !dynamicSecretPersistedTimeEqual(record.ExpiresAt, command.ExpiresAt) || !dynamicSecretPersistedTimeEqual(record.HardExpiresAt, command.HardExpiresAt) {
				return true, errors.New("server: terminal dynamic-secret issuance does not match its projected command")
			}
			if record.State != store.DynamicSecretLeasePending {
				return true, nil
			}
		}
		return true, d.appendAndProjectID(ctx, dynamicSecretEventID(m.TenantID, "provider-issue-failed", command.ID), m.TenantID, projections.EventDynamicSecretLeaseIssuanceFailed,
			projections.DynamicSecretLeaseFailure{ID: command.ID, Error: terminal})
	case m.Destination == dynamicSecretRevokeDestination:
		var item dynsecret.RevokeItem
		if err := json.Unmarshal(m.Payload, &item); err != nil || item.LeaseID == "" {
			return true, errors.New("server: terminal dynamic-secret revocation payload is invalid")
		}
		if d.store != nil {
			record, err := d.store.GetDynamicSecretLease(ctx, m.TenantID, item.LeaseID)
			if err != nil {
				return true, err
			}
			if m.IdempotencyKey != "dynsecret.revoke:"+item.LeaseID || record.RevokeOutboxID == nil || *record.RevokeOutboxID != m.ID || record.Provider != item.Provider || record.BackendRef != item.BackendRef || record.State != store.DynamicSecretLeaseRevoked {
				return true, errors.New("server: terminal dynamic-secret revocation does not match its projected command")
			}
			if record.RevocationStatus != store.DynamicSecretRevocationPending {
				return true, nil
			}
		}
		return true, d.appendAndProjectID(ctx, dynamicSecretEventID(m.TenantID, "provider-revocation-failed", item.LeaseID), m.TenantID, projections.EventDynamicSecretLeaseRevocationFailed,
			projections.DynamicSecretLeaseFailure{ID: item.LeaseID, Error: terminal})
	case strings.HasPrefix(m.Destination, secretSyncDestinationPrefix):
		var payload secretSyncOutboxPayload
		if err := json.Unmarshal(m.Payload, &payload); err != nil || payload.ID == "" {
			return true, errors.New("server: terminal secret-sync payload is invalid")
		}
		if d.store != nil {
			record, err := d.store.GetSecretSyncJob(ctx, m.TenantID, payload.ID)
			if err != nil {
				return true, err
			}
			targetID := strings.TrimPrefix(m.Destination, secretSyncDestinationPrefix)
			if record.OutboxID != m.ID || record.IdempotencyKey != m.IdempotencyKey || record.Target != targetID || record.RemoteKey != payload.Key || record.RequestBinding != payload.RequestBinding || payload.Target != targetID {
				return true, errors.New("server: terminal secret-sync failure does not match its projected command")
			}
			if record.Status != store.SecretSyncJobPending {
				return true, nil
			}
		}
		return true, d.appendAndProjectID(ctx, "secret-sync-failed-"+uuid.NewSHA1(secretSyncEventNamespace, []byte(m.TenantID+"\x00"+payload.ID)).String(), m.TenantID, projections.EventSecretSyncFailed,
			projections.SecretSyncFailed{ID: payload.ID, Attempts: m.Attempts, Error: terminal})
	default:
		return false, nil
	}
}

// issueDynamicSecret is the only production path allowed to call Provider.Generate.
// The request handler projects this command first, and worker retries always reuse
// the deterministic lease id as the provider idempotency identity.
func (d *secretIntegrationOutboxDispatcher) issueDynamicSecret(ctx context.Context, m orchestrator.Message) error {
	if d.kek == nil || d.store == nil || d.log == nil {
		return errors.New("server: dynamic-secret issuance requires KEK, store, and event log")
	}
	var command projections.DynamicSecretIssueCommand
	if err := json.Unmarshal(m.Payload, &command); err != nil {
		return fmt.Errorf("server: decode dynamic-secret issuance: %w", err)
	}
	if command.ID == "" || command.IdempotencyKey == "" || command.Provider == "" || command.Role == "" || command.ExpiresAt.IsZero() || command.HardExpiresAt.IsZero() {
		return errors.New("server: dynamic-secret issuance payload is incomplete")
	}
	if m.IdempotencyKey != "dynsecret.issue:"+command.ID {
		return errors.New("server: dynamic-secret issuance outbox identity is mismatched")
	}
	record, err := d.store.GetDynamicSecretLease(ctx, m.TenantID, command.ID)
	if err != nil {
		return err
	}
	if record.IdempotencyKey != command.IdempotencyKey || record.RequestBinding != command.RequestBinding || record.Provider != command.Provider || record.Role != command.Role || !dynamicSecretPersistedTimeEqual(record.ExpiresAt, command.ExpiresAt) || !dynamicSecretPersistedTimeEqual(record.HardExpiresAt, command.HardExpiresAt) {
		return errors.New("server: dynamic-secret issuance command does not match its pending lease")
	}
	switch record.State {
	case store.DynamicSecretLeaseActive:
		if record.BackendRef == "" || len(record.SealedCredential) == 0 {
			return errors.New("server: active dynamic-secret lease has no sealed result")
		}
		return nil // outbox-finalization retry; never call the provider again.
	case store.DynamicSecretLeaseFailed, store.DynamicSecretLeaseRevoked:
		return nil
	case store.DynamicSecretLeasePending:
	default:
		return fmt.Errorf("server: unsupported dynamic-secret lease state %q", record.State)
	}
	nativeTTL := time.Until(record.HardExpiresAt)
	if nativeTTL <= 0 {
		return d.appendAndProject(ctx, m.TenantID, projections.EventDynamicSecretLeaseIssuanceFailed, projections.DynamicSecretLeaseFailure{
			ID: record.ID, Error: "provider credential validity window elapsed before issuance",
		})
	}
	var provider dynsecret.Provider
	for _, candidate := range d.dynamicProviders.ForTenant(m.TenantID) {
		if candidate.Name() == command.Provider {
			provider = candidate
			break
		}
	}
	if provider == nil {
		return fmt.Errorf("server: dynamic-secret provider %q is not configured for tenant", command.Provider)
	}
	request := dynsecret.GenerateRequest{Role: command.Role, TTL: nativeTTL, LeaseID: command.ID}
	var credential dynsecret.Credential
	if preparedProvider, ok := provider.(dynsecret.PreparedProvider); ok {
		sealedPreparation := record.SealedPreparation
		if len(sealedPreparation) == 0 {
			// Compatibility with pending intents written before preparation moved
			// wholly into the worker.
			sealedPreparation = command.SealedPreparation
		}
		if len(sealedPreparation) == 0 {
			prepared, prepareErr := preparedProvider.Prepare(ctx, request)
			if prepareErr != nil {
				return fmt.Errorf("server: prepare dynamic-secret identity in outbox worker: %w", prepareErr)
			}
			if len(prepared) == 0 {
				return errors.New("server: prepared dynamic-secret provider returned empty retry identity")
			}
			preparedLocked, lockErr := secret.NewFrom(prepared)
			secret.Wipe(prepared)
			if lockErr != nil {
				return fmt.Errorf("server: lock dynamic-secret preparation: %w", lockErr)
			}
			sealedPreparation, err = seal.Seal(d.kek, preparedLocked.Bytes(), dynamicSecretPreparationAAD(m.TenantID, command.ID, command.Provider))
			preparedLocked.Destroy()
			if err != nil {
				return fmt.Errorf("server: seal dynamic-secret preparation: %w", err)
			}
			if err := d.appendAndProject(ctx, m.TenantID, projections.EventDynamicSecretLeasePrepared, projections.DynamicSecretLeasePrepared{
				ID: command.ID, Provider: command.Provider, SealedPreparation: sealedPreparation,
			}); err != nil {
				return fmt.Errorf("server: persist dynamic-secret preparation before provider call: %w", err)
			}
		}
		var preparedLocked *secret.Buffer
		if len(sealedPreparation) > 0 {
			prepared, openErr := seal.Open(d.kek, sealedPreparation, dynamicSecretPreparationAAD(m.TenantID, command.ID, command.Provider))
			if openErr != nil {
				return fmt.Errorf("server: open dynamic-secret preparation: %w", openErr)
			}
			preparedLocked, err = secret.NewFrom(prepared)
			secret.Wipe(prepared)
			if err != nil {
				return fmt.Errorf("server: lock dynamic-secret preparation: %w", err)
			}
			defer preparedLocked.Destroy()
		}
		var prepared []byte
		if preparedLocked != nil {
			prepared = preparedLocked.Bytes()
		}
		credential, err = preparedProvider.GeneratePrepared(ctx, request, prepared)
	} else {
		if len(command.SealedPreparation) > 0 || len(record.SealedPreparation) > 0 {
			return errors.New("server: dynamic-secret command carries preparation for an incompatible provider")
		}
		credential, err = provider.Generate(ctx, request)
	}
	if err != nil {
		return fmt.Errorf("server: generate dynamic-secret lease %s with provider %s: %w", command.ID, command.Provider, err)
	}
	if credential.BackendRef == "" || len(credential.Secret) == 0 {
		secret.Wipe(credential.Secret)
		return errors.New("server: dynamic-secret provider returned an incomplete credential")
	}
	locked, err := secret.NewFrom(credential.Secret)
	secret.Wipe(credential.Secret)
	credential.Secret = nil
	if err != nil {
		return fmt.Errorf("server: lock generated dynamic-secret credential: %w", err)
	}
	defer locked.Destroy()
	sealedCredential, err := seal.Seal(d.kek, locked.Bytes(), dynamicSecretCredentialAAD(m.TenantID, command.ID, command.Provider))
	if err != nil {
		return fmt.Errorf("server: seal dynamic-secret credential result: %w", err)
	}
	return d.appendAndProject(ctx, m.TenantID, projections.EventDynamicSecretLeaseIssued, projections.DynamicSecretLeaseIssued{
		ID: command.ID, IdempotencyKey: command.IdempotencyKey, RequestBinding: command.RequestBinding, Provider: command.Provider,
		Role: command.Role, BackendRef: credential.BackendRef, SealedCredential: sealedCredential,
		ExpiresAt: command.ExpiresAt, HardExpiresAt: command.HardExpiresAt,
	})
}

// PostgreSQL timestamptz persists microseconds, while an immutable event/outbox
// JSON timestamp may carry nanoseconds. Bind against the exact persisted value:
// sub-microsecond bits cannot survive the read model, but a difference of one
// persisted microsecond still fails closed.
func dynamicSecretPersistedTimeEqual(persisted, command time.Time) bool {
	return persisted.UTC().Truncate(time.Microsecond).Equal(command.UTC().Truncate(time.Microsecond))
}

func (d *secretIntegrationOutboxDispatcher) revokeDynamicSecret(ctx context.Context, m orchestrator.Message) error {
	if (d.store == nil) != (d.log == nil) {
		return errors.New("server: dynamic-secret revocation requires store and event log together")
	}
	var item dynsecret.RevokeItem
	if err := json.Unmarshal(m.Payload, &item); err != nil {
		return fmt.Errorf("server: decode dynamic-secret revocation: %w", err)
	}
	if item.LeaseID == "" || item.Provider == "" || item.BackendRef == "" {
		return errors.New("server: dynamic-secret revocation payload is incomplete")
	}
	if d.store != nil {
		if m.IdempotencyKey != "dynsecret.revoke:"+item.LeaseID {
			return errors.New("server: dynamic-secret revocation outbox identity is mismatched")
		}
		record, err := d.store.GetDynamicSecretLease(ctx, m.TenantID, item.LeaseID)
		if err != nil {
			return fmt.Errorf("server: load dynamic-secret revocation binding: %w", err)
		}
		if record.State != store.DynamicSecretLeaseRevoked || record.RevokeOutboxID == nil || *record.RevokeOutboxID != m.ID || record.Provider != item.Provider || record.BackendRef != item.BackendRef {
			return errors.New("server: dynamic-secret revocation outbox does not match its projected lease")
		}
		switch record.RevocationStatus {
		case store.DynamicSecretRevocationCompleted:
			return nil
		case store.DynamicSecretRevocationFailed:
			return errors.New("server: refusing provider call for failed dynamic-secret revocation")
		case store.DynamicSecretRevocationPending:
		default:
			return fmt.Errorf("server: dynamic-secret revocation has invalid projected status %q", record.RevocationStatus)
		}
	}
	for _, provider := range d.dynamicProviders.ForTenant(m.TenantID) {
		if provider.Name() == item.Provider {
			if err := provider.Revoke(ctx, item.BackendRef); err != nil {
				return fmt.Errorf("server: revoke dynamic-secret lease %s with provider %s: %w", item.LeaseID, item.Provider, err)
			}
			return d.appendAndProjectID(ctx, dynamicSecretEventID(m.TenantID, "provider-revocation-completed", m.IdempotencyKey), m.TenantID, projections.EventDynamicSecretLeaseRevocationCompleted, projections.DynamicSecretLeaseRevocationCompleted{ID: item.LeaseID})
		}
	}
	return fmt.Errorf("server: dynamic-secret provider %q is not configured for tenant", item.Provider)
}

func (d *secretIntegrationOutboxDispatcher) deliverSecretSync(ctx context.Context, m orchestrator.Message) error {
	if d.kek == nil {
		return errors.New("server: secret-sync delivery requires a KEK")
	}
	targetID := strings.TrimPrefix(m.Destination, secretSyncDestinationPrefix)
	if targetID == "" {
		return errors.New("server: secret-sync destination target is empty")
	}
	var payload secretSyncOutboxPayload
	if err := json.Unmarshal(m.Payload, &payload); err != nil {
		return fmt.Errorf("server: decode secret-sync delivery: %w", err)
	}
	if payload.ID == "" || payload.Key == "" || payload.Target != targetID || len(payload.Sealed) == 0 {
		return errors.New("server: secret-sync delivery payload is incomplete or target-mismatched")
	}
	var projected store.SecretSyncJob
	if d.store != nil {
		var loadErr error
		projected, loadErr = d.store.GetSecretSyncJob(ctx, m.TenantID, payload.ID)
		if loadErr != nil {
			return fmt.Errorf("server: load secret-sync command binding: %w", loadErr)
		}
		if projected.OutboxID != m.ID || projected.Target != targetID || projected.RemoteKey != payload.Key || projected.IdempotencyKey != m.IdempotencyKey || projected.RequestBinding != payload.RequestBinding {
			return errors.New("server: secret-sync outbox does not match its projected command")
		}
		switch projected.Status {
		case store.SecretSyncJobDelivered:
			return nil
		case store.SecretSyncJobFailed:
			return errors.New("server: refusing external delivery for failed secret-sync job")
		case store.SecretSyncJobPending:
		default:
			return fmt.Errorf("server: secret-sync job has invalid projected status %q", projected.Status)
		}
	}
	target := d.syncTargets.ForTenant(m.TenantID)[targetID]
	if target == nil {
		return fmt.Errorf("server: secret-sync target %q is not configured for tenant", targetID)
	}
	value, err := seal.Open(d.kek, payload.Sealed, secretSyncAAD(m.TenantID, targetID, payload.ID, payload.Key))
	if err != nil {
		return fmt.Errorf("server: open secret-sync delivery: %w", err)
	}
	if d.store != nil && crypto.SHA256Hex(value) != projected.ValueDigest {
		secret.Wipe(value)
		return errors.New("server: secret-sync sealed payload digest does not match its projected command")
	}
	locked, err := secret.NewFrom(value)
	secret.Wipe(value)
	if err != nil {
		return fmt.Errorf("server: lock secret-sync delivery value: %w", err)
	}
	defer locked.Destroy()
	if err := target.DeliverOperation(ctx, payload.ID, payload.Key, locked.Bytes()); err != nil {
		return fmt.Errorf("server: deliver secret-sync job %s to %s: %w", payload.ID, targetID, err)
	}
	if d.afterSecretSyncDelivery != nil {
		if err := d.afterSecretSyncDelivery(ctx, payload); err != nil {
			return err
		}
	}
	attempts := m.Attempts
	if attempts < 1 {
		attempts = 1
	}
	return d.appendAndProjectID(ctx, "secret-sync-delivered-"+uuid.NewSHA1(secretSyncEventNamespace, []byte(m.TenantID+"\x00"+payload.ID)).String(), m.TenantID, projections.EventSecretSyncDelivered, projections.SecretSyncDelivered{ID: payload.ID, Attempts: attempts})
}

func (d *secretIntegrationOutboxDispatcher) appendAndProject(ctx context.Context, tenantID, eventType string, payload any) error {
	return d.appendAndProjectID(ctx, "", tenantID, eventType, payload)
}

func (d *secretIntegrationOutboxDispatcher) appendAndProjectID(ctx context.Context, eventID, tenantID, eventType string, payload any) error {
	if d.store == nil && d.log == nil {
		return nil // narrow embed/test compatibility; production wires both.
	}
	if d.store == nil || d.log == nil {
		return errors.New("server: secret integration delivery evidence requires store and event log")
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event, err := d.log.Append(ctx, events.Event{ID: eventID, Type: eventType, TenantID: tenantID, Data: data})
	if err != nil {
		return err
	}
	return projections.New(d.store).Apply(ctx, event)
}
