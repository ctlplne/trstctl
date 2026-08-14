// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/cloudauth"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/secretsync"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

// secretIntegrationOutboxDispatcher owns the first-party dynsecret.* and
// secret.sync.* destinations. Keeping this routing explicit prevents the generic
// dispatcher fallback from acknowledging an unknown secret side effect as though
// it had been delivered.
type secretIntegrationOutboxDispatcher struct {
	dynamicProviders         DynamicSecretProviderRegistry
	fallbackDynamicProviders []dynsecret.Provider
	syncTargets              SecretSyncTargetRegistry
	fallbackSyncTargets      map[string]*secretsync.Target
	kek                      seal.KeyWrapper
	tenantCrypto             tenantseal.Access
	store                    *store.Store
	log                      *events.Log

	// Test-only crash seam. Runtime proof uses it to interrupt the worker after a
	// version-creating receiver commits but before the delivered event/outbox ACK.
	// Production leaves it nil.
	afterSecretSyncDelivery func(context.Context, secretSyncOutboxPayload) error
	// Test-only scheduling seam immediately before the command-global receiver
	// authority lock. It lets a terminal append race an older generation that
	// already performed every earlier history check but has not started receiver I/O.
	beforeSecretSyncReceiverAuthority func(context.Context, secretSyncOutboxPayload) error
	// Test-only crash seam after durable failure authority commits but before its
	// deterministic event append. Production leaves it nil.
	afterSecretSyncFailureAuthority func(context.Context, store.SecretSyncReceiverAuthority) error
	// Test-only crash seam after the canonical event append and before projection.
	// It proves recovery reuses retained history after broker dedupe expiry.
	afterCanonicalAppend func(events.Event) error
	// Test-only diagnostic seam. Runtime proof reduces the live provider error to
	// a closed non-secret class in memory; production leaves it nil and durable
	// outbox errors remain the closed AN-8-safe values below.
	afterDynamicSecretDelivery func(error)
}

func queueSecretSyncEvent(ctx context.Context, st *store.Store, log *events.Log, kek seal.KeyWrapper, tenantID, secretName string, secretVersion int, target, remoteKey, idempotencyKey, requestBinding string, value []byte, tenantCrypto tenantseal.Access) error {
	if st == nil || log == nil || kek == nil {
		return errors.New("server: durable secret sync requires store, event log, and KEK")
	}
	if tenantID == "" || secretName == "" || secretVersion <= 0 || target == "" || remoteKey == "" || idempotencyKey == "" || requestBinding == "" {
		return errors.New("server: durable secret sync command is incomplete")
	}
	tenantEpoch, err := st.ApplicationSecretTenantEpoch(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("server: resolve secret-sync tenant lifecycle epoch: %w", err)
	}
	jobID := store.DurableSecretSyncJobIDForEpoch(tenantID, tenantEpoch, idempotencyKey)
	command := store.SecretSyncJob{
		ID: jobID, TenantID: tenantID, TenantEpoch: tenantEpoch,
		SecretName: secretName, SecretVersion: int64(secretVersion),
		Target: target, RemoteKey: remoteKey, ValueDigest: crypto.SHA256Hex(value),
		IdempotencyKey: store.SecretSyncOutboxIdempotencyKey(target, jobID), RequestBinding: requestBinding,
	}
	if existing, err := st.GetSecretSyncJob(ctx, tenantID, jobID); err == nil {
		if !store.SecretSyncCommandMatches(existing, command) {
			return fmt.Errorf("%w: secret-sync idempotency key already binds another authenticated command", store.ErrIdempotencyConflict)
		}
	} else if !store.IsNotFound(err) {
		return err
	}
	eventID := store.SecretSyncQueuedEventID(tenantID, jobID)
	event, found, err := log.EventByID(ctx, eventID)
	if err != nil {
		return err
	}
	if !found {
		sealed, sealErr := sealTenantValue(ctx, tenantCrypto, kek, tenantID, value, secretSyncAAD(tenantID, target, jobID, remoteKey))
		if sealErr != nil {
			return sealErr
		}
		payload := projections.SecretSyncQueued{
			TenantEpoch: tenantEpoch, ID: jobID, SecretName: secretName, SecretVersion: int64(secretVersion),
			Target: target, RemoteKey: remoteKey, ValueDigest: command.ValueDigest,
			IdempotencyKey: command.IdempotencyKey, RequestBinding: requestBinding, Sealed: sealed,
		}
		data, marshalErr := json.Marshal(payload)
		if marshalErr != nil {
			return marshalErr
		}
		event, err = log.Append(ctx, events.Event{
			ID: eventID, Type: projections.EventSecretSyncQueued, TenantID: tenantID,
			SchemaVersion: projections.SecretSyncEventSchemaVersion, Data: data,
		})
		if err != nil {
			return err
		}
	}
	if err := validateCanonicalSecretSyncQueued(ctx, event, command, value, kek, tenantCrypto); err != nil {
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

// validateCanonicalSecretSyncQueued treats retained event history as the permanent
// idempotency fence. Sealing is randomized, so a retry cannot compare freshly
// marshaled event bytes after JetStream's finite duplicate window. It instead
// validates every stable command field, the authenticated actor, and the opened
// plaintext in constant time before reusing the canonical ciphertext/event.
func validateCanonicalSecretSyncQueued(ctx context.Context, event events.Event, command store.SecretSyncJob, value []byte, kek seal.KeyWrapper, tenantCrypto tenantseal.Access) error {
	var expectedActor *events.Actor
	if actor, ok := events.ActorFromContext(ctx); ok {
		expectedActor = &actor
	}
	if event.ID != store.SecretSyncQueuedEventID(command.TenantID, command.ID) ||
		event.Type != projections.EventSecretSyncQueued || event.TenantID != command.TenantID ||
		event.SchemaVersion != projections.SecretSyncEventSchemaVersion || event.Time.IsZero() ||
		!reflect.DeepEqual(event.Actor, expectedActor) {
		return fmt.Errorf("%w: canonical secret-sync queued event envelope differs", store.ErrIdempotencyConflict)
	}
	var payload projections.SecretSyncQueued
	if err := json.Unmarshal(event.Data, &payload); err != nil {
		return fmt.Errorf("%w: canonical secret-sync queued payload is invalid", store.ErrIdempotencyConflict)
	}
	if payload.TenantEpoch != command.TenantEpoch || payload.ID != command.ID || payload.SecretName != command.SecretName ||
		payload.SecretVersion != command.SecretVersion || payload.Target != command.Target ||
		payload.RemoteKey != command.RemoteKey || payload.ValueDigest != command.ValueDigest ||
		payload.IdempotencyKey != command.IdempotencyKey || payload.RequestBinding != command.RequestBinding || len(payload.Sealed) == 0 {
		return fmt.Errorf("%w: canonical secret-sync queued command differs", store.ErrIdempotencyConflict)
	}
	opened, err := openTenantValue(ctx, tenantCrypto, kek, command.TenantID, payload.Sealed,
		secretSyncAAD(command.TenantID, command.Target, command.ID, command.RemoteKey))
	if err != nil {
		return fmt.Errorf("%w: canonical secret-sync queued value cannot be opened", store.ErrIdempotencyConflict)
	}
	defer secret.Wipe(opened)
	if !crypto.ConstantTimeEqual(opened, value) {
		return fmt.Errorf("%w: canonical secret-sync queued value differs", store.ErrIdempotencyConflict)
	}
	return nil
}

// Deliver returns handled=false only for a destination outside this subsystem.
// A recognized but unconfigured/invalid destination is handled with an error so
// the outbox retains it for operator-visible retry instead of marking it done.
func (d *secretIntegrationOutboxDispatcher) Deliver(ctx context.Context, m orchestrator.Message) (handled bool, err error) {
	switch {
	case m.Destination == dynamicSecretIssueDestination:
		err := d.issueDynamicSecret(ctx, m)
		if d.afterDynamicSecretDelivery != nil {
			d.afterDynamicSecretDelivery(err)
		}
		return true, err
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

func (d *secretIntegrationOutboxDispatcher) dynamicProvidersForTenant(tenantID string) []dynsecret.Provider {
	if d.dynamicProviders != nil {
		return d.dynamicProviders.ForTenant(tenantID)
	}
	return append([]dynsecret.Provider(nil), d.fallbackDynamicProviders...)
}

// DeliverTerminalFailure projects the terminal state for a secret integration
// before the generic outbox marks its row failed. It deliberately records a
// closed-set message rather than cause.Error(): an upstream may echo a credential
// in its response body, and neither the event log nor PostgreSQL may retain that
// text (AN-8).
func (d *secretIntegrationOutboxDispatcher) DeliverTerminalFailure(ctx context.Context, m orchestrator.Message, cause error) (handled bool, err error) {
	const terminal = "external delivery exhausted its retry budget"
	switch {
	case m.Destination == dynamicSecretIssueDestination:
		var command projections.DynamicSecretIssueCommand
		if err := json.Unmarshal(m.Payload, &command); err != nil || command.TenantEpoch == "" || command.ID == "" {
			return true, errors.New("server: terminal dynamic-secret issuance payload is invalid")
		}
		if d.store == nil {
			return true, errors.New("server: terminal dynamic-secret issuance requires tenant epoch authority")
		}
		record, err := d.store.GetDynamicSecretLease(ctx, m.TenantID, command.ID)
		if err != nil {
			return true, err
		}
		if m.IdempotencyKey != store.DynamicSecretIssueOutboxIdempotencyKey(command.TenantEpoch, command.ID) ||
			record.TenantEpoch != command.TenantEpoch || record.IssueOutboxID != m.ID ||
			record.IdempotencyKey != command.IdempotencyKey || record.RequestBinding != command.RequestBinding ||
			record.Provider != command.Provider || record.Role != command.Role ||
			!dynamicSecretPersistedTimeEqual(record.ExpiresAt, command.ExpiresAt) ||
			!dynamicSecretPersistedTimeEqual(record.HardExpiresAt, command.HardExpiresAt) {
			return true, errors.New("server: terminal dynamic-secret issuance does not match its projected command")
		}
		if record.State != store.DynamicSecretLeasePending {
			return true, nil
		}
		return true, d.appendAndProjectID(ctx, dynamicSecretEventID(m.TenantID, command.TenantEpoch, "provider-issue-failed", command.ID), m.TenantID, projections.EventDynamicSecretLeaseIssuanceFailed,
			projections.DynamicSecretLeaseIssuanceFailure{TenantEpoch: record.TenantEpoch, ID: command.ID, Error: terminal})
	case m.Destination == dynamicSecretRevokeDestination:
		var item dynsecret.RevokeItem
		if err := json.Unmarshal(m.Payload, &item); err != nil || item.TenantEpoch == "" || item.LeaseID == "" {
			return true, errors.New("server: terminal dynamic-secret revocation payload is invalid")
		}
		if d.store == nil {
			return true, errors.New("server: terminal dynamic-secret revocation requires tenant epoch authority")
		}
		record, err := d.store.GetDynamicSecretLease(ctx, m.TenantID, item.LeaseID)
		if err != nil {
			return true, err
		}
		if m.IdempotencyKey != store.DynamicSecretRevokeOutboxIdempotencyKey(item.TenantEpoch, item.LeaseID) ||
			record.TenantEpoch != item.TenantEpoch || record.RevokeOutboxID == nil ||
			*record.RevokeOutboxID != m.ID || record.Provider != item.Provider ||
			record.BackendRef != item.BackendRef || record.State != store.DynamicSecretLeaseRevoked {
			return true, errors.New("server: terminal dynamic-secret revocation does not match its projected command")
		}
		if record.RevocationStatus != store.DynamicSecretRevocationPending {
			return true, nil
		}
		return true, d.appendAndProjectID(ctx, dynamicSecretEventID(m.TenantID, item.TenantEpoch, "provider-revocation-failed", item.LeaseID), m.TenantID, projections.EventDynamicSecretLeaseRevocationFailed,
			projections.DynamicSecretLeaseFailure{TenantEpoch: item.TenantEpoch, ID: item.LeaseID, Error: terminal})
	case strings.HasPrefix(m.Destination, secretSyncDestinationPrefix):
		var payload secretSyncOutboxPayload
		if err := json.Unmarshal(m.Payload, &payload); err != nil || payload.ID == "" || payload.Key == "" || payload.Target == "" || len(payload.Sealed) == 0 {
			return true, errors.New("server: terminal secret-sync payload is invalid")
		}
		if d.store == nil || d.log == nil {
			return true, errors.New("server: terminal secret-sync failure requires store and retained event history")
		}
		record, err := d.store.GetSecretSyncJob(ctx, m.TenantID, payload.ID)
		if err != nil {
			return true, err
		}
		targetID := strings.TrimPrefix(m.Destination, secretSyncDestinationPrefix)
		if record.OutboxID != m.ID || record.IdempotencyKey != m.IdempotencyKey || record.Target != targetID || record.RemoteKey != payload.Key || record.RequestBinding != payload.RequestBinding || payload.Target != targetID {
			return true, errors.New("server: terminal secret-sync failure does not match its projected command")
		}
		if !orchestrator.IsDefiniteNoEffect(cause) {
			if cause == nil {
				return true, errors.New("server: terminal secret-sync failure has no delivery cause")
			}
			return true, orchestrator.DeferDelivery(cause)
		}
		switch record.Status {
		case store.SecretSyncJobFailed:
			return true, nil
		case store.SecretSyncJobDelivered:
			// The generic finalizer still sees the current delivery error. Refund this
			// stale claim so a cleanup claim can observe delivered and ACK it.
			return true, orchestrator.DeferDelivery(cause)
		case store.SecretSyncJobPending:
		default:
			return true, fmt.Errorf("server: terminal secret-sync job has invalid projected status %q", record.Status)
		}
		if record.TargetOrder <= 0 {
			return true, errors.New("server: migration-derived secret-sync command cannot be terminalized by a new worker")
		}
		if err := validateProjectedSecretSyncSource(ctx, d.log, record, payload); err != nil {
			return true, err
		}
		if m.Attempts < 1 {
			return true, errors.New("server: terminal secret-sync failure requires a positive attempt count")
		}
		return true, d.terminalizeSecretSyncFailure(ctx, m, record, cause, terminal, 0, true)
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
	if command.TenantEpoch == "" || command.ID == "" || command.IdempotencyKey == "" || command.Provider == "" || command.Role == "" || command.ExpiresAt.IsZero() || command.HardExpiresAt.IsZero() {
		return errors.New("server: dynamic-secret issuance payload is incomplete")
	}
	if m.IdempotencyKey != store.DynamicSecretIssueOutboxIdempotencyKey(command.TenantEpoch, command.ID) {
		return errors.New("server: dynamic-secret issuance outbox identity is mismatched")
	}
	record, err := d.store.GetDynamicSecretLease(ctx, m.TenantID, command.ID)
	if err != nil {
		return err
	}
	if record.TenantEpoch != command.TenantEpoch || record.IdempotencyKey != command.IdempotencyKey ||
		record.RequestBinding != command.RequestBinding || record.Provider != command.Provider ||
		record.Role != command.Role || !dynamicSecretPersistedTimeEqual(record.ExpiresAt, command.ExpiresAt) ||
		!dynamicSecretPersistedTimeEqual(record.HardExpiresAt, command.HardExpiresAt) {
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
	issuedEventID := dynamicSecretEventID(m.TenantID, command.TenantEpoch, "provider-issued", command.ID)
	if recovered, recoverErr := d.recoverDynamicSecretIssued(ctx, issuedEventID, m.TenantID, command); recoverErr != nil {
		return recoverErr
	} else if recovered {
		return nil
	}
	nativeTTL := time.Until(record.HardExpiresAt)
	if nativeTTL <= 0 {
		return d.appendAndProjectID(ctx, dynamicSecretEventID(m.TenantID, command.TenantEpoch, "provider-issue-failed", command.ID), m.TenantID, projections.EventDynamicSecretLeaseIssuanceFailed, projections.DynamicSecretLeaseIssuanceFailure{
			TenantEpoch: record.TenantEpoch, ID: record.ID,
			Error: "provider credential validity window elapsed before issuance",
		})
	}
	var provider dynsecret.Provider
	for _, candidate := range d.dynamicProvidersForTenant(m.TenantID) {
		if candidate.Name() == command.Provider {
			provider = candidate
			break
		}
	}
	if provider == nil {
		return fmt.Errorf("server: dynamic-secret provider %q is not configured for tenant", command.Provider)
	}
	request := dynsecret.GenerateRequest{Role: command.Role, TTL: nativeTTL, LeaseID: command.ID}
	credential, err := d.generateDynamicSecretCredential(ctx, m, command, record, provider, request)
	if err != nil {
		return err
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
	sealedCredential, err := sealTenantValue(ctx, d.tenantCrypto, d.kek, m.TenantID, locked.Bytes(), dynamicSecretCredentialAAD(m.TenantID, command.ID, command.Provider))
	if err != nil {
		return fmt.Errorf("server: seal dynamic-secret credential result: %w", err)
	}
	return d.appendAndProjectID(ctx, issuedEventID, m.TenantID, projections.EventDynamicSecretLeaseIssued, projections.DynamicSecretLeaseIssued{
		TenantEpoch: command.TenantEpoch, ID: command.ID, IdempotencyKey: command.IdempotencyKey,
		RequestBinding: command.RequestBinding, Provider: command.Provider,
		Role: command.Role, BackendRef: credential.BackendRef, SealedCredential: sealedCredential,
		ExpiresAt: command.ExpiresAt, HardExpiresAt: command.HardExpiresAt,
	})
}

// generateDynamicSecretCredential owns the provider preparation state machine.
// Immutable preparation evidence is recovered or projected before the external
// provider call, and plaintext retry identity stays in locked memory only while
// GeneratePrepared is executing.
func (d *secretIntegrationOutboxDispatcher) generateDynamicSecretCredential(
	ctx context.Context,
	m orchestrator.Message,
	command projections.DynamicSecretIssueCommand,
	record store.DynamicSecretLease,
	provider dynsecret.Provider,
	request dynsecret.GenerateRequest,
) (dynsecret.Credential, error) {
	preparedProvider, preparedCapable := provider.(dynsecret.PreparedProvider)
	if !preparedCapable {
		if len(command.SealedPreparation) > 0 || len(record.SealedPreparation) > 0 {
			return dynsecret.Credential{}, errors.New("server: dynamic-secret command carries preparation for an incompatible provider")
		}
		credential, err := provider.Generate(ctx, request)
		if err != nil {
			return dynsecret.Credential{}, fmt.Errorf("server: generate dynamic-secret lease %s with provider %s: %w", command.ID, command.Provider, err)
		}
		return credential, nil
	}
	preparedEventID := dynamicSecretEventID(m.TenantID, command.TenantEpoch, "provider-prepared", command.ID)
	// Read immutable preparation evidence before either Prepare or
	// GeneratePrepared can touch the provider. SQL can lag the event log after a
	// crash, including when an older row still carries preparation ciphertext.
	recoveredPreparation, err := d.recoverDynamicSecretPrepared(ctx, preparedEventID, m.TenantID, command)
	if err != nil {
		return dynsecret.Credential{}, err
	}
	sealedPreparation := record.SealedPreparation
	if len(sealedPreparation) > 0 && len(command.SealedPreparation) > 0 &&
		!bytes.Equal(sealedPreparation, command.SealedPreparation) {
		return dynsecret.Credential{}, fmt.Errorf("%w: projected and queued dynamic-secret preparations differ", store.ErrIdempotencyConflict)
	}
	if len(sealedPreparation) == 0 {
		// Compatibility with pending intents written before preparation moved
		// wholly into the worker.
		sealedPreparation = command.SealedPreparation
	}
	if recoveredPreparation {
		record, err = d.store.GetDynamicSecretLease(ctx, m.TenantID, command.ID)
		if err != nil {
			return dynsecret.Credential{}, fmt.Errorf("server: reload recovered dynamic-secret preparation: %w", err)
		}
		if record.TenantEpoch != command.TenantEpoch || record.State != store.DynamicSecretLeasePending ||
			len(record.SealedPreparation) == 0 {
			return dynsecret.Credential{}, errors.New("server: recovered dynamic-secret preparation lost its pending command binding")
		}
		if len(sealedPreparation) > 0 && !bytes.Equal(sealedPreparation, record.SealedPreparation) {
			return dynsecret.Credential{}, fmt.Errorf("%w: retained and projected dynamic-secret preparations differ", store.ErrIdempotencyConflict)
		}
		sealedPreparation = record.SealedPreparation
	}
	if len(sealedPreparation) == 0 {
		prepared, prepareErr := preparedProvider.Prepare(ctx, request)
		if prepareErr != nil {
			return dynsecret.Credential{}, fmt.Errorf("server: prepare dynamic-secret identity in outbox worker: %w", prepareErr)
		}
		if len(prepared) == 0 {
			return dynsecret.Credential{}, errors.New("server: prepared dynamic-secret provider returned empty retry identity")
		}
		preparedLocked, lockErr := secret.NewFrom(prepared)
		secret.Wipe(prepared)
		if lockErr != nil {
			return dynsecret.Credential{}, fmt.Errorf("server: lock dynamic-secret preparation: %w", lockErr)
		}
		sealedPreparation, err = sealTenantValue(ctx, d.tenantCrypto, d.kek, m.TenantID, preparedLocked.Bytes(), dynamicSecretPreparationAAD(m.TenantID, command.ID, command.Provider))
		preparedLocked.Destroy()
		if err != nil {
			return dynsecret.Credential{}, fmt.Errorf("server: seal dynamic-secret preparation: %w", err)
		}
		if err := d.appendAndProjectID(ctx, preparedEventID, m.TenantID, projections.EventDynamicSecretLeasePrepared, projections.DynamicSecretLeasePrepared{
			TenantEpoch: command.TenantEpoch, ID: command.ID,
			Provider: command.Provider, SealedPreparation: sealedPreparation,
		}); err != nil {
			return dynsecret.Credential{}, fmt.Errorf("server: persist dynamic-secret preparation before provider call: %w", err)
		}
		record, err = d.store.GetDynamicSecretLease(ctx, m.TenantID, command.ID)
		if err != nil {
			return dynsecret.Credential{}, fmt.Errorf("server: reload canonical dynamic-secret preparation: %w", err)
		}
		if record.TenantEpoch != command.TenantEpoch || record.State != store.DynamicSecretLeasePending ||
			!bytes.Equal(record.SealedPreparation, sealedPreparation) {
			return dynsecret.Credential{}, fmt.Errorf("%w: projected dynamic-secret preparation differs from canonical event", store.ErrIdempotencyConflict)
		}
		sealedPreparation = record.SealedPreparation
	}
	if len(sealedPreparation) == 0 {
		return dynsecret.Credential{}, errors.New("server: canonical dynamic-secret preparation is empty")
	}
	prepared, err := openTenantValue(ctx, d.tenantCrypto, d.kek, m.TenantID, sealedPreparation,
		dynamicSecretPreparationAAD(m.TenantID, command.ID, command.Provider))
	if err != nil {
		return dynsecret.Credential{}, fmt.Errorf("server: open dynamic-secret preparation: %w", err)
	}
	preparedLocked, err := secret.NewFrom(prepared)
	secret.Wipe(prepared)
	if err != nil {
		return dynsecret.Credential{}, fmt.Errorf("server: lock dynamic-secret preparation: %w", err)
	}
	defer preparedLocked.Destroy()
	credential, err := preparedProvider.GeneratePrepared(ctx, request, preparedLocked.Bytes())
	if err != nil {
		return dynsecret.Credential{}, fmt.Errorf("server: generate dynamic-secret lease %s with provider %s: %w", command.ID, command.Provider, err)
	}
	return credential, nil
}

func (d *secretIntegrationOutboxDispatcher) recoverDynamicSecretIssued(ctx context.Context, eventID, tenantID string, command projections.DynamicSecretIssueCommand) (bool, error) {
	canonical, found, err := d.log.EventByID(ctx, eventID)
	if err != nil || !found {
		return found, err
	}
	var expectedActor *events.Actor
	if actor, ok := events.ActorFromContext(ctx); ok {
		expectedActor = &actor
	}
	if canonical.ID != eventID || canonical.Type != projections.EventDynamicSecretLeaseIssued ||
		canonical.TenantID != tenantID || canonical.SchemaVersion != projections.DynamicSecretEventSchemaVersion ||
		canonical.Time.IsZero() || !reflect.DeepEqual(canonical.Actor, expectedActor) {
		return true, fmt.Errorf("%w: canonical dynamic-secret issued event envelope differs", store.ErrIdempotencyConflict)
	}
	var issued projections.DynamicSecretLeaseIssued
	if err := json.Unmarshal(canonical.Data, &issued); err != nil ||
		issued.TenantEpoch != command.TenantEpoch || issued.ID != command.ID ||
		issued.IdempotencyKey != command.IdempotencyKey || issued.RequestBinding != command.RequestBinding ||
		issued.Provider != command.Provider || issued.Role != command.Role || issued.BackendRef == "" ||
		len(issued.SealedCredential) == 0 || !dynamicSecretPersistedTimeEqual(issued.ExpiresAt, command.ExpiresAt) ||
		!dynamicSecretPersistedTimeEqual(issued.HardExpiresAt, command.HardExpiresAt) {
		return true, fmt.Errorf("%w: canonical dynamic-secret issued command differs", store.ErrIdempotencyConflict)
	}
	opened, err := openTenantValue(ctx, d.tenantCrypto, d.kek, tenantID, issued.SealedCredential,
		dynamicSecretCredentialAAD(tenantID, issued.ID, issued.Provider))
	if err != nil || len(opened) == 0 {
		secret.Wipe(opened)
		return true, fmt.Errorf("%w: canonical dynamic-secret issued credential is invalid", store.ErrIdempotencyConflict)
	}
	secret.Wipe(opened)
	if d.afterCanonicalAppend != nil {
		if err := d.afterCanonicalAppend(canonical); err != nil {
			return true, err
		}
	}
	return true, projections.New(d.store).Apply(ctx, canonical)
}

// recoverDynamicSecretPrepared projects retained worker-created preparation
// before Prepare can run again. The ciphertext is opened only to prove it is a
// usable nonempty value bound to the exact tenant/lease/provider AAD; plaintext
// is wiped immediately and never enters retained history.
func (d *secretIntegrationOutboxDispatcher) recoverDynamicSecretPrepared(ctx context.Context, eventID, tenantID string, command projections.DynamicSecretIssueCommand) (bool, error) {
	canonical, found, err := d.log.EventByID(ctx, eventID)
	if err != nil || !found {
		return found, err
	}
	var expectedActor *events.Actor
	if actor, ok := events.ActorFromContext(ctx); ok {
		expectedActor = &actor
	}
	if canonical.ID != eventID || canonical.Type != projections.EventDynamicSecretLeasePrepared ||
		canonical.TenantID != tenantID || canonical.SchemaVersion != projections.DynamicSecretEventSchemaVersion ||
		canonical.Time.IsZero() || !reflect.DeepEqual(canonical.Actor, expectedActor) {
		return true, fmt.Errorf("%w: canonical dynamic-secret prepared event envelope differs", store.ErrIdempotencyConflict)
	}
	var prepared projections.DynamicSecretLeasePrepared
	if err := json.Unmarshal(canonical.Data, &prepared); err != nil ||
		prepared.TenantEpoch != command.TenantEpoch || prepared.ID != command.ID ||
		prepared.Provider != command.Provider || len(prepared.SealedPreparation) == 0 {
		return true, fmt.Errorf("%w: canonical dynamic-secret prepared command differs", store.ErrIdempotencyConflict)
	}
	opened, err := openTenantValue(ctx, d.tenantCrypto, d.kek, tenantID,
		prepared.SealedPreparation,
		dynamicSecretPreparationAAD(tenantID, prepared.ID, prepared.Provider))
	if err != nil || len(opened) == 0 {
		secret.Wipe(opened)
		return true, fmt.Errorf("%w: canonical dynamic-secret preparation is invalid", store.ErrIdempotencyConflict)
	}
	secret.Wipe(opened)
	if d.afterCanonicalAppend != nil {
		if err := d.afterCanonicalAppend(canonical); err != nil {
			return true, err
		}
	}
	return true, projections.New(d.store).Apply(ctx, canonical)
}

// PostgreSQL timestamptz persists microseconds, while an immutable event/outbox
// JSON timestamp may carry nanoseconds. Bind against the exact persisted value:
// sub-microsecond bits cannot survive the read model, but a difference of one
// persisted microsecond still fails closed.
func dynamicSecretPersistedTimeEqual(persisted, command time.Time) bool {
	return persisted.UTC().Truncate(time.Microsecond).Equal(command.UTC().Truncate(time.Microsecond))
}

func (d *secretIntegrationOutboxDispatcher) revokeDynamicSecret(ctx context.Context, m orchestrator.Message) error {
	if d.store == nil || d.log == nil {
		return errors.New("server: dynamic-secret revocation requires store, event log, and tenant epoch authority")
	}
	var item dynsecret.RevokeItem
	if err := json.Unmarshal(m.Payload, &item); err != nil {
		return fmt.Errorf("server: decode dynamic-secret revocation: %w", err)
	}
	if item.TenantEpoch == "" || item.LeaseID == "" || item.Provider == "" || item.BackendRef == "" {
		return errors.New("server: dynamic-secret revocation payload is incomplete")
	}
	if m.IdempotencyKey != store.DynamicSecretRevokeOutboxIdempotencyKey(item.TenantEpoch, item.LeaseID) {
		return errors.New("server: dynamic-secret revocation outbox identity is mismatched")
	}
	record, err := d.store.GetDynamicSecretLease(ctx, m.TenantID, item.LeaseID)
	if err != nil {
		return fmt.Errorf("server: load dynamic-secret revocation binding: %w", err)
	}
	if record.TenantEpoch != item.TenantEpoch || record.State != store.DynamicSecretLeaseRevoked ||
		record.RevokeOutboxID == nil || *record.RevokeOutboxID != m.ID ||
		record.Provider != item.Provider || record.BackendRef != item.BackendRef {
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
	completedEventID := dynamicSecretEventID(
		m.TenantID, item.TenantEpoch, "provider-revocation-completed", item.LeaseID)
	if _, found, err := d.log.EventByID(ctx, completedEventID); err != nil {
		return err
	} else if found {
		return d.appendAndProjectID(ctx, completedEventID, m.TenantID,
			projections.EventDynamicSecretLeaseRevocationCompleted,
			projections.DynamicSecretLeaseRevocationCompleted{
				TenantEpoch: item.TenantEpoch, ID: item.LeaseID,
			})
	}
	for _, provider := range d.dynamicProvidersForTenant(m.TenantID) {
		if provider.Name() == item.Provider {
			if err := provider.Revoke(ctx, item.BackendRef); err != nil {
				return fmt.Errorf("server: revoke dynamic-secret lease %s with provider %s: %w", item.LeaseID, item.Provider, err)
			}
			return d.appendAndProjectID(ctx, completedEventID, m.TenantID, projections.EventDynamicSecretLeaseRevocationCompleted, projections.DynamicSecretLeaseRevocationCompleted{
				TenantEpoch: item.TenantEpoch, ID: item.LeaseID,
			})
		}
	}
	return fmt.Errorf("server: dynamic-secret provider %q is not configured for tenant", item.Provider)
}

func (d *secretIntegrationOutboxDispatcher) deliverSecretSync(ctx context.Context, m orchestrator.Message) error {
	if d.kek == nil {
		return orchestrator.DefiniteNoEffect(errors.New("server: secret-sync delivery requires a KEK"))
	}
	targetID := strings.TrimPrefix(m.Destination, secretSyncDestinationPrefix)
	if targetID == "" {
		return orchestrator.DefiniteNoEffect(errors.New("server: secret-sync destination target is empty"))
	}
	var payload secretSyncOutboxPayload
	if err := json.Unmarshal(m.Payload, &payload); err != nil {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: decode secret-sync delivery: %w", err))
	}
	if payload.ID == "" || payload.Key == "" || payload.Target != targetID || len(payload.Sealed) == 0 {
		return orchestrator.DefiniteNoEffect(errors.New("server: secret-sync delivery payload is incomplete or target-mismatched"))
	}
	attempts := m.Attempts
	if attempts < 1 {
		attempts = 1
	}
	var projected store.SecretSyncJob
	if d.store != nil {
		var loadErr error
		projected, loadErr = d.store.GetSecretSyncJob(ctx, m.TenantID, payload.ID)
		if loadErr != nil {
			return fmt.Errorf("server: load secret-sync command binding: %w", loadErr)
		}
		if projected.OutboxID != m.ID || projected.Target != targetID || projected.RemoteKey != payload.Key || projected.IdempotencyKey != m.IdempotencyKey || projected.RequestBinding != payload.RequestBinding {
			return orchestrator.DefiniteNoEffect(errors.New("server: secret-sync outbox does not match its projected command"))
		}
		if projected.TargetOrder > 0 {
			if d.log == nil {
				return orchestrator.DefiniteNoEffect(errors.New("server: event-derived secret-sync delivery requires retained event history"))
			}
			if err := validateProjectedSecretSyncSource(ctx, d.log, projected, payload); err != nil {
				return orchestrator.DefiniteNoEffect(err)
			}
		} else if projected.Status == store.SecretSyncJobPending {
			return orchestrator.DefiniteNoEffect(errors.New("server: migration-derived secret-sync command cannot remain pending"))
		}
		switch projected.Status {
		case store.SecretSyncJobDelivered:
			return nil
		case store.SecretSyncJobFailed:
			// The terminal domain event is already canonical. A rebuilt/purged
			// outbox row is cleanup only: ACK it without target lookup, secret open,
			// retry budget, or circuit pollution.
			return nil
		case store.SecretSyncJobPending:
		default:
			return orchestrator.DefiniteNoEffect(fmt.Errorf("server: secret-sync job has invalid projected status %q", projected.Status))
		}
		deliveredID := store.SecretSyncDeliveredEventID(m.TenantID, payload.ID)
		failedID := store.SecretSyncFailedEventID(m.TenantID, payload.ID)
		deliveredEvent, deliveredFound, deliveredErr := d.log.EventByID(ctx, deliveredID)
		if deliveredErr != nil {
			return deliveredErr
		}
		failedEvent, failedFound, failedErr := d.log.EventByID(ctx, failedID)
		if failedErr != nil {
			return failedErr
		}
		if deliveredFound && failedFound {
			return fmt.Errorf("%w: retained secret-sync history contains both delivered and failed outcomes", store.ErrIdempotencyConflict)
		}
		if deliveredFound {
			return d.validateAndProjectSecretSyncEvidence(ctx, deliveredEvent, m.TenantID,
				projections.EventSecretSyncDelivered, projections.SecretSyncDelivered{
					ID: payload.ID, TenantEpoch: projected.TenantEpoch, Attempts: attempts,
				})
		}
		if failedFound {
			return d.validateAndProjectSecretSyncEvidence(ctx, failedEvent, m.TenantID,
				projections.EventSecretSyncFailed, projections.SecretSyncFailed{
					ID: payload.ID, TenantEpoch: projected.TenantEpoch, Attempts: attempts,
				})
		}
		blocked, blockErr := d.store.SecretSyncHasOlderNonterminal(ctx, m.TenantID, targetID, m.ID)
		if blockErr != nil {
			return fmt.Errorf("server: check older secret-sync command: %w", blockErr)
		}
		if blocked {
			return orchestrator.DeferDelivery(errors.New("server: older secret-sync command for this target is still pending"))
		}
	}
	target := d.secretSyncTarget(m.TenantID, targetID)
	if target == nil {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: secret-sync target %q is not configured for tenant", targetID))
	}
	value, err := openTenantValue(ctx, d.tenantCrypto, d.kek, m.TenantID, payload.Sealed, secretSyncAAD(m.TenantID, targetID, payload.ID, payload.Key))
	if err != nil {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: open secret-sync delivery: %w", err))
	}
	if d.store != nil && crypto.SHA256Hex(value) != projected.ValueDigest {
		secret.Wipe(value)
		return orchestrator.DefiniteNoEffect(errors.New("server: secret-sync sealed payload digest does not match its projected command"))
	}
	locked, err := secret.NewFrom(value)
	secret.Wipe(value)
	if err != nil {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: lock secret-sync delivery value: %w", err))
	}
	defer locked.Destroy()
	if d.beforeSecretSyncReceiverAuthority != nil {
		if err := d.beforeSecretSyncReceiverAuthority(ctx, payload); err != nil {
			return err
		}
	}
	receiverToken, proceed, err := d.beginSecretSyncReceiverIO(ctx, m, projected)
	if err != nil {
		return err
	}
	if !proceed {
		return nil
	}
	if err := target.DeliverOperation(ctx, payload.ID, payload.Key, locked.Bytes()); err != nil {
		if errors.Is(err, cloudauth.ErrOfflineDisabled) {
			provider := cloudauth.OfflineProvider(err)
			if provider == "" {
				provider = "Cloud"
			}
			return d.terminalizeSecretSyncFailure(ctx, m, projected, err,
				provider+" workload identity disabled by air-gap policy", receiverToken, false)
		}
		return fmt.Errorf("server: deliver secret-sync job %s to %s: %w", payload.ID, targetID, err)
	}
	if d.afterSecretSyncDelivery != nil {
		if err := d.afterSecretSyncDelivery(ctx, payload); err != nil {
			return err
		}
	}
	if err := d.appendAndProjectSecretSyncEvidence(ctx, store.SecretSyncDeliveredEventID(m.TenantID, payload.ID), m.TenantID, projections.EventSecretSyncDelivered, projections.SecretSyncDelivered{
		ID: payload.ID, TenantEpoch: projected.TenantEpoch, Attempts: attempts,
	}); err != nil {
		return err
	}
	return nil
}

// secretSyncTarget resolves tenant-owned targets before the worker opens the
// sealed value. The fallback exists only for the legacy single-tenant wiring.
func (d *secretIntegrationOutboxDispatcher) secretSyncTarget(tenantID, targetID string) *secretsync.Target {
	if d.syncTargets != nil {
		return d.syncTargets.ForTenant(tenantID)[targetID]
	}
	return d.fallbackSyncTargets[targetID]
}

var errSecretSyncSourceLocated = errors.New("server: secret-sync queued source located")

// validateProjectedSecretSyncSource treats the exact event at target_order as
// command authority. This closes the final gap left by SQL triggers: the app role
// may enqueue a pending row, but it cannot make a worker perform I/O unless every
// executable byte is also present in retained AN-2 history. Embedded rotation
// syncs are authorized by their parent application-secret mutation event.
func validateProjectedSecretSyncSource(
	ctx context.Context,
	log *events.Log,
	job store.SecretSyncJob,
	outbox secretSyncOutboxPayload,
) error {
	if job.TargetOrder <= 0 {
		return errors.New("server: event-derived secret-sync source order is invalid")
	}
	var source events.Event
	found := false
	err := log.Replay(ctx, uint64(job.TargetOrder), func(event events.Event) error { // #nosec G115 -- positive int64 is exactly representable as uint64.
		if event.Sequence < uint64(job.TargetOrder) { // #nosec G115 -- positive int64 is exactly representable as uint64.
			return nil
		}
		if event.Sequence > uint64(job.TargetOrder) { // #nosec G115 -- positive int64 is exactly representable as uint64.
			return errSecretSyncSourceLocated
		}
		source, found = event, true
		return errSecretSyncSourceLocated
	})
	if err != nil && !errors.Is(err, errSecretSyncSourceLocated) {
		return fmt.Errorf("server: read canonical secret-sync queued source: %w", err)
	}
	if !found || source.TenantID != job.TenantID || source.Sequence != uint64(job.TargetOrder) { // #nosec G115 -- positive int64 is exactly representable as uint64.
		return fmt.Errorf("%w: secret-sync job %s has no event at its projected order", store.ErrIdempotencyConflict, job.ID)
	}
	var queued projections.SecretSyncQueued
	switch source.Type {
	case projections.EventSecretSyncQueued:
		if source.ID != store.SecretSyncQueuedEventID(job.TenantID, job.ID) ||
			source.SchemaVersion != projections.SecretSyncEventSchemaVersion {
			return fmt.Errorf("%w: secret-sync queued source envelope differs", store.ErrIdempotencyConflict)
		}
		if err := json.Unmarshal(source.Data, &queued); err != nil {
			return fmt.Errorf("%w: secret-sync queued source payload is invalid", store.ErrIdempotencyConflict)
		}
	case projections.EventApplicationSecretCreated, projections.EventApplicationSecretRotated,
		projections.EventApplicationSecretRecovered, projections.EventApplicationSecretDeleted:
		if source.SchemaVersion != projections.ApplicationSecretMutationSchemaVersion {
			return fmt.Errorf("%w: embedded secret-sync source schema differs", store.ErrIdempotencyConflict)
		}
		var mutation projections.ApplicationSecretMutation
		if err := json.Unmarshal(source.Data, &mutation); err != nil || mutation.Sync == nil ||
			mutation.TenantEpoch != job.TenantEpoch {
			return fmt.Errorf("%w: embedded secret-sync source payload is invalid", store.ErrIdempotencyConflict)
		}
		queued = *mutation.Sync
		if queued.TenantEpoch != "" && queued.TenantEpoch != mutation.TenantEpoch {
			return fmt.Errorf("%w: embedded secret-sync source epoch differs", store.ErrIdempotencyConflict)
		}
		queued.TenantEpoch = mutation.TenantEpoch
	default:
		return fmt.Errorf("%w: secret-sync projected order names %s, not a queued command", store.ErrIdempotencyConflict, source.Type)
	}
	if queued.TenantEpoch != job.TenantEpoch || queued.ID != job.ID ||
		queued.SecretName != job.SecretName || queued.SecretVersion != job.SecretVersion ||
		queued.Target != job.Target || queued.RemoteKey != job.RemoteKey ||
		queued.ValueDigest != job.ValueDigest || queued.IdempotencyKey != job.IdempotencyKey ||
		queued.RequestBinding != job.RequestBinding || outbox.ID != queued.ID ||
		outbox.Key != queued.RemoteKey || outbox.Target != queued.Target ||
		outbox.RequestBinding != queued.RequestBinding || !bytes.Equal(outbox.Sealed, queued.Sealed) {
		return fmt.Errorf("%w: projected/outbox secret-sync command differs from retained queued source", store.ErrIdempotencyConflict)
	}
	return nil
}

type secretSyncTerminalOutcome uint8

const (
	secretSyncTerminalNone secretSyncTerminalOutcome = iota
	secretSyncTerminalDelivered
	secretSyncTerminalFailed
)

var errSecretSyncTerminalRetained = errors.New("server: retained secret-sync terminal event won before receiver I/O")

var errSecretSyncTenantOffboardRetained = errors.New("server: retained tenant offboard won before secret-sync receiver I/O")

// beginSecretSyncReceiverIO is the last operation before Target.DeliverOperation.
// The fixed history read is outermost. Begin then takes lifecycle, terminal-choice,
// tenant, epoch, and receiver-row locks in one short SQL transaction. The returned
// token is committed before this function returns, so Target.DeliverOperation never
// runs while a database connection or history lock is held.
func (d *secretIntegrationOutboxDispatcher) beginSecretSyncReceiverIO(
	ctx context.Context,
	m orchestrator.Message,
	job store.SecretSyncJob,
) (token int64, proceed bool, err error) {
	if d.store == nil && d.log == nil {
		return 0, true, nil // narrow embed/test compatibility.
	}
	if d.store == nil || d.log == nil {
		return 0, false, errors.New("server: secret-sync receiver authority requires store and retained event history")
	}
	err = d.store.WithPrivacyRecoveryBarrier(ctx, m.TenantID, "secret-sync receiver begin", func(privacyCtx context.Context) error {
		return d.log.WithHistoryRead(privacyCtx, func(readCtx context.Context) error {
			authority, loadErr := d.store.SecretSyncReceiverAuthority(readCtx, m.TenantID, job.ID)
			if errors.Is(loadErr, pgx.ErrNoRows) {
				return nil
			}
			if loadErr != nil {
				return loadErr
			}
			attempts := m.Attempts
			if attempts < authority.OutboxAttempts {
				attempts = authority.OutboxAttempts
			}
			if attempts < 1 {
				attempts = 1
			}

			var (
				retained events.Event
				outcome  secretSyncTerminalOutcome
			)
			guard := func(guardCtx context.Context, registration store.TenantRegistrationSnapshot) error {
				var guardErr error
				outcome, retained, guardErr = d.probeSecretSyncTerminalRetained(
					guardCtx, m.TenantID, job.ID)
				if guardErr != nil {
					return guardErr
				}
				if outcome != secretSyncTerminalNone {
					return errSecretSyncTerminalRetained
				}
				offboarded, guardErr := d.probeSecretSyncTenantOffboardRetained(
					guardCtx, m.TenantID, registration)
				if guardErr != nil {
					return guardErr
				}
				if offboarded {
					return errSecretSyncTenantOffboardRetained
				}
				return nil
			}
			var beginErr error
			token, proceed, beginErr = d.store.BeginSecretSyncReceiverIO(
				readCtx, m.TenantID, job.TenantEpoch, job.ID, m.ID, guard)
			if errors.Is(beginErr, errSecretSyncTerminalRetained) {
				proceed = false
				switch outcome {
				case secretSyncTerminalDelivered:
					return d.validateAndProjectSecretSyncEvidence(readCtx, retained, m.TenantID,
						projections.EventSecretSyncDelivered, projections.SecretSyncDelivered{
							ID: job.ID, TenantEpoch: job.TenantEpoch, Attempts: attempts,
						})
				case secretSyncTerminalFailed:
					return d.validateAndProjectSecretSyncEvidence(readCtx, retained, m.TenantID,
						projections.EventSecretSyncFailed, projections.SecretSyncFailed{
							ID: job.ID, TenantEpoch: job.TenantEpoch, Attempts: attempts,
						})
				default:
					return fmt.Errorf("%w: retained secret-sync terminal outcome is invalid", store.ErrIdempotencyConflict)
				}
			}
			if errors.Is(beginErr, errSecretSyncTenantOffboardRetained) {
				proceed = false
				// The retained lifecycle event is authoritative even when its SQL
				// projection rolled back. Keep this old command pending until the
				// offboard producer resumes and removes the tenant; it must never
				// become a new secret-sync failure after the offboard event.
				return orchestrator.DeferDelivery(beginErr)
			}
			if beginErr != nil || proceed {
				return beginErr
			}

			authority, loadErr = d.store.SecretSyncReceiverAuthority(readCtx, m.TenantID, job.ID)
			if errors.Is(loadErr, pgx.ErrNoRows) {
				return nil
			}
			if loadErr != nil {
				return loadErr
			}
			if authority.JobStatus != store.SecretSyncJobPending {
				return fmt.Errorf("%w: terminal secret-sync SQL fact has no retained terminal event", store.ErrIdempotencyConflict)
			}
			if authority.EffectState != store.SecretSyncReceiverFailureAuthorized {
				return nil
			}
			// A worker may crash after committing failure authority but before the
			// deterministic event append. Complete that zero-I/O transition; never
			// reinterpret it as permission to call the receiver.
			return d.store.WithSecretSyncTerminalChoiceLock(
				readCtx, m.TenantID, job.ID, func(lockCtx context.Context) error {
					return d.appendAndProjectSecretSyncEvidenceLocked(lockCtx,
						store.SecretSyncFailedEventID(m.TenantID, job.ID), m.TenantID,
						projections.EventSecretSyncFailed, projections.SecretSyncFailed{
							ID: job.ID, TenantEpoch: job.TenantEpoch,
							Attempts: authority.FailureAttempts, Error: authority.FailureDetail,
						})
				})
		})
	})
	return token, proceed, err
}

// terminalizeSecretSyncFailure retains failed only when durable command-global
// authority proves every worker generation stopped without a receiver effect.
// terminalCallback distinguishes the generic outbox failure callback: that path
// must return DeliveryDeferred when a delivered winner or ambiguity is observed so
// it cannot dead-letter the row behind opposite terminal evidence.
func (d *secretIntegrationOutboxDispatcher) terminalizeSecretSyncFailure(
	ctx context.Context,
	m orchestrator.Message,
	job store.SecretSyncJob,
	cause error,
	closedError string,
	receiverToken int64,
	terminalCallback bool,
) error {
	if d.store == nil || d.log == nil {
		return errors.New("server: secret-sync terminal failure requires store and retained event history")
	}
	return d.store.WithPrivacyRecoveryBarrier(ctx, m.TenantID, "secret-sync terminal failure", func(privacyCtx context.Context) error {
		return d.log.WithHistoryRead(privacyCtx, func(readCtx context.Context) error {
			return d.store.WithSecretSyncTerminalChoiceLock(readCtx, m.TenantID, job.ID, func(lockCtx context.Context) error {
				authority, err := d.store.SecretSyncReceiverAuthority(lockCtx, m.TenantID, job.ID)
				if err != nil {
					return err
				}
				attempts := m.Attempts
				if attempts < authority.OutboxAttempts {
					attempts = authority.OutboxAttempts
				}
				if attempts < 1 {
					return errors.New("server: terminal secret-sync failure requires a positive attempt count")
				}
				outcome, err := d.probeAndProjectSecretSyncTerminalLocked(lockCtx, m.TenantID, job, attempts)
				if err != nil {
					return err
				}
				switch outcome {
				case secretSyncTerminalDelivered:
					if terminalCallback {
						return orchestrator.DeferDelivery(cause)
					}
					return nil
				case secretSyncTerminalFailed:
					return nil
				}

				if authority.JobStatus != store.SecretSyncJobPending {
					return fmt.Errorf("%w: terminal secret-sync SQL fact has no retained terminal event", store.ErrIdempotencyConflict)
				}
				authorized := false
				if receiverToken == 0 {
					authorized, err = d.store.AuthorizeSecretSyncPreIOFailure(lockCtx, m.TenantID, job.ID, m.ID, closedError, attempts)
				} else {
					authorized, err = d.store.AuthorizeSecretSyncOnlyStartedNoEffect(lockCtx, m.TenantID, job.ID, m.ID, receiverToken, closedError, attempts)
				}
				if err != nil {
					return err
				}
				if !authorized {
					if terminalCallback {
						return orchestrator.DeferDelivery(cause)
					}
					return errors.New("server: secret-sync failure remains ambiguous across receiver generations")
				}
				if d.afterSecretSyncFailureAuthority != nil {
					authority, err := d.store.SecretSyncReceiverAuthority(lockCtx, m.TenantID, job.ID)
					if err != nil {
						return err
					}
					if err := d.afterSecretSyncFailureAuthority(lockCtx, authority); err != nil {
						return err
					}
				}
				return d.appendAndProjectSecretSyncEvidenceLocked(lockCtx,
					store.SecretSyncFailedEventID(m.TenantID, job.ID), m.TenantID,
					projections.EventSecretSyncFailed, projections.SecretSyncFailed{
						ID: job.ID, TenantEpoch: job.TenantEpoch, Attempts: attempts, Error: closedError,
					})
			})
		})
	})
}

// probeAndProjectSecretSyncTerminalLocked closes the append-before-projection
// crash window at the last pre-I/O gate. The caller holds the command advisory
// lock, so no new terminal event can appear between this dual-ID probe and the
// receiver-start transition.
func (d *secretIntegrationOutboxDispatcher) probeAndProjectSecretSyncTerminalLocked(
	ctx context.Context,
	tenantID string,
	job store.SecretSyncJob,
	attempts int,
) (secretSyncTerminalOutcome, error) {
	outcome, canonical, err := d.probeSecretSyncTerminalRetained(ctx, tenantID, job.ID)
	if err != nil {
		return secretSyncTerminalNone, err
	}
	switch outcome {
	case secretSyncTerminalDelivered:
		err = d.validateAndProjectSecretSyncEvidence(ctx, canonical, tenantID,
			projections.EventSecretSyncDelivered, projections.SecretSyncDelivered{
				ID: job.ID, TenantEpoch: job.TenantEpoch, Attempts: attempts,
			})
		return secretSyncTerminalDelivered, err
	case secretSyncTerminalFailed:
		err = d.validateAndProjectSecretSyncEvidence(ctx, canonical, tenantID,
			projections.EventSecretSyncFailed, projections.SecretSyncFailed{
				ID: job.ID, TenantEpoch: job.TenantEpoch, Attempts: attempts,
			})
		return secretSyncTerminalFailed, err
	default:
		return secretSyncTerminalNone, nil
	}
}

// probeSecretSyncTerminalRetained is read-only so BeginSecretSyncReceiverIO may
// invoke it after taking lifecycle and terminal locks without trying to open a
// nested projection transaction. The caller projects only after Begin's SQL
// transaction has committed or rolled back.
func (d *secretIntegrationOutboxDispatcher) probeSecretSyncTerminalRetained(
	ctx context.Context,
	tenantID, jobID string,
) (secretSyncTerminalOutcome, events.Event, error) {
	deliveredEvent, deliveredFound, err := d.log.EventByID(
		ctx, store.SecretSyncDeliveredEventID(tenantID, jobID))
	if err != nil {
		return secretSyncTerminalNone, events.Event{}, err
	}
	failedEvent, failedFound, err := d.log.EventByID(
		ctx, store.SecretSyncFailedEventID(tenantID, jobID))
	if err != nil {
		return secretSyncTerminalNone, events.Event{}, err
	}
	if deliveredFound && failedFound {
		return secretSyncTerminalNone, events.Event{}, fmt.Errorf(
			"%w: retained secret-sync history contains both delivered and failed outcomes",
			store.ErrIdempotencyConflict)
	}
	if deliveredFound {
		return secretSyncTerminalDelivered, deliveredEvent, nil
	}
	if failedFound {
		return secretSyncTerminalFailed, failedEvent, nil
	}
	return secretSyncTerminalNone, events.Event{}, nil
}

// probeSecretSyncTenantOffboardRetained closes the Append-success/SQL-rollback
// gap for tenant offboarding. The caller holds the current registration's shared
// lifecycle fence, so an offboard cannot append after this check until the
// receiver-start transaction commits. If the deterministic event is already
// retained, SQL is stale and no command from that registration may cross the
// external receiver boundary.
func (d *secretIntegrationOutboxDispatcher) probeSecretSyncTenantOffboardRetained(
	ctx context.Context,
	tenantID string,
	registration store.TenantRegistrationSnapshot,
) (bool, error) {
	if d.log == nil || tenantID == "" || !registration.Exists ||
		registration.EventSeq == 0 || registration.Name == "" {
		return false, fmt.Errorf("%w: secret-sync tenant registration authority is incomplete",
			store.ErrIdempotencyConflict)
	}
	registered, found, err := d.log.EventAtSequence(ctx, registration.EventSeq)
	if err != nil {
		return false, err
	}
	if !found || registered.ID == "" || registered.Sequence != registration.EventSeq ||
		registered.Type != projections.EventTenantRegistered || registered.TenantID != tenantID ||
		registered.Time.IsZero() {
		return false, fmt.Errorf("%w: live tenant registration has no exact retained envelope",
			store.ErrIdempotencyConflict)
	}
	if err := projections.ValidateSchemaVersion(registered); err != nil {
		return false, err
	}
	var registeredPayload struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(registered.Data, &registeredPayload); err != nil ||
		registeredPayload.Name != registration.Name {
		return false, fmt.Errorf("%w: live tenant registration payload differs from SQL",
			store.ErrIdempotencyConflict)
	}

	offboardID := projections.TenantOffboardEventID(tenantID, registered.ID)
	offboarded, found, err := d.log.EventByID(ctx, offboardID)
	if err != nil || !found {
		return false, err
	}
	if offboarded.ID != offboardID || offboarded.Type != projections.EventTenantOffboarded ||
		offboarded.TenantID != tenantID || offboarded.Sequence <= registered.Sequence ||
		offboarded.Time.IsZero() {
		return false, fmt.Errorf("%w: retained tenant offboard envelope differs",
			store.ErrIdempotencyConflict)
	}
	if err := projections.ValidateSchemaVersion(offboarded); err != nil {
		return false, err
	}
	var offboardPayload struct {
		RowsDeleted int `json:"rows_deleted"`
	}
	if err := json.Unmarshal(offboarded.Data, &offboardPayload); err != nil ||
		offboardPayload.RowsDeleted < 0 {
		return false, fmt.Errorf("%w: retained tenant offboard payload is invalid",
			store.ErrIdempotencyConflict)
	}
	return true, nil
}

// appendAndProjectSecretSyncEvidence freezes the first successful worker claim's
// attempt count in retained history. Attempts is delivery bookkeeping, not part of
// the receiver command: after an append/projection crash, the next real outbox
// claim has a larger count. Rebuilding JSON from that larger count would collide
// with the deterministic event ID after JetStream's duplicate window. Recovery
// therefore validates the stable evidence fields exactly and reprojects the
// retained canonical count, while also rejecting a non-monotonic retry.
func (d *secretIntegrationOutboxDispatcher) appendAndProjectSecretSyncEvidence(ctx context.Context, eventID, tenantID, eventType string, payload any) error {
	if d.store == nil && d.log == nil {
		return nil // narrow embed/test compatibility; production wires both.
	}
	if d.store == nil || d.log == nil {
		return errors.New("server: secret-sync delivery evidence requires store and event log")
	}
	jobID := ""
	switch expected := payload.(type) {
	case projections.SecretSyncDelivered:
		jobID = expected.ID
	case projections.SecretSyncFailed:
		jobID = expected.ID
	}
	if jobID == "" {
		return errors.New("server: secret-sync terminal evidence payload is invalid")
	}
	return d.store.WithPrivacyRecoveryBarrier(ctx, tenantID, "secret-sync terminal event", func(privacyCtx context.Context) error {
		return d.log.WithHistoryRead(privacyCtx, func(readCtx context.Context) error {
			return d.store.WithSecretSyncTerminalChoiceLock(readCtx, tenantID, jobID, func(lockCtx context.Context) error {
				return d.appendAndProjectSecretSyncEvidenceLocked(lockCtx, eventID, tenantID, eventType, payload)
			})
		})
	})
}

func (d *secretIntegrationOutboxDispatcher) appendAndProjectSecretSyncEvidenceLocked(ctx context.Context, eventID, tenantID, eventType string, payload any) error {
	oppositeID := ""
	jobID := ""
	switch eventType {
	case projections.EventSecretSyncDelivered:
		if expected, ok := payload.(projections.SecretSyncDelivered); ok {
			jobID = expected.ID
			oppositeID = store.SecretSyncFailedEventID(tenantID, expected.ID)
		}
	case projections.EventSecretSyncFailed:
		if expected, ok := payload.(projections.SecretSyncFailed); ok {
			jobID = expected.ID
			oppositeID = store.SecretSyncDeliveredEventID(tenantID, expected.ID)
		}
	}
	if oppositeID == "" {
		return errors.New("server: secret-sync terminal evidence payload is invalid")
	}
	if _, found, err := d.log.EventByID(ctx, oppositeID); err != nil {
		return err
	} else if found {
		return fmt.Errorf("%w: retained secret-sync history already contains the opposite terminal outcome", store.ErrIdempotencyConflict)
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	candidate := events.Event{
		ID: eventID, Type: eventType, TenantID: tenantID,
		SchemaVersion: projections.SecretSyncEventSchemaVersion, Data: data,
	}
	if actor, ok := events.ActorFromContext(ctx); ok {
		candidate.Actor = &actor
	}
	canonical, found, err := d.log.EventByID(ctx, eventID)
	if err != nil {
		return err
	}
	if !found {
		authority, authorityErr := d.store.SecretSyncReceiverAuthority(ctx, tenantID, jobID)
		if authorityErr != nil {
			return authorityErr
		}
		authorized := false
		switch eventType {
		case projections.EventSecretSyncDelivered:
			authorized = authority.JobStatus == store.SecretSyncJobPending &&
				authority.EffectState == store.SecretSyncReceiverEffectPossible &&
				authority.ReceiverIOStarts > 0
		case projections.EventSecretSyncFailed:
			expected, ok := payload.(projections.SecretSyncFailed)
			authorized = ok && authority.JobStatus == store.SecretSyncJobPending &&
				authority.EffectState == store.SecretSyncReceiverFailureAuthorized &&
				authority.ReceiverIOStarts >= 0 && authority.ReceiverIOStarts <= 1 &&
				authority.FailureDetail == expected.Error &&
				authority.FailureAttempts == expected.Attempts
		}
		if !authorized {
			return fmt.Errorf("%w: secret-sync terminal event lacks durable receiver-effect authority", store.ErrIdempotencyConflict)
		}
		canonical, err = d.log.Append(ctx, candidate)
		if err != nil {
			return err
		}
	}
	return d.validateAndProjectSecretSyncEvidence(ctx, canonical, tenantID, eventType, payload)
}

func (d *secretIntegrationOutboxDispatcher) validateAndProjectSecretSyncEvidence(ctx context.Context, canonical events.Event, tenantID, eventType string, payload any) error {
	var expectedActor *events.Actor
	if actor, ok := events.ActorFromContext(ctx); ok {
		expectedActor = &actor
	}
	eventID := ""
	expectedSchemaVersion := projections.SecretSyncEventSchemaVersion
	switch expected := payload.(type) {
	case projections.SecretSyncDelivered:
		eventID = store.SecretSyncDeliveredEventID(tenantID, expected.ID)
		if expected.TenantEpoch == "" {
			expectedSchemaVersion = events.DefaultSchemaVersion
		}
	case projections.SecretSyncFailed:
		eventID = store.SecretSyncFailedEventID(tenantID, expected.ID)
		if expected.TenantEpoch == "" {
			expectedSchemaVersion = events.DefaultSchemaVersion
		}
	}
	if canonical.ID != eventID || canonical.Type != eventType ||
		canonical.TenantID != tenantID || canonical.SchemaVersion != expectedSchemaVersion ||
		canonical.Time.IsZero() || !reflect.DeepEqual(canonical.Actor, expectedActor) {
		return fmt.Errorf("%w: canonical secret-sync evidence envelope differs", store.ErrIdempotencyConflict)
	}
	switch eventType {
	case projections.EventSecretSyncDelivered:
		expected, ok := payload.(projections.SecretSyncDelivered)
		if !ok {
			return errors.New("server: secret-sync delivered evidence has an invalid producer payload")
		}
		var retained projections.SecretSyncDelivered
		if err := json.Unmarshal(canonical.Data, &retained); err != nil ||
			retained.ID != expected.ID || retained.TenantEpoch != expected.TenantEpoch || retained.RemoteVersion != expected.RemoteVersion ||
			retained.Attempts < 1 || retained.Attempts > expected.Attempts {
			return fmt.Errorf("%w: canonical secret-sync delivered evidence differs", store.ErrIdempotencyConflict)
		}
	case projections.EventSecretSyncFailed:
		expected, ok := payload.(projections.SecretSyncFailed)
		if !ok {
			return errors.New("server: secret-sync failed evidence has an invalid producer payload")
		}
		var retained projections.SecretSyncFailed
		if err := json.Unmarshal(canonical.Data, &retained); err != nil ||
			retained.ID != expected.ID || retained.TenantEpoch != expected.TenantEpoch || retained.Error == "" ||
			expected.Error != "" && retained.Error != expected.Error ||
			retained.Attempts < 1 || retained.Attempts > expected.Attempts {
			return fmt.Errorf("%w: canonical secret-sync failed evidence differs", store.ErrIdempotencyConflict)
		}
	default:
		return fmt.Errorf("server: unsupported secret-sync evidence type %q", eventType)
	}
	if d.afterCanonicalAppend != nil {
		if err := d.afterCanonicalAppend(canonical); err != nil {
			return err
		}
	}
	return projections.New(d.store).Apply(ctx, canonical)
}

func (d *secretIntegrationOutboxDispatcher) appendAndProjectID(ctx context.Context, eventID, tenantID, eventType string, payload any) error {
	if d.store == nil && d.log == nil {
		return nil // narrow embed/test compatibility; production wires both.
	}
	if d.store == nil || d.log == nil {
		return errors.New("server: secret integration delivery evidence requires store and event log")
	}
	if eventID == "" {
		return errors.New("server: dynamic-secret event identity is empty")
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	candidate := events.Event{
		ID: eventID, Type: eventType, TenantID: tenantID,
		SchemaVersion: dynamicSecretEventSchemaVersion(eventType), Data: data,
	}
	if actor, ok := events.ActorFromContext(ctx); ok {
		candidate.Actor = &actor
	}
	canonical, found, err := d.log.EventByID(ctx, eventID)
	if err != nil {
		return err
	}
	if !found {
		canonical, err = d.log.Append(ctx, candidate)
		if err != nil {
			return err
		}
	}
	if canonical.ID != candidate.ID || canonical.Type != candidate.Type ||
		canonical.TenantID != candidate.TenantID || canonical.SchemaVersion != candidate.SchemaVersion ||
		canonical.Time.IsZero() || !bytes.Equal(canonical.Data, candidate.Data) ||
		!reflect.DeepEqual(canonical.Actor, candidate.Actor) {
		return fmt.Errorf("%w: canonical secret-integration event envelope differs", store.ErrIdempotencyConflict)
	}
	if d.afterCanonicalAppend != nil {
		if err := d.afterCanonicalAppend(canonical); err != nil {
			return err
		}
	}
	return projections.New(d.store).Apply(ctx, canonical)
}
