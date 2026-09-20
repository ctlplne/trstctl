// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

type retainedSecretSyncTerminal struct {
	event events.Event
	row   store.SecretSyncTerminalEvent
}

// validateSecretSyncRetainedHistory proves that every terminal SQL fact which
// can release a per-target FIFO barrier is backed by one canonical retained AN-2
// event. Migration 0153 could only create a synthetic receipt from PostgreSQL;
// startup upgrades that receipt after exact evidence comparison, or fails closed
// before workers can perform receiver I/O.
func (p *Projector) validateSecretSyncRetainedHistory(
	ctx context.Context,
	log *events.Log,
	requireActiveSQL bool,
	allowUnprojectedTail bool,
) error {
	if !p.allowSecretSyncRecoveryBootstrap {
		if err := p.store.RequireSecretSyncReceiverRecoveryAuthorized(ctx); err != nil {
			return fmt.Errorf("projections: secret-sync recovery readiness: %w", err)
		}
	}
	return log.WithHistoryRead(ctx, func(readCtx context.Context) error {
		head, err := log.LastSequence(readCtx)
		if err != nil {
			return fmt.Errorf("projections: read secret-sync history head: %w", err)
		}
		authority, err := classifySecretSyncLifecycleThrough(readCtx, log, head)
		if err != nil {
			return fmt.Errorf("projections: classify retained secret-sync lifecycle: %w", err)
		}
		byOutcome := authority.terminalByJob
		activeTerminal := authority.activeTerminal

		rows, err := p.store.ListSecretSyncTerminalHistoryRows(readCtx)
		if err != nil {
			return err
		}
		var checkpoint uint64
		if allowUnprojectedTail {
			checkpoint, err = p.store.ProjectionCheckpoint(readCtx)
			if err != nil {
				return fmt.Errorf("projections: read checkpoint for secret-sync history validation: %w", err)
			}
		}
		sqlTerminal := make(map[string]struct{}, len(rows))
		for _, item := range rows {
			key := item.Job.TenantID + "\x1f" + item.Job.ID
			if _, active := activeTerminal[key]; !active {
				erasedSequence, erased := authority.erasedAt[key]
				if requireActiveSQL && (!allowUnprojectedTail || !erased || erasedSequence <= checkpoint) {
					return fmt.Errorf("%w: terminal secret-sync job %s belongs to an erased or unknown tenant lifecycle", store.ErrIdempotencyConflict, item.Job.ID)
				}
			}
			canonical, ok := byOutcome[key]
			if !ok {
				return fmt.Errorf("projections: terminal secret-sync job %s has no canonical retained event", item.Job.ID)
			}
			event := canonical.row
			if event.Status != item.Job.Status || event.Attempts != item.Job.Attempts ||
				event.RemoteVersion != item.Job.RemoteVersion || event.LastError != item.Job.LastError ||
				!samePostgresTime(event.OccurredAt, item.Job.UpdatedAt) ||
				(item.Job.Status == store.SecretSyncJobDelivered &&
					(item.Job.DeliveredAt == nil || !samePostgresTime(event.OccurredAt, *item.Job.DeliveredAt))) ||
				(item.Job.Status == store.SecretSyncJobFailed && item.Job.DeliveredAt != nil) {
				return fmt.Errorf("%w: retained secret-sync event evidence differs from terminal job %s", store.ErrIdempotencyConflict, item.Job.ID)
			}
			if event.TenantEpoch != "" && event.TenantEpoch != item.Job.TenantEpoch {
				return fmt.Errorf("%w: retained secret-sync event epoch differs from terminal job %s", store.ErrIdempotencyConflict, item.Job.ID)
			}
			event.TenantEpoch = item.Job.TenantEpoch
			if err := validateSecretSyncTerminalOutbox(item, schemaVersionOf(canonical.event)); err != nil {
				return err
			}
			sqlTerminal[key] = struct{}{}
			digest := crypto.SHA256Hex(canonical.event.Data)
			if item.Job.TerminalEventFromEvent != nil && *item.Job.TerminalEventFromEvent {
				if item.Job.TerminalEventSequence == nil || item.Job.TerminalEventID != canonical.event.ID ||
					item.Job.TerminalEventType != canonical.event.Type ||
					*item.Job.TerminalEventSequence != event.EventSequence ||
					item.Job.TerminalEventDigest != digest {
					return fmt.Errorf("%w: terminal secret-sync job %s receipt differs from retained event", store.ErrIdempotencyConflict, item.Job.ID)
				}
				continue
			}
			if item.Job.TerminalEventFromEvent == nil {
				return fmt.Errorf("%w: terminal secret-sync job %s has no receipt provenance", store.ErrIdempotencyConflict, item.Job.ID)
			}
			if err := p.store.ReconcileSecretSyncLegacyTerminalReceipt(readCtx, event); err != nil {
				return fmt.Errorf("projections: reconcile migration-derived terminal receipt for %s: %w", item.Job.ID, err)
			}
		}
		if requireActiveSQL {
			for key, terminal := range activeTerminal {
				if _, ok := sqlTerminal[key]; ok {
					continue
				}
				if allowUnprojectedTail && terminal.event.Sequence > checkpoint {
					continue
				}
				return fmt.Errorf("%w: active retained secret-sync terminal event %s is missing exact SQL evidence", store.ErrIdempotencyConflict, terminal.event.ID)
			}
		}
		return nil
	})
}

func validateSecretSyncTerminalOutbox(item store.SecretSyncTerminalHistoryRow, eventSchemaVersion int) error {
	job := item.Job
	if job.TargetOrder == 0 {
		return fmt.Errorf("%w: terminal secret-sync job %s has zero target order", store.ErrIdempotencyConflict, job.ID)
	}
	legacyEventFailure := job.Status == store.SecretSyncJobFailed &&
		eventSchemaVersion < SecretSyncEventSchemaVersion
	if !item.OutboxPresent {
		// Retention GC may remove only an event-derived terminal cleanup row.
		// A synthetic migration receipt still needs its negative-order outbox as
		// the only durable FIFO provenance available to that old release.
		if legacyEventFailure || job.TargetOrder < 0 ||
			job.TerminalEventFromEvent == nil || !*job.TerminalEventFromEvent {
			return fmt.Errorf("%w: terminal secret-sync job %s lost required retained outbox provenance", store.ErrIdempotencyConflict, job.ID)
		}
		return nil
	}
	if item.OutboxDestination != "secret.sync."+job.Target ||
		item.OutboxTargetOrder != job.TargetOrder || item.OutboxOrderFromEvent == nil ||
		(job.TargetOrder > 0) != *item.OutboxOrderFromEvent {
		return fmt.Errorf("%w: terminal secret-sync job %s outbox destination/order provenance differs", store.ErrIdempotencyConflict, job.ID)
	}
	compatible := false
	switch job.Status {
	case store.SecretSyncJobDelivered:
		compatible = item.OutboxEffectState == store.SecretSyncReceiverEffectPossible &&
			item.OutboxReceiverStarts > 0 && item.OutboxFailureDetail == "" &&
			item.OutboxFailureAttempts == 0 &&
			(item.OutboxStatus == "pending" || item.OutboxStatus == "processing" || item.OutboxStatus == "delivered")
	case store.SecretSyncJobFailed:
		// An air-gap-policy rejection records the failed domain fact and returns
		// success to the generic finalizer, so failed+delivered is intentional.
		canonicalFailure := item.OutboxEffectState == store.SecretSyncReceiverFailureAuthorized &&
			item.OutboxReceiverStarts >= 0 && item.OutboxReceiverStarts <= 1 &&
			item.OutboxFailureDetail == job.LastError && item.OutboxFailureAttempts == job.Attempts
		// Neither a v1 failure event nor pre-0153 PostgreSQL state can prove whether
		// the old generic failure happened before or after receiver I/O. Both
		// therefore retain effect_possible as a permanent successor barrier. A
		// migration row usually has negative order; a legacy artifact normalized
		// against rebuilt history can have positive order. The sticky receiver state,
		// not the SQL allocation shape, is the conservative evidence in both cases.
		ambiguousAuthority :=
			item.OutboxEffectState == store.SecretSyncReceiverEffectPossible &&
				item.OutboxReceiverStarts > 0 && item.OutboxFailureDetail == "" &&
				item.OutboxFailureAttempts == 0
		if legacyEventFailure {
			compatible = ambiguousAuthority
		} else {
			// A current terminal event normally finds the failure_authorized
			// receipt its producer froze before append. Existing effect_possible
			// is nevertheless valid, stronger recovery evidence: a pre-0153
			// artifact had no typed receiver fields, and replay may never upgrade
			// that conservative barrier merely because the paired event uses the
			// current wire schema.
			compatible = canonicalFailure || ambiguousAuthority
		}
		compatible = compatible &&
			(item.OutboxStatus == "pending" || item.OutboxStatus == "processing" ||
				item.OutboxStatus == "failed" || item.OutboxStatus == "delivered")
	}
	if !compatible {
		return fmt.Errorf("%w: terminal secret-sync job %s and retained outbox status/receiver authority disagree", store.ErrIdempotencyConflict, job.ID)
	}
	return nil
}

func samePostgresTime(left, right time.Time) bool {
	return left.UTC().Truncate(time.Microsecond).Equal(right.UTC().Truncate(time.Microsecond))
}

const (
	// DynamicSecretEventSchemaVersion binds every lease/operation transition to
	// the tenant registration that owned its command. Version 1 remains replayable
	// only through retained-history lifecycle classification and exact row binding.
	DynamicSecretEventSchemaVersion = 2

	// DynamicSecretIssuanceFailureEventSchemaVersion is retained as a source-level
	// compatibility name for the first transition upgraded to the v2 contract.
	DynamicSecretIssuanceFailureEventSchemaVersion = DynamicSecretEventSchemaVersion

	// SecretSyncEventSchemaVersion adds an explicit tenant registration epoch to
	// standalone queued and terminal events. Version 1 remains replayable only
	// through the registration-sequence legacy fence.
	SecretSyncEventSchemaVersion = 2

	EventDynamicSecretLeasePending             = "dynsecret.lease.pending"
	EventDynamicSecretLeasePrepared            = "dynsecret.lease.prepared"
	EventDynamicSecretLeaseIssued              = "dynsecret.lease.issued"
	EventDynamicSecretLeaseIssuanceFailed      = "dynsecret.lease.issuance_failed"
	EventDynamicSecretLeaseRenewed             = "dynsecret.lease.renewed"
	EventDynamicSecretLeaseRevocationRequested = "dynsecret.lease.revocation_requested"
	EventDynamicSecretLeaseRevocationCompleted = "dynsecret.lease.revocation_completed"
	EventDynamicSecretLeaseRevocationFailed    = "dynsecret.lease.revocation_failed"
	EventDynamicSecretOperationRequested       = "dynsecret.operation.requested"
	EventDynamicSecretOperationCompleted       = "dynsecret.operation.completed"
	EventSecretSyncQueued                      = "secret.sync.queued" // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
	EventSecretSyncDelivered                   = "secret.sync.delivered"
	EventSecretSyncFailed                      = "secret.sync.failed"
	EventSecretSyncWorkloadIdentityUpserted    = "secret.sync.workload_identity_source.upserted"
	EventSecretSyncWorkloadIdentityStatus      = "secret.sync.workload_identity_source.status"
	EventSecretSyncWorkloadIdentityDeleted     = "secret.sync.workload_identity_source.deleted"
)

func secretSyncTargetOrder(sequence uint64) (int64, error) {
	if sequence == 0 || sequence > uint64(1<<63-1) {
		return 0, fmt.Errorf("projections: secret-sync command requires a positive int64 event sequence")
	}
	return int64(sequence), nil // #nosec G115 -- the explicit bound above proves this event sequence fits PostgreSQL bigint.
}

func dynamicSecretEventSequence(sequence uint64) (int64, error) {
	if sequence == 0 || sequence > uint64(1<<63-1) {
		return 0, fmt.Errorf("projections: dynamic-secret outcome requires a positive int64 event sequence")
	}
	return int64(sequence), nil // #nosec G115 -- the explicit bound above proves this event sequence fits PostgreSQL bigint.
}

func (p *Projector) resolveDynamicSecretEventEpochTx(
	ctx context.Context,
	tx pgx.Tx,
	e events.Event,
	payloadEpoch string,
) (string, bool, error) {
	if schemaVersionOf(e) >= DynamicSecretEventSchemaVersion && payloadEpoch == "" {
		return "", false, fmt.Errorf("projections: %s v%d requires tenant_epoch", e.Type, schemaVersionOf(e))
	}
	eventSequence, err := dynamicSecretEventSequence(e.Sequence)
	if err != nil {
		return "", false, err
	}
	tenantEpoch, err := p.store.ResolveDynamicSecretTenantEpochTx(
		ctx, tx, e.TenantID, payloadEpoch, eventSequence)
	if errors.Is(err, store.ErrDynamicSecretTenantEpochMismatch) {
		return "", true, nil
	}
	return tenantEpoch, false, err
}

func (p *Projector) resolveDynamicSecretPendingEventEpochTx(
	ctx context.Context,
	tx pgx.Tx,
	e events.Event,
	payloadEpoch string,
) (string, bool, error) {
	if schemaVersionOf(e) >= DynamicSecretEventSchemaVersion && payloadEpoch == "" {
		return "", false, fmt.Errorf("projections: %s v%d requires tenant_epoch", e.Type, e.SchemaVersion)
	}
	eventSequence, err := dynamicSecretEventSequence(e.Sequence)
	if err != nil {
		return "", false, err
	}
	tenantEpoch, err := p.store.ResolveDynamicSecretPendingTenantEpochTx(
		ctx, tx, e.TenantID, payloadEpoch, eventSequence)
	if errors.Is(err, store.ErrDynamicSecretTenantEpochMismatch) {
		return "", true, nil
	}
	return tenantEpoch, false, err
}

func validateDynamicSecretEventIdentity(e events.Event, tenantEpoch, purpose, commandID string) error {
	if schemaVersionOf(e) < DynamicSecretEventSchemaVersion {
		return nil
	}
	if e.ID == "" || e.TenantID == "" || tenantEpoch == "" || commandID == "" ||
		e.ID != store.DynamicSecretEventID(e.TenantID, tenantEpoch, purpose, commandID) {
		return fmt.Errorf("%w: %s event identity is not canonical", store.ErrIdempotencyConflict, e.Type)
	}
	return nil
}

// DynamicSecretLeasePending reserves one deterministic lease before the first
// provider call. SealedPreparation remains for replay compatibility; new request
// paths leave it empty and the outbox worker emits DynamicSecretLeasePrepared.
type DynamicSecretLeasePending struct {
	TenantEpoch       string    `json:"tenant_epoch,omitempty"`
	ID                string    `json:"id"`
	IdempotencyKey    string    `json:"idempotency_key"`
	RequestBinding    string    `json:"request_binding,omitempty"`
	Provider          string    `json:"provider"`
	Role              string    `json:"role"`
	ExpiresAt         time.Time `json:"expires_at"`
	HardExpiresAt     time.Time `json:"hard_expires_at"`
	SealedPreparation []byte    `json:"sealed_preparation,omitempty"`
}

// DynamicSecretIssueCommand is the non-secret provider command projected into
// the PostgreSQL outbox in the same transaction as the pending lease. LeaseID is
// the provider idempotency identity used on every worker retry.
type DynamicSecretIssueCommand struct {
	TenantEpoch       string    `json:"tenant_epoch"`
	ID                string    `json:"id"`
	IdempotencyKey    string    `json:"idempotency_key"`
	RequestBinding    string    `json:"request_binding,omitempty"`
	Provider          string    `json:"provider"`
	Role              string    `json:"role"`
	ExpiresAt         time.Time `json:"expires_at"`
	HardExpiresAt     time.Time `json:"hard_expires_at"`
	SealedPreparation []byte    `json:"sealed_preparation,omitempty"`
}

// DynamicSecretLeasePrepared records only worker-created envelope ciphertext.
// It is appended before the first PreparedProvider external mutation so a crash
// retry reuses the identical local key material.
type DynamicSecretLeasePrepared struct {
	TenantEpoch       string `json:"tenant_epoch,omitempty"`
	ID                string `json:"id"`
	Provider          string `json:"provider"`
	SealedPreparation []byte `json:"sealed_preparation"`
}

type DynamicSecretLeaseIssued struct {
	TenantEpoch    string `json:"tenant_epoch,omitempty"`
	ID             string `json:"id"`
	IdempotencyKey string `json:"idempotency_key"`
	RequestBinding string `json:"request_binding,omitempty"`
	Provider       string `json:"provider"`
	Role           string `json:"role"`
	BackendRef     string `json:"backend_ref"`
	// SealedCredential is ciphertext bound to tenant/lease/provider AAD. No
	// plaintext provider credential is ever appended to the event stream.
	SealedCredential []byte    `json:"sealed_credential"`
	ExpiresAt        time.Time `json:"expires_at"`
	HardExpiresAt    time.Time `json:"hard_expires_at"`
}

type DynamicSecretLeaseFailure struct {
	TenantEpoch string `json:"tenant_epoch,omitempty"`
	ID          string `json:"id"`
	Error       string `json:"error"`
}

// DynamicSecretLeaseIssuanceFailure is the current failure wire shape. The
// explicit epoch prevents a retained old-registration outcome from changing a
// new command that later reuses the same public lease ID.
type DynamicSecretLeaseIssuanceFailure struct {
	TenantEpoch string `json:"tenant_epoch"`
	ID          string `json:"id"`
	Error       string `json:"error"`
}

type DynamicSecretLeaseRenewed struct {
	TenantEpoch string    `json:"tenant_epoch,omitempty"`
	OperationID string    `json:"operation_id,omitempty"`
	ID          string    `json:"id"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type DynamicSecretLeaseRevocationRequested struct {
	TenantEpoch string `json:"tenant_epoch,omitempty"`
	OperationID string `json:"operation_id,omitempty"`
	ID          string `json:"id"`
	Provider    string `json:"provider"`
	BackendRef  string `json:"backend_ref"`
}

// DynamicSecretRevokeCommand preserves the legacy RevokeItem field names while
// adding the lower-case epoch field migration 0156 injects into retained rows.
type DynamicSecretRevokeCommand struct {
	TenantEpoch string `json:"tenant_epoch"`
	LeaseID     string `json:"LeaseID"`
	Provider    string `json:"Provider"`
	BackendRef  string `json:"BackendRef"`
}

type DynamicSecretLeaseRevocationCompleted struct {
	TenantEpoch string `json:"tenant_epoch,omitempty"`
	ID          string `json:"id"`
}

// DynamicSecretOperationRequested claims one raw Idempotency-Key for an exact
// authenticated lifecycle command. Response is public lease metadata only.
type DynamicSecretOperationRequested struct {
	TenantEpoch    string          `json:"tenant_epoch,omitempty"`
	OperationID    string          `json:"operation_id"`
	IdempotencyKey string          `json:"idempotency_key"`
	RequestBinding string          `json:"request_binding"`
	Action         string          `json:"action"`
	LeaseID        string          `json:"lease_id"`
	Response       json.RawMessage `json:"response"`
}

type DynamicSecretOperationCompleted struct {
	TenantEpoch    string `json:"tenant_epoch,omitempty"`
	OperationID    string `json:"operation_id"`
	RequestBinding string `json:"request_binding"`
	Action         string `json:"action"`
	LeaseID        string `json:"lease_id"`
}

// SecretSyncQueued contains metadata plus an already-sealed delivery value. The
// event log can rebuild the outbox without ever carrying plaintext.
type SecretSyncQueued struct {
	TenantEpoch    string `json:"tenant_epoch,omitempty"`
	ID             string `json:"id"`
	SecretName     string `json:"secret_name"`
	SecretVersion  int64  `json:"secret_version"`
	Target         string `json:"target"`
	RemoteKey      string `json:"remote_key"`
	ValueDigest    string `json:"value_digest"`
	IdempotencyKey string `json:"idempotency_key"`
	RequestBinding string `json:"request_binding,omitempty"`
	Sealed         []byte `json:"sealed"`
}

type SecretSyncDelivered struct {
	ID            string `json:"id"`
	TenantEpoch   string `json:"tenant_epoch,omitempty"`
	Attempts      int    `json:"attempts"`
	RemoteVersion string `json:"remote_version,omitempty"`
}

type SecretSyncFailed struct {
	ID          string `json:"id"`
	TenantEpoch string `json:"tenant_epoch,omitempty"`
	Attempts    int    `json:"attempts"`
	Error       string `json:"error"`
}

// SecretSyncWorkloadIdentitySourceUpserted carries reference-only tenant policy.
// Workload proofs and cloud credentials are forbidden from this event.
type SecretSyncWorkloadIdentitySourceUpserted struct {
	ID                       string   `json:"id"`
	Name                     string   `json:"name"`
	Provider                 string   `json:"provider"`
	RoleARN                  string   `json:"role_arn"`
	ServiceAccount           string   `json:"service_account,omitempty"`
	AzureTenantID            string   `json:"azure_tenant_id,omitempty"`
	ClientID                 string   `json:"client_id,omitempty"`
	TargetScope              string   `json:"target_scope,omitempty"`
	Audience                 string   `json:"audience"`
	Subject                  string   `json:"subject"`
	TargetID                 string   `json:"target_id"`
	AllowedRemoteKeyPrefixes []string `json:"allowed_remote_key_prefixes,omitempty"`
	WorkloadProofRef         string   `json:"workload_proof_ref"`
	TrustSourceID            string   `json:"trust_source_id"`
	Enabled                  bool     `json:"enabled"`
}

type SecretSyncWorkloadIdentitySourceStatus struct {
	ID        string     `json:"id"`
	Status    string     `json:"status"`
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type SecretSyncWorkloadIdentitySourceDeleted struct {
	ID string `json:"id"`
}

func init() {
	for _, eventType := range []string{
		EventDynamicSecretLeasePending,
		EventDynamicSecretLeasePrepared,
		EventDynamicSecretLeaseIssued,
		EventDynamicSecretLeaseIssuanceFailed,
		EventDynamicSecretLeaseRenewed,
		EventDynamicSecretLeaseRevocationRequested,
		EventDynamicSecretLeaseRevocationCompleted,
		EventDynamicSecretLeaseRevocationFailed,
		EventDynamicSecretOperationRequested,
		EventDynamicSecretOperationCompleted,
		EventSecretSyncQueued,
		EventSecretSyncDelivered,
		EventSecretSyncFailed,
		EventSecretSyncWorkloadIdentityUpserted,
		EventSecretSyncWorkloadIdentityStatus,
		EventSecretSyncWorkloadIdentityDeleted,
	} {
		knownSchemaVersions[eventType] = map[int]bool{1: true}
	}
	for _, eventType := range []string{EventSecretSyncQueued, EventSecretSyncDelivered, EventSecretSyncFailed} {
		knownSchemaVersions[eventType][SecretSyncEventSchemaVersion] = true
	}
	for _, eventType := range []string{
		EventDynamicSecretLeasePending,
		EventDynamicSecretLeasePrepared,
		EventDynamicSecretLeaseIssued,
		EventDynamicSecretLeaseIssuanceFailed,
		EventDynamicSecretLeaseRenewed,
		EventDynamicSecretLeaseRevocationRequested,
		EventDynamicSecretLeaseRevocationCompleted,
		EventDynamicSecretLeaseRevocationFailed,
		EventDynamicSecretOperationRequested,
		EventDynamicSecretOperationCompleted,
	} {
		knownSchemaVersions[eventType][DynamicSecretEventSchemaVersion] = true
	}
}

func (p *Projector) applySecretIntegrationTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	if isDynamicSecretTransitionEventType(e.Type) && e.Time.IsZero() {
		return true, fmt.Errorf("projections: %s event timestamp is empty", e.Type)
	}
	switch e.Type {
	case EventDynamicSecretLeasePending:
		var payload DynamicSecretLeasePending
		if err := decode(e, &payload); err != nil {
			return true, err
		}
		if payload.ID == "" || payload.IdempotencyKey == "" || payload.Provider == "" || payload.Role == "" || payload.ExpiresAt.IsZero() || payload.HardExpiresAt.IsZero() {
			return true, fmt.Errorf("projections: %s payload is incomplete", e.Type)
		}
		if err := validateDynamicSecretEventIdentity(e, payload.TenantEpoch, "issue-requested", payload.ID); err != nil {
			return true, err
		}
		tenantEpoch, inert, err := p.resolveDynamicSecretPendingEventEpochTx(ctx, tx, e, payload.TenantEpoch)
		if inert {
			return true, nil
		}
		if err != nil {
			return true, err
		}
		command, err := json.Marshal(DynamicSecretIssueCommand{
			TenantEpoch: tenantEpoch, ID: payload.ID, IdempotencyKey: payload.IdempotencyKey,
			RequestBinding: payload.RequestBinding, Provider: payload.Provider, Role: payload.Role,
			ExpiresAt: payload.ExpiresAt, HardExpiresAt: payload.HardExpiresAt,
			SealedPreparation: payload.SealedPreparation,
		})
		if err != nil {
			return true, err
		}
		return true, p.store.ApplyDynamicSecretIssueIntentTx(ctx, tx, store.DynamicSecretLease{
			ID: payload.ID, TenantID: e.TenantID, TenantEpoch: tenantEpoch,
			IdempotencyKey: payload.IdempotencyKey, RequestBinding: payload.RequestBinding,
			Provider: payload.Provider, Role: payload.Role, State: store.DynamicSecretLeasePending,
			SealedPreparation: payload.SealedPreparation,
			IssuedAt:          e.Time, ExpiresAt: payload.ExpiresAt, HardExpiresAt: payload.HardExpiresAt, UpdatedAt: e.Time,
		}, command)
	case EventDynamicSecretLeasePrepared:
		var payload DynamicSecretLeasePrepared
		if err := decode(e, &payload); err != nil {
			return true, err
		}
		if payload.ID == "" || payload.Provider == "" || len(payload.SealedPreparation) == 0 {
			return true, fmt.Errorf("projections: %s payload is incomplete", e.Type)
		}
		if err := validateDynamicSecretEventIdentity(e, payload.TenantEpoch, "provider-prepared", payload.ID); err != nil {
			return true, err
		}
		tenantEpoch, inert, err := p.resolveDynamicSecretEventEpochTx(ctx, tx, e, payload.TenantEpoch)
		if inert {
			return true, nil
		}
		if err != nil {
			return true, err
		}
		return true, p.store.ApplyDynamicSecretLeasePreparedForEpochTx(
			ctx, tx, e.TenantID, tenantEpoch, payload.ID, payload.Provider,
			payload.SealedPreparation, e.Time)
	case EventDynamicSecretLeaseIssued:
		var payload DynamicSecretLeaseIssued
		if err := decode(e, &payload); err != nil {
			return true, err
		}
		if payload.ID == "" || payload.IdempotencyKey == "" || payload.Provider == "" || payload.Role == "" || payload.BackendRef == "" || len(payload.SealedCredential) == 0 || payload.ExpiresAt.IsZero() || payload.HardExpiresAt.IsZero() {
			return true, fmt.Errorf("projections: %s payload is incomplete", e.Type)
		}
		if err := validateDynamicSecretEventIdentity(e, payload.TenantEpoch, "provider-issued", payload.ID); err != nil {
			return true, err
		}
		tenantEpoch, inert, err := p.resolveDynamicSecretEventEpochTx(ctx, tx, e, payload.TenantEpoch)
		if inert {
			return true, nil
		}
		if err != nil {
			return true, err
		}
		return true, p.store.ApplyDynamicSecretLeaseIssuedTx(ctx, tx, store.DynamicSecretLease{
			ID: payload.ID, TenantID: e.TenantID, TenantEpoch: tenantEpoch,
			IdempotencyKey: payload.IdempotencyKey, RequestBinding: payload.RequestBinding,
			Provider: payload.Provider, Role: payload.Role, BackendRef: payload.BackendRef, SealedCredential: payload.SealedCredential,
			State: store.DynamicSecretLeaseActive, IssuedAt: e.Time, ExpiresAt: payload.ExpiresAt,
			HardExpiresAt: payload.HardExpiresAt, UpdatedAt: e.Time,
		})
	case EventDynamicSecretLeaseIssuanceFailed:
		var payload DynamicSecretLeaseIssuanceFailure
		if err := decode(e, &payload); err != nil {
			return true, err
		}
		if payload.ID == "" || payload.Error == "" {
			return true, fmt.Errorf("projections: %s payload is incomplete", e.Type)
		}
		if err := validateDynamicSecretEventIdentity(e, payload.TenantEpoch, "provider-issue-failed", payload.ID); err != nil {
			return true, err
		}
		tenantEpoch, inert, err := p.resolveDynamicSecretEventEpochTx(ctx, tx, e, payload.TenantEpoch)
		if inert {
			// A retained outcome from an erased registration has no authority over
			// a newly registered tenant, even when its lease ID is reused.
			return true, nil
		}
		if err != nil {
			return true, err
		}
		return true, p.store.ApplyDynamicSecretLeaseIssuanceFailedForEpochTx(
			ctx, tx, e.TenantID, tenantEpoch, payload.ID, payload.Error, e.Time)
	case EventDynamicSecretLeaseRenewed:
		var payload DynamicSecretLeaseRenewed
		if err := decode(e, &payload); err != nil {
			return true, err
		}
		if payload.ID == "" || payload.ExpiresAt.IsZero() ||
			(schemaVersionOf(e) >= DynamicSecretEventSchemaVersion && payload.OperationID == "") {
			return true, fmt.Errorf("projections: %s payload is incomplete", e.Type)
		}
		if err := validateDynamicSecretEventIdentity(e, payload.TenantEpoch, "lease-renewed", payload.OperationID); err != nil {
			return true, err
		}
		tenantEpoch, inert, err := p.resolveDynamicSecretEventEpochTx(ctx, tx, e, payload.TenantEpoch)
		if inert {
			return true, nil
		}
		if err != nil {
			return true, err
		}
		return true, p.store.ApplyDynamicSecretLeaseRenewedForEpochTx(
			ctx, tx, e.TenantID, tenantEpoch, payload.ID, payload.ExpiresAt, e.Time)
	case EventDynamicSecretLeaseRevocationRequested:
		var payload DynamicSecretLeaseRevocationRequested
		if err := decode(e, &payload); err != nil {
			return true, err
		}
		if payload.ID == "" || payload.Provider == "" || payload.BackendRef == "" ||
			(schemaVersionOf(e) >= DynamicSecretEventSchemaVersion && payload.OperationID == "") {
			return true, fmt.Errorf("projections: %s payload is incomplete", e.Type)
		}
		if err := validateDynamicSecretEventIdentity(e, payload.TenantEpoch, "lease-revocation-requested", payload.OperationID); err != nil {
			return true, err
		}
		tenantEpoch, inert, err := p.resolveDynamicSecretEventEpochTx(ctx, tx, e, payload.TenantEpoch)
		if inert {
			return true, nil
		}
		if err != nil {
			return true, err
		}
		outboxPayload, err := json.Marshal(DynamicSecretRevokeCommand{
			TenantEpoch: tenantEpoch, LeaseID: payload.ID,
			Provider: payload.Provider, BackendRef: payload.BackendRef,
		})
		if err != nil {
			return true, err
		}
		return true, p.store.ApplyDynamicSecretRevocationIntentForEpochTx(
			ctx, tx, e.TenantID, tenantEpoch, payload.ID, outboxPayload, e.Time)
	case EventDynamicSecretLeaseRevocationCompleted:
		var payload DynamicSecretLeaseRevocationCompleted
		if err := decode(e, &payload); err != nil {
			return true, err
		}
		if payload.ID == "" {
			return true, fmt.Errorf("projections: %s payload is incomplete", e.Type)
		}
		if err := validateDynamicSecretEventIdentity(e, payload.TenantEpoch, "provider-revocation-completed", payload.ID); err != nil {
			return true, err
		}
		tenantEpoch, inert, err := p.resolveDynamicSecretEventEpochTx(ctx, tx, e, payload.TenantEpoch)
		if inert {
			return true, nil
		}
		if err != nil {
			return true, err
		}
		return true, p.store.ApplyDynamicSecretLeaseRevocationCompletedForEpochTx(
			ctx, tx, e.TenantID, tenantEpoch, payload.ID, e.Time)
	case EventDynamicSecretLeaseRevocationFailed:
		var payload DynamicSecretLeaseFailure
		if err := decode(e, &payload); err != nil {
			return true, err
		}
		if payload.ID == "" || payload.Error == "" {
			return true, fmt.Errorf("projections: %s payload is incomplete", e.Type)
		}
		if err := validateDynamicSecretEventIdentity(e, payload.TenantEpoch, "provider-revocation-failed", payload.ID); err != nil {
			return true, err
		}
		tenantEpoch, inert, err := p.resolveDynamicSecretEventEpochTx(ctx, tx, e, payload.TenantEpoch)
		if inert {
			return true, nil
		}
		if err != nil {
			return true, err
		}
		return true, p.store.ApplyDynamicSecretLeaseRevocationFailedForEpochTx(
			ctx, tx, e.TenantID, tenantEpoch, payload.ID, payload.Error, e.Time)
	case EventDynamicSecretOperationRequested:
		var payload DynamicSecretOperationRequested
		if err := decode(e, &payload); err != nil {
			return true, err
		}
		if payload.OperationID == "" || payload.IdempotencyKey == "" || payload.RequestBinding == "" ||
			payload.Action == "" || payload.LeaseID == "" || len(payload.Response) == 0 {
			return true, fmt.Errorf("projections: %s payload is incomplete", e.Type)
		}
		if err := validateDynamicSecretEventIdentity(e, payload.TenantEpoch, "operation-requested", payload.OperationID); err != nil {
			return true, err
		}
		tenantEpoch, inert, err := p.resolveDynamicSecretEventEpochTx(ctx, tx, e, payload.TenantEpoch)
		if inert {
			return true, nil
		}
		if err != nil {
			return true, err
		}
		return true, p.store.ApplyDynamicSecretOperationRequestedTx(ctx, tx, store.DynamicSecretOperation{
			TenantID: e.TenantID, TenantEpoch: tenantEpoch, OperationID: payload.OperationID,
			IdempotencyKey: payload.IdempotencyKey, RequestBinding: payload.RequestBinding,
			Action: payload.Action, LeaseID: payload.LeaseID, Response: payload.Response,
			Status: store.DynamicSecretOperationPending, CreatedAt: e.Time, UpdatedAt: e.Time,
		})
	case EventDynamicSecretOperationCompleted:
		var payload DynamicSecretOperationCompleted
		if err := decode(e, &payload); err != nil {
			return true, err
		}
		if payload.OperationID == "" || payload.RequestBinding == "" || payload.Action == "" || payload.LeaseID == "" {
			return true, fmt.Errorf("projections: %s payload is incomplete", e.Type)
		}
		if err := validateDynamicSecretEventIdentity(e, payload.TenantEpoch, "operation-completed", payload.OperationID); err != nil {
			return true, err
		}
		tenantEpoch, inert, err := p.resolveDynamicSecretEventEpochTx(ctx, tx, e, payload.TenantEpoch)
		if inert {
			return true, nil
		}
		if err != nil {
			return true, err
		}
		return true, p.store.ApplyDynamicSecretOperationCompletedForEpochTx(
			ctx, tx, e.TenantID, tenantEpoch, payload.OperationID,
			payload.RequestBinding, payload.Action, payload.LeaseID, e.Time)
	case EventSecretSyncQueued:
		var payload SecretSyncQueued
		if err := decode(e, &payload); err != nil {
			return true, err
		}
		if e.ID != store.SecretSyncQueuedEventID(e.TenantID, payload.ID) {
			return true, fmt.Errorf("%w: secret-sync queued event identity is not canonical", store.ErrIdempotencyConflict)
		}
		if e.SchemaVersion >= SecretSyncEventSchemaVersion && payload.TenantEpoch == "" {
			return true, fmt.Errorf("projections: %s v%d requires tenant_epoch", e.Type, e.SchemaVersion)
		}
		targetOrder, err := secretSyncTargetOrder(e.Sequence)
		if err != nil {
			return true, err
		}
		tenantEpoch, err := p.store.ResolveSecretSyncQueuedTenantEpochTx(ctx, tx, e.TenantID, payload.TenantEpoch, targetOrder)
		if errors.Is(err, store.ErrApplicationSecretTenantEpochMismatch) {
			return true, nil
		}
		if err != nil {
			return true, err
		}
		outboxPayload, err := json.Marshal(struct {
			ID             string `json:"id"`
			Key            string `json:"key"`
			Target         string `json:"target"`
			RequestBinding string `json:"request_binding,omitempty"`
			Sealed         []byte `json:"sealed"`
		}{
			ID: payload.ID, Key: payload.RemoteKey, Target: payload.Target,
			RequestBinding: payload.RequestBinding, Sealed: payload.Sealed,
		})
		if err != nil {
			return true, err
		}
		job := store.SecretSyncJob{
			ID: payload.ID, TenantID: e.TenantID, TenantEpoch: tenantEpoch, SecretName: payload.SecretName,
			SecretVersion: payload.SecretVersion, Target: payload.Target, RemoteKey: payload.RemoteKey,
			ValueDigest: payload.ValueDigest, Status: store.SecretSyncJobPending,
			TargetOrder:    targetOrder,
			IdempotencyKey: payload.IdempotencyKey, RequestBinding: payload.RequestBinding,
			RequestedAt: e.Time, UpdatedAt: e.Time,
		}
		return true, p.store.ApplySecretSyncIntentTx(ctx, tx, job, "secret.sync."+payload.Target, outboxPayload)
	case EventSecretSyncDelivered:
		var payload SecretSyncDelivered
		if err := decode(e, &payload); err != nil {
			return true, err
		}
		if payload.ID == "" || payload.Attempts < 1 || e.ID != store.SecretSyncDeliveredEventID(e.TenantID, payload.ID) {
			return true, fmt.Errorf("%w: secret-sync delivered event identity is not canonical", store.ErrIdempotencyConflict)
		}
		if e.SchemaVersion >= SecretSyncEventSchemaVersion && payload.TenantEpoch == "" {
			return true, fmt.Errorf("projections: %s v%d requires tenant_epoch", e.Type, e.SchemaVersion)
		}
		eventSequence, err := secretSyncTargetOrder(e.Sequence)
		if err != nil {
			return true, err
		}
		tenantEpoch, err := p.store.ResolveSecretSyncTenantEpochTx(ctx, tx, e.TenantID, payload.TenantEpoch, eventSequence)
		if errors.Is(err, store.ErrApplicationSecretTenantEpochMismatch) {
			return true, nil
		}
		if err != nil {
			return true, err
		}
		err = p.store.ApplySecretSyncTerminalEventTx(ctx, tx, store.SecretSyncTerminalEvent{
			TenantID: e.TenantID, TenantEpoch: tenantEpoch, JobID: payload.ID,
			Status: store.SecretSyncJobDelivered, Attempts: payload.Attempts,
			RemoteVersion: payload.RemoteVersion, OccurredAt: e.Time,
			EventID: e.ID, EventType: e.Type, EventSequence: eventSequence,
			PayloadDigest: crypto.SHA256Hex(e.Data),
		})
		if errors.Is(err, pgx.ErrNoRows) {
			// A late outcome for a job erased by tenant.offboarded is inert. Full
			// replay and the durable tail use the lifecycle authority above; this
			// missing-row rule closes the inline append/project crash window too.
			return true, nil
		}
		return true, err
	case EventSecretSyncFailed:
		var payload SecretSyncFailed
		if err := decode(e, &payload); err != nil {
			return true, err
		}
		if payload.ID == "" || payload.Attempts < 1 || payload.Error == "" || e.ID != store.SecretSyncFailedEventID(e.TenantID, payload.ID) {
			return true, fmt.Errorf("%w: secret-sync failed event identity is not canonical", store.ErrIdempotencyConflict)
		}
		if e.SchemaVersion >= SecretSyncEventSchemaVersion && payload.TenantEpoch == "" {
			return true, fmt.Errorf("projections: %s v%d requires tenant_epoch", e.Type, e.SchemaVersion)
		}
		eventSequence, err := secretSyncTargetOrder(e.Sequence)
		if err != nil {
			return true, err
		}
		tenantEpoch, err := p.store.ResolveSecretSyncTenantEpochTx(ctx, tx, e.TenantID, payload.TenantEpoch, eventSequence)
		if errors.Is(err, store.ErrApplicationSecretTenantEpochMismatch) {
			return true, nil
		}
		if err != nil {
			return true, err
		}
		err = p.store.ApplySecretSyncTerminalEventTx(ctx, tx, store.SecretSyncTerminalEvent{
			TenantID: e.TenantID, TenantEpoch: tenantEpoch, JobID: payload.ID,
			Status: store.SecretSyncJobFailed, Attempts: payload.Attempts, LastError: payload.Error,
			OccurredAt: e.Time, EventID: e.ID, EventType: e.Type, EventSequence: eventSequence,
			PayloadDigest:             crypto.SHA256Hex(e.Data),
			FailureDefinitelyNoEffect: schemaVersionOf(e) >= SecretSyncEventSchemaVersion,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return true, nil
		}
		return true, err
	case EventSecretSyncWorkloadIdentityUpserted:
		var payload SecretSyncWorkloadIdentitySourceUpserted
		if err := decode(e, &payload); err != nil {
			return true, err
		}
		if payload.ID == "" || payload.Name == "" || payload.Provider == "" ||
			payload.Audience == "" || payload.Subject == "" || payload.TargetID == "" ||
			payload.WorkloadProofRef == "" || payload.TrustSourceID == "" {
			return true, fmt.Errorf("projections: %s payload is incomplete", e.Type)
		}
		validProviderConfig := (payload.Provider == "aws" &&
			payload.RoleARN != "" && payload.ServiceAccount == "" &&
			payload.AzureTenantID == "" && payload.ClientID == "" && payload.TargetScope == "") ||
			(payload.Provider == "gcp" &&
				payload.RoleARN == "" && payload.AzureTenantID == "" &&
				payload.ClientID == "" && payload.TargetScope == "") ||
			(payload.Provider == "azure" &&
				payload.RoleARN == "" && payload.ServiceAccount == "" &&
				payload.AzureTenantID != "" && payload.ClientID != "" && payload.TargetScope != "")
		if !validProviderConfig {
			return true, fmt.Errorf("projections: %s provider configuration is invalid", e.Type)
		}
		status := store.SecretSyncWorkloadIdentityReady
		reason := "configured"
		if !payload.Enabled {
			status = store.SecretSyncWorkloadIdentityDisabled
			reason = "disabled_by_operator"
		}
		return true, p.store.ApplySecretSyncWorkloadIdentitySourceUpsertedTx(ctx, tx, store.SecretSyncWorkloadIdentitySource{
			ID: payload.ID, TenantID: e.TenantID, Name: payload.Name, Provider: payload.Provider,
			RoleARN: payload.RoleARN, ServiceAccount: payload.ServiceAccount,
			AzureTenantID: payload.AzureTenantID, ClientID: payload.ClientID, TargetScope: payload.TargetScope,
			Audience: payload.Audience, Subject: payload.Subject,
			TargetID: payload.TargetID, AllowedRemoteKeyPrefixes: payload.AllowedRemoteKeyPrefixes,
			WorkloadProofRef: payload.WorkloadProofRef, TrustSourceID: payload.TrustSourceID,
			Enabled: payload.Enabled, Status: status, StatusReason: reason,
			CreatedAt: e.Time, UpdatedAt: e.Time,
		})
	case EventSecretSyncWorkloadIdentityStatus:
		var payload SecretSyncWorkloadIdentitySourceStatus
		if err := decode(e, &payload); err != nil {
			return true, err
		}
		if payload.ID == "" || payload.Status == "" || payload.Reason == "" {
			return true, fmt.Errorf("projections: %s payload is incomplete", e.Type)
		}
		return true, p.store.ApplySecretSyncWorkloadIdentitySourceStatusTx(
			ctx, tx, e.TenantID, payload.ID, payload.Status, payload.Reason, payload.ExpiresAt, e.Time,
		)
	case EventSecretSyncWorkloadIdentityDeleted:
		var payload SecretSyncWorkloadIdentitySourceDeleted
		if err := decode(e, &payload); err != nil {
			return true, err
		}
		if payload.ID == "" {
			return true, fmt.Errorf("projections: %s payload is incomplete", e.Type)
		}
		return true, p.store.ApplySecretSyncWorkloadIdentitySourceDeletedTx(ctx, tx, e.TenantID, payload.ID)
	default:
		return false, nil
	}
}
