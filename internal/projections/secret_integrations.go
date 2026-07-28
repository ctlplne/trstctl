// SPDX-License-Identifier: MPL-2.0

package projections

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

const (
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
	EventSecretSyncQueued                      = "secret.sync.queued"
	EventSecretSyncDelivered                   = "secret.sync.delivered"
	EventSecretSyncFailed                      = "secret.sync.failed"
	EventSecretSyncWorkloadIdentityUpserted    = "secret.sync.workload_identity_source.upserted"
	EventSecretSyncWorkloadIdentityStatus      = "secret.sync.workload_identity_source.status"
	EventSecretSyncWorkloadIdentityDeleted     = "secret.sync.workload_identity_source.deleted"
)

// DynamicSecretLeasePending reserves one deterministic lease before the first
// provider call. SealedPreparation remains for replay compatibility; new request
// paths leave it empty and the outbox worker emits DynamicSecretLeasePrepared.
type DynamicSecretLeasePending struct {
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
	ID                string `json:"id"`
	Provider          string `json:"provider"`
	SealedPreparation []byte `json:"sealed_preparation"`
}

type DynamicSecretLeaseIssued struct {
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
	ID    string `json:"id"`
	Error string `json:"error"`
}

type DynamicSecretLeaseRenewed struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expires_at"`
}

type DynamicSecretLeaseRevocationRequested struct {
	ID         string `json:"id"`
	Provider   string `json:"provider"`
	BackendRef string `json:"backend_ref"`
}

type DynamicSecretLeaseRevocationCompleted struct {
	ID string `json:"id"`
}

// DynamicSecretOperationRequested claims one raw Idempotency-Key for an exact
// authenticated lifecycle command. Response is public lease metadata only.
type DynamicSecretOperationRequested struct {
	OperationID    string          `json:"operation_id"`
	IdempotencyKey string          `json:"idempotency_key"`
	RequestBinding string          `json:"request_binding"`
	Action         string          `json:"action"`
	LeaseID        string          `json:"lease_id"`
	Response       json.RawMessage `json:"response"`
}

type DynamicSecretOperationCompleted struct {
	OperationID    string `json:"operation_id"`
	RequestBinding string `json:"request_binding"`
	Action         string `json:"action"`
	LeaseID        string `json:"lease_id"`
}

// SecretSyncQueued contains metadata plus an already-sealed delivery value. The
// event log can rebuild the outbox without ever carrying plaintext.
type SecretSyncQueued struct {
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
	Attempts      int    `json:"attempts"`
	RemoteVersion string `json:"remote_version,omitempty"`
}

type SecretSyncFailed struct {
	ID       string `json:"id"`
	Attempts int    `json:"attempts"`
	Error    string `json:"error"`
}

// SecretSyncWorkloadIdentitySourceUpserted carries reference-only tenant policy.
// Workload proofs and cloud credentials are forbidden from this event.
type SecretSyncWorkloadIdentitySourceUpserted struct {
	ID                       string   `json:"id"`
	Name                     string   `json:"name"`
	Provider                 string   `json:"provider"`
	RoleARN                  string   `json:"role_arn"`
	ServiceAccount           string   `json:"service_account,omitempty"`
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
}

func (p *Projector) applySecretIntegrationTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	switch e.Type {
	case EventDynamicSecretLeasePending:
		var payload DynamicSecretLeasePending
		if err := decode(e, &payload); err != nil {
			return true, err
		}
		if payload.ID == "" || payload.IdempotencyKey == "" || payload.Provider == "" || payload.Role == "" || payload.ExpiresAt.IsZero() || payload.HardExpiresAt.IsZero() {
			return true, fmt.Errorf("projections: %s payload is incomplete", e.Type)
		}
		command, err := json.Marshal(DynamicSecretIssueCommand(payload))
		if err != nil {
			return true, err
		}
		return true, p.store.ApplyDynamicSecretIssueIntentTx(ctx, tx, store.DynamicSecretLease{
			ID: payload.ID, TenantID: e.TenantID, IdempotencyKey: payload.IdempotencyKey, RequestBinding: payload.RequestBinding,
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
		return true, p.store.ApplyDynamicSecretLeasePreparedTx(ctx, tx, e.TenantID, payload.ID, payload.Provider, payload.SealedPreparation, e.Time)
	case EventDynamicSecretLeaseIssued:
		var payload DynamicSecretLeaseIssued
		if err := decode(e, &payload); err != nil {
			return true, err
		}
		if payload.ID == "" || payload.IdempotencyKey == "" || payload.Provider == "" || payload.Role == "" || payload.BackendRef == "" || len(payload.SealedCredential) == 0 || payload.ExpiresAt.IsZero() || payload.HardExpiresAt.IsZero() {
			return true, fmt.Errorf("projections: %s payload is incomplete", e.Type)
		}
		return true, p.store.ApplyDynamicSecretLeaseIssuedTx(ctx, tx, store.DynamicSecretLease{
			ID: payload.ID, TenantID: e.TenantID, IdempotencyKey: payload.IdempotencyKey, RequestBinding: payload.RequestBinding,
			Provider: payload.Provider, Role: payload.Role, BackendRef: payload.BackendRef, SealedCredential: payload.SealedCredential,
			State: store.DynamicSecretLeaseActive, IssuedAt: e.Time, ExpiresAt: payload.ExpiresAt,
			HardExpiresAt: payload.HardExpiresAt, UpdatedAt: e.Time,
		})
	case EventDynamicSecretLeaseIssuanceFailed:
		var payload DynamicSecretLeaseFailure
		if err := decode(e, &payload); err != nil {
			return true, err
		}
		return true, p.store.ApplyDynamicSecretLeaseIssuanceFailedTx(ctx, tx, e.TenantID, payload.ID, payload.Error, e.Time)
	case EventDynamicSecretLeaseRenewed:
		var payload DynamicSecretLeaseRenewed
		if err := decode(e, &payload); err != nil {
			return true, err
		}
		return true, p.store.ApplyDynamicSecretLeaseRenewedTx(ctx, tx, e.TenantID, payload.ID, payload.ExpiresAt, e.Time)
	case EventDynamicSecretLeaseRevocationRequested:
		var payload DynamicSecretLeaseRevocationRequested
		if err := decode(e, &payload); err != nil {
			return true, err
		}
		outboxPayload, err := json.Marshal(struct {
			LeaseID    string `json:"LeaseID"`
			Provider   string `json:"Provider"`
			BackendRef string `json:"BackendRef"`
		}{LeaseID: payload.ID, Provider: payload.Provider, BackendRef: payload.BackendRef})
		if err != nil {
			return true, err
		}
		return true, p.store.ApplyDynamicSecretRevocationIntentTx(ctx, tx, e.TenantID, payload.ID, outboxPayload, e.Time)
	case EventDynamicSecretLeaseRevocationCompleted:
		var payload DynamicSecretLeaseRevocationCompleted
		if err := decode(e, &payload); err != nil {
			return true, err
		}
		return true, p.store.ApplyDynamicSecretLeaseRevocationCompletedTx(ctx, tx, e.TenantID, payload.ID, e.Time)
	case EventDynamicSecretLeaseRevocationFailed:
		var payload DynamicSecretLeaseFailure
		if err := decode(e, &payload); err != nil {
			return true, err
		}
		return true, p.store.ApplyDynamicSecretLeaseRevocationFailedTx(ctx, tx, e.TenantID, payload.ID, payload.Error, e.Time)
	case EventDynamicSecretOperationRequested:
		var payload DynamicSecretOperationRequested
		if err := decode(e, &payload); err != nil {
			return true, err
		}
		if payload.OperationID == "" || payload.IdempotencyKey == "" || payload.RequestBinding == "" || payload.LeaseID == "" || len(payload.Response) == 0 {
			return true, fmt.Errorf("projections: %s payload is incomplete", e.Type)
		}
		return true, p.store.ApplyDynamicSecretOperationRequestedTx(ctx, tx, store.DynamicSecretOperation{
			TenantID: e.TenantID, OperationID: payload.OperationID,
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
		return true, p.store.ApplyDynamicSecretOperationCompletedTx(ctx, tx, e.TenantID, payload.OperationID, payload.RequestBinding, payload.Action, payload.LeaseID, e.Time)
	case EventSecretSyncQueued:
		var payload SecretSyncQueued
		if err := decode(e, &payload); err != nil {
			return true, err
		}
		outboxPayload, err := json.Marshal(struct {
			ID             string `json:"id"`
			Key            string `json:"key"`
			Target         string `json:"target"`
			RequestBinding string `json:"request_binding,omitempty"`
			Sealed         []byte `json:"sealed"`
		}{ID: payload.ID, Key: payload.RemoteKey, Target: payload.Target, RequestBinding: payload.RequestBinding, Sealed: payload.Sealed})
		if err != nil {
			return true, err
		}
		job := store.SecretSyncJob{
			ID: payload.ID, TenantID: e.TenantID, SecretName: payload.SecretName,
			SecretVersion: payload.SecretVersion, Target: payload.Target, RemoteKey: payload.RemoteKey,
			ValueDigest: payload.ValueDigest, Status: store.SecretSyncJobPending,
			IdempotencyKey: payload.IdempotencyKey, RequestBinding: payload.RequestBinding,
			RequestedAt: e.Time, UpdatedAt: e.Time,
		}
		return true, p.store.ApplySecretSyncIntentTx(ctx, tx, job, "secret.sync."+payload.Target, outboxPayload)
	case EventSecretSyncDelivered:
		var payload SecretSyncDelivered
		if err := decode(e, &payload); err != nil {
			return true, err
		}
		return true, p.store.ApplySecretSyncJobDeliveredTx(ctx, tx, e.TenantID, payload.ID, payload.Attempts, payload.RemoteVersion, e.Time)
	case EventSecretSyncFailed:
		var payload SecretSyncFailed
		if err := decode(e, &payload); err != nil {
			return true, err
		}
		return true, p.store.ApplySecretSyncJobFailedTx(ctx, tx, e.TenantID, payload.ID, payload.Attempts, payload.Error, e.Time)
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
		if (payload.Provider == "aws" && payload.RoleARN == "") ||
			(payload.Provider == "gcp" && payload.RoleARN != "") {
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
