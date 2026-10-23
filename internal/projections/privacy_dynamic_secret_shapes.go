// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"encoding/json"
	"time"
)

// Dynamic-secret lease and operation privacy payload shapes (the exact
// mirrors the served log checks envelopes against). They live beside the
// workflow so the central registry stays within its served-source size guard.

type privacyDynamicSecretLegacyLeaseAudit struct {
	Lease      string `json:"lease"`
	Provider   string `json:"provider"`
	Role       string `json:"role"`
	BackendRef string `json:"backend_ref"`
	State      string `json:"state"`
}

// Dynamic-secret v1 shapes are kept explicit. The current Go payloads contain an
// optional epoch only so old bytes still decode; using those structs for v1
// privacy validation would accidentally bless tenant_epoch on the legacy schema.
type privacyDynamicSecretLeasePendingV1 struct {
	ID                string    `json:"id"`
	IdempotencyKey    string    `json:"idempotency_key"`
	RequestBinding    string    `json:"request_binding,omitempty"`
	Provider          string    `json:"provider"`
	Role              string    `json:"role"`
	ExpiresAt         time.Time `json:"expires_at"`
	HardExpiresAt     time.Time `json:"hard_expires_at"`
	SealedPreparation []byte    `json:"sealed_preparation,omitempty"`
}

type privacyDynamicSecretLeasePreparedV1 struct {
	ID                string `json:"id"`
	Provider          string `json:"provider"`
	SealedPreparation []byte `json:"sealed_preparation"`
}

type privacyDynamicSecretLeaseIssuedV1 struct {
	ID               string    `json:"id"`
	IdempotencyKey   string    `json:"idempotency_key"`
	RequestBinding   string    `json:"request_binding,omitempty"`
	Provider         string    `json:"provider"`
	Role             string    `json:"role"`
	BackendRef       string    `json:"backend_ref"`
	SealedCredential []byte    `json:"sealed_credential"`
	ExpiresAt        time.Time `json:"expires_at"`
	HardExpiresAt    time.Time `json:"hard_expires_at"`
}

type privacyDynamicSecretLeaseFailureV1 struct {
	ID    string `json:"id"`
	Error string `json:"error"`
}

type privacyDynamicSecretLeaseRenewedV1 struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expires_at"`
}

type privacyDynamicSecretLeaseRevocationRequestedV1 struct {
	ID         string `json:"id"`
	Provider   string `json:"provider"`
	BackendRef string `json:"backend_ref"`
}

type privacyDynamicSecretLeaseRevocationCompletedV1 struct {
	ID string `json:"id"`
}

type privacyDynamicSecretOperationRequestedV1 struct {
	OperationID    string          `json:"operation_id"`
	IdempotencyKey string          `json:"idempotency_key"`
	RequestBinding string          `json:"request_binding"`
	Action         string          `json:"action"`
	LeaseID        string          `json:"lease_id"`
	Response       json.RawMessage `json:"response"`
}

type privacyDynamicSecretOperationCompletedV1 struct {
	OperationID    string `json:"operation_id"`
	RequestBinding string `json:"request_binding"`
	Action         string `json:"action"`
	LeaseID        string `json:"lease_id"`
}

// Dynamic-secret v2 shapes deliberately make tenant_epoch (and the operation
// identity used by transition event IDs) required. Runtime payload structs keep
// those fields optional solely so retained v1 bytes can still be decoded.
type privacyDynamicSecretLeasePendingV2 struct {
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

type privacyDynamicSecretLeasePreparedV2 struct {
	TenantEpoch       string `json:"tenant_epoch"`
	ID                string `json:"id"`
	Provider          string `json:"provider"`
	SealedPreparation []byte `json:"sealed_preparation"`
}

type privacyDynamicSecretLeaseIssuedV2 struct {
	TenantEpoch      string    `json:"tenant_epoch"`
	ID               string    `json:"id"`
	IdempotencyKey   string    `json:"idempotency_key"`
	RequestBinding   string    `json:"request_binding,omitempty"`
	Provider         string    `json:"provider"`
	Role             string    `json:"role"`
	BackendRef       string    `json:"backend_ref"`
	SealedCredential []byte    `json:"sealed_credential"`
	ExpiresAt        time.Time `json:"expires_at"`
	HardExpiresAt    time.Time `json:"hard_expires_at"`
}

type privacyDynamicSecretLeaseFailureV2 struct {
	TenantEpoch string `json:"tenant_epoch"`
	ID          string `json:"id"`
	Error       string `json:"error"`
	AttemptID   string `json:"attempt_id,omitempty"`
}

type privacyDynamicSecretLeaseRenewedV2 struct {
	TenantEpoch string    `json:"tenant_epoch"`
	OperationID string    `json:"operation_id"`
	ID          string    `json:"id"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type privacyDynamicSecretLeaseRevocationRequestedV2 struct {
	TenantEpoch string `json:"tenant_epoch"`
	OperationID string `json:"operation_id"`
	ID          string `json:"id"`
	Provider    string `json:"provider"`
	BackendRef  string `json:"backend_ref"`
}

type privacyDynamicSecretLeaseRevocationRetryRequestedV2 struct {
	TenantEpoch      string `json:"tenant_epoch"`
	OperationID      string `json:"operation_id"`
	ID               string `json:"id"`
	Provider         string `json:"provider"`
	BackendRef       string `json:"backend_ref"`
	PreviousOutboxID int64  `json:"previous_outbox_id"`
}

type privacyDynamicSecretLeaseRevocationCompletedV2 struct {
	TenantEpoch string `json:"tenant_epoch"`
	ID          string `json:"id"`
	AttemptID   string `json:"attempt_id,omitempty"`
}

type privacyDynamicSecretOperationRequestedV2 struct {
	TenantEpoch    string          `json:"tenant_epoch"`
	OperationID    string          `json:"operation_id"`
	IdempotencyKey string          `json:"idempotency_key"`
	RequestBinding string          `json:"request_binding"`
	Action         string          `json:"action"`
	LeaseID        string          `json:"lease_id"`
	Response       json.RawMessage `json:"response"`
}

type privacyDynamicSecretOperationCompletedV2 struct {
	TenantEpoch    string `json:"tenant_epoch"`
	OperationID    string `json:"operation_id"`
	RequestBinding string `json:"request_binding"`
	Action         string `json:"action"`
	LeaseID        string `json:"lease_id"`
}
