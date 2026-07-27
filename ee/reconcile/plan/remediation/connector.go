// SPDX-License-Identifier: LicenseRef-trstctl-EE

package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/ee/reconcile/canon"
	corestore "trstctl.com/trstctl/internal/store"
)

const (
	ReceiptStatusDelivered = "delivered"
	ReceiptStatusDenied    = "denied"
	ReceiptStatusFailed    = "failed"
)

var ErrOperationDenied = errors.New("xrec remediation: operation class denied")

// OperationGrant is an exact allow-list of signer-approved operation classes a
// remediation connector may execute. It is intentionally narrower than the
// read-only observation grant: remediation writes are separate and write-scoped.
type OperationGrant struct {
	classes map[string]bool
}

// NewOperationGrant returns an operation-class grant for a remediation
// connector. Operation names are normalized the same way plan actions are.
func NewOperationGrant(classes ...string) OperationGrant {
	g := OperationGrant{classes: map[string]bool{}}
	for _, class := range classes {
		if op := normalizeOperation(class); op != "" {
			g.classes[op] = true
		}
	}
	return g
}

func (g OperationGrant) Allows(operation string) bool {
	return g.classes[normalizeOperation(operation)]
}

// RemediationRequest is the connector-facing form of an authorized XREC
// remediation job.
type RemediationRequest struct {
	TenantID       string
	PlanID         string
	WitnessID      string
	WitnessHash    string
	AuthorityID    string
	RecordKey      canon.RecordKey
	Operation      string
	Parameters     map[string]string
	Authorization  []byte
	IdempotencyKey string
}

// RemediationConnector is distinct from observation reducers/connectors. It may
// perform only the operation classes its exact grant permits.
type RemediationConnector interface {
	Name() string
	OperationGrant() OperationGrant
	ExecuteRemediationAction(context.Context, RemediationRequest) (detail string, err error)
}

// Receipt is the audit evidence for one remediation job execution attempt.
type Receipt struct {
	TenantID       string
	PlanID         string
	WitnessID      string
	WitnessHash    string
	AuthorityID    string
	RecordKey      canon.RecordKey
	Operation      string
	Connector      string
	Status         string
	Reason         string
	Detail         string
	IdempotencyKey string
	RecordedAt     time.Time
}

// ReceiptRecorder records delivered/denied/failed remediation connector
// outcomes. The store-backed implementation is used by the production attach.
type ReceiptRecorder interface {
	RecordRemediationReceipt(context.Context, Receipt) error
}

// Registry routes XREC remediation jobs to distinct write-scoped connectors.
type Registry struct {
	mu         sync.RWMutex
	connectors map[string]RemediationConnector
	recorder   ReceiptRecorder
}

// NewRegistry returns an empty remediation connector registry.
func NewRegistry(recorder ReceiptRecorder) *Registry {
	return &Registry{connectors: map[string]RemediationConnector{}, recorder: recorder}
}

// Register adds a write-scoped remediation connector under its Name.
func (r *Registry) Register(c RemediationConnector) {
	if r == nil || c == nil || strings.TrimSpace(c.Name()) == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.connectors[strings.TrimSpace(c.Name())] = c
}

// ExecuteRemediation implements Executor. An out-of-grant operation is recorded
// as denied and then acknowledged, so the outbox does not retry an operation that
// must never run. Missing connectors and connector failures fail closed and are
// retried by the outbox.
func (r *Registry) ExecuteRemediation(ctx context.Context, job Job) error {
	if r == nil {
		return ErrConnectorNotConfigured
	}
	req := requestFromJob(job)
	receipt := receiptFromRequest(req)
	r.mu.RLock()
	conn := r.connectors[req.AuthorityID]
	r.mu.RUnlock()
	if conn == nil {
		receipt.Status = ReceiptStatusFailed
		receipt.Reason = "connector_not_registered"
		receipt.Detail = "no write-scoped remediation connector registered for authority"
		if err := r.record(ctx, receipt); err != nil {
			return err
		}
		return fmt.Errorf("%w: %s", ErrConnectorNotConfigured, req.AuthorityID)
	}
	receipt.Connector = conn.Name()
	if !conn.OperationGrant().Allows(req.Operation) {
		receipt.Status = ReceiptStatusDenied
		receipt.Reason = "operation_class_denied"
		receipt.Detail = "operation is outside the connector capability grant"
		return r.record(ctx, receipt)
	}
	detail, err := conn.ExecuteRemediationAction(ctx, req)
	if err != nil {
		receipt.Status = ReceiptStatusFailed
		receipt.Reason = "connector_failed"
		receipt.Detail = err.Error()
		if receiptErr := r.record(ctx, receipt); receiptErr != nil {
			return errors.Join(err, fmt.Errorf("xrec remediation: record failed-action receipt: %w", receiptErr))
		}
		return err
	}
	receipt.Status = ReceiptStatusDelivered
	receipt.Reason = "connector_delivered"
	receipt.Detail = strings.TrimSpace(detail)
	return r.record(ctx, receipt)
}

func (r *Registry) record(ctx context.Context, receipt Receipt) error {
	if r.recorder == nil {
		return nil
	}
	return r.recorder.RecordRemediationReceipt(ctx, receipt)
}

func requestFromJob(job Job) RemediationRequest {
	return RemediationRequest{
		TenantID:       job.TenantID,
		PlanID:         job.PlanID,
		WitnessID:      job.WitnessID,
		WitnessHash:    job.WitnessHash,
		AuthorityID:    job.AuthorityID,
		RecordKey:      job.RecordKey,
		Operation:      normalizeOperation(job.Operation),
		Parameters:     copyStringMap(job.Parameters),
		Authorization:  append([]byte(nil), job.Authorization...),
		IdempotencyKey: job.IdempotencyKey,
	}
}

func receiptFromRequest(req RemediationRequest) Receipt {
	return Receipt{
		TenantID:       req.TenantID,
		PlanID:         req.PlanID,
		WitnessID:      req.WitnessID,
		WitnessHash:    req.WitnessHash,
		AuthorityID:    req.AuthorityID,
		RecordKey:      req.RecordKey,
		Operation:      req.Operation,
		Connector:      req.AuthorityID,
		IdempotencyKey: req.IdempotencyKey,
	}
}

// StoreReceiptRecorder records XREC remediation receipts under tenant RLS.
type StoreReceiptRecorder struct {
	store *corestore.Store
}

func NewStoreReceiptRecorder(s *corestore.Store) *StoreReceiptRecorder {
	return &StoreReceiptRecorder{store: s}
}

func (r *StoreReceiptRecorder) RecordRemediationReceipt(ctx context.Context, receipt Receipt) error {
	if r == nil || r.store == nil {
		return ErrConnectorNotConfigured
	}
	if receipt.TenantID == "" || receipt.IdempotencyKey == "" || receipt.Status == "" {
		return ErrInvalidAuthorization
	}
	recordKeyJSON, err := json.Marshal(receipt.RecordKey)
	if err != nil {
		return fmt.Errorf("xrec remediation: encode receipt record key: %w", err)
	}
	return r.store.WithTenant(ctx, receipt.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO xrec_remediation_receipts
			    (tenant_id, plan_id, witness_id, witness_hash, authority_id, record_key, operation, connector, status, reason, detail, idempotency_key)
			  VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9, $10, $11)
			  ON CONFLICT (tenant_id, idempotency_key) DO UPDATE
			    SET status = EXCLUDED.status,
			        reason = EXCLUDED.reason,
			        detail = EXCLUDED.detail,
			        connector = EXCLUDED.connector,
			        recorded_at = now()`,
			receipt.PlanID, receipt.WitnessID, receipt.WitnessHash, receipt.AuthorityID,
			string(recordKeyJSON), receipt.Operation, receipt.Connector, receipt.Status,
			receipt.Reason, receipt.Detail, receipt.IdempotencyKey)
		if err != nil {
			return fmt.Errorf("xrec remediation: record receipt: %w", err)
		}
		return nil
	})
}
