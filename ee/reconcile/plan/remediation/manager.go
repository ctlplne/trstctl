// SPDX-License-Identifier: LicenseRef-trstctl-EE

package remediation

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/ee/reconcile/canon"
	xrecplan "trstctl.com/trstctl/ee/reconcile/plan"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/signing"
	corestore "trstctl.com/trstctl/internal/store"
)

const (
	// EventTypeAuthorizationRecorded is the ledger event name stored with each
	// signer-approved remediation authorization.
	EventTypeAuthorizationRecorded = "xrec.remediation.authorized"
	// OutboxDestination is the first-party destination drained by the XREC
	// remediation outbox handler.
	OutboxDestination = "xrec.remediation"
)

var ErrInvalidAuthorization = errors.New("xrec remediation: invalid authorization")

// AuthorizationRequest is the control-plane handoff after the isolated signer has
// approved a plan action. The decision's Authorization bytes are public, opaque
// proof from the signer gate; this package stores them and stages a job but does
// not perform the corrective write inside the transaction.
type AuthorizationRequest struct {
	TenantID   string
	SignedPlan xrecplan.SignedPlan
	Action     xrecplan.Action
	Decision   signing.OperationDecision
}

// AuthorizationRecord is the durable tenant-scoped ledger row written before the
// remediation job is enqueued in the same transaction.
type AuthorizationRecord struct {
	ID             int64
	TenantID       string
	PlanID         string
	PlanHash       string
	WitnessID      string
	WitnessHash    string
	AuthorityID    string
	RecordKey      canon.RecordKey
	Operation      string
	Authorization  []byte
	IdempotencyKey string
	Inserted       bool
	OutboxInserted bool
	CreatedAt      time.Time
}

// Job is the outbox payload for one authorized corrective write. The write-scoped
// connector lands in XREC-09c; this job shape is already stable and idempotent.
type Job struct {
	TenantID       string            `json:"tenant_id"`
	PlanID         string            `json:"plan_id"`
	PlanHash       string            `json:"plan_hash"`
	WitnessID      string            `json:"witness_id"`
	WitnessHash    string            `json:"witness_hash"`
	AuthorityID    string            `json:"authority_id"`
	RecordKey      canon.RecordKey   `json:"record_key"`
	Operation      string            `json:"operation"`
	Parameters     map[string]string `json:"parameters,omitempty"`
	Authorization  []byte            `json:"authorization"`
	IdempotencyKey string            `json:"idempotency_key"`
}

// Manager owns the same-transaction authorization + outbox enqueue path.
type Manager struct {
	store        *corestore.Store
	outbox       *orchestrator.Outbox
	afterEnqueue func(context.Context) error
}

// Option configures a Manager.
type Option func(*Manager)

// WithAfterEnqueue injects a hook after the ledger row and outbox row are both
// written but before commit. Tests use it to prove the transaction rolls back as
// one unit.
func WithAfterEnqueue(f func(context.Context) error) Option {
	return func(m *Manager) { m.afterEnqueue = f }
}

// NewManager returns an XREC remediation authorization manager over the shared
// core store and outbox table.
func NewManager(s *corestore.Store, outbox *orchestrator.Outbox, opts ...Option) (*Manager, error) {
	if s == nil {
		return nil, fmt.Errorf("%w: nil store", ErrInvalidAuthorization)
	}
	if outbox == nil {
		outbox = orchestrator.NewOutbox(s)
	}
	m := &Manager{store: s, outbox: outbox}
	for _, opt := range opts {
		if opt != nil {
			opt(m)
		}
	}
	return m, nil
}

// Authorize records the signer-approved action and stages its corrective write in
// the same tenant-scoped database transaction. The idempotency key is derived from
// (witness hash, record key, operation), so repeating the same authorization does
// not create a second ledger row or outbox job.
func (m *Manager) Authorize(ctx context.Context, req AuthorizationRequest) (AuthorizationRecord, error) {
	rec, job, err := buildAuthorization(req)
	if err != nil {
		return AuthorizationRecord{}, err
	}
	payload, err := json.Marshal(job)
	if err != nil {
		return AuthorizationRecord{}, fmt.Errorf("xrec remediation: encode job: %w", err)
	}
	var out AuthorizationRecord
	err = m.store.WithTenant(ctx, rec.TenantID, func(tx pgx.Tx) error {
		stored, inserted, err := insertAuthorization(ctx, tx, rec)
		if err != nil {
			return err
		}
		stored.Inserted = inserted
		outboxInserted, err := m.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
			TenantID:       rec.TenantID,
			Destination:    OutboxDestination,
			IdempotencyKey: rec.IdempotencyKey,
			Payload:        payload,
		})
		if err != nil {
			return err
		}
		stored.OutboxInserted = outboxInserted
		out = stored
		if m.afterEnqueue != nil {
			return m.afterEnqueue(ctx)
		}
		return nil
	})
	if err != nil {
		return AuthorizationRecord{}, err
	}
	return out, nil
}

func buildAuthorization(req AuthorizationRequest) (AuthorizationRecord, Job, error) {
	tenantID := strings.TrimSpace(req.TenantID)
	if tenantID == "" {
		tenantID = strings.TrimSpace(req.SignedPlan.Plan.TenantID)
	}
	operation := normalizeOperation(req.Action.Operation)
	if tenantID == "" || operation == "" || !req.Decision.Approved || len(req.Decision.Authorization) == 0 {
		return AuthorizationRecord{}, Job{}, ErrInvalidAuthorization
	}
	authorityID := strings.TrimSpace(req.Action.AuthorityID)
	if authorityID == "" {
		return AuthorizationRecord{}, Job{}, fmt.Errorf("%w: missing remediation authority", ErrInvalidAuthorization)
	}
	if len(req.Decision.RefusalRecord) != 0 {
		return AuthorizationRecord{}, Job{}, fmt.Errorf("%w: approved decision carried a refusal", ErrInvalidAuthorization)
	}
	plan := req.SignedPlan.Plan
	if strings.TrimSpace(plan.TenantID) != tenantID || strings.TrimSpace(req.Action.RecordKey.TenantID) != tenantID {
		return AuthorizationRecord{}, Job{}, fmt.Errorf("%w: tenant mismatch", ErrInvalidAuthorization)
	}
	if !planContainsAction(plan, req.Action) {
		return AuthorizationRecord{}, Job{}, fmt.Errorf("%w: action not in signed plan", ErrInvalidAuthorization)
	}
	planHash, err := plan.Hash()
	if err != nil {
		return AuthorizationRecord{}, Job{}, err
	}
	if len(req.SignedPlan.PlanHash) != 0 && !bytes.Equal(req.SignedPlan.PlanHash, planHash) {
		return AuthorizationRecord{}, Job{}, fmt.Errorf("%w: plan hash mismatch", ErrInvalidAuthorization)
	}
	idem, err := StableIdempotencyKey(plan.WitnessHash, req.Action.RecordKey, operation)
	if err != nil {
		return AuthorizationRecord{}, Job{}, err
	}
	rec := AuthorizationRecord{
		TenantID:       tenantID,
		PlanID:         strings.TrimSpace(plan.PlanID),
		PlanHash:       hex.EncodeToString(planHash),
		WitnessID:      strings.TrimSpace(plan.WitnessID),
		WitnessHash:    hex.EncodeToString(plan.WitnessHash),
		AuthorityID:    authorityID,
		RecordKey:      req.Action.RecordKey,
		Operation:      operation,
		Authorization:  append([]byte(nil), req.Decision.Authorization...),
		IdempotencyKey: idem,
	}
	job := Job{
		TenantID:       rec.TenantID,
		PlanID:         rec.PlanID,
		PlanHash:       rec.PlanHash,
		WitnessID:      rec.WitnessID,
		WitnessHash:    rec.WitnessHash,
		AuthorityID:    rec.AuthorityID,
		RecordKey:      rec.RecordKey,
		Operation:      rec.Operation,
		Parameters:     copyStringMap(req.Action.Parameters),
		Authorization:  append([]byte(nil), rec.Authorization...),
		IdempotencyKey: rec.IdempotencyKey,
	}
	return rec, job, nil
}

// StableIdempotencyKey returns the remediation idempotency key for the exact
// signer-approved tuple required by XREC-09b.
func StableIdempotencyKey(witnessHash []byte, recordKey canon.RecordKey, operation string) (string, error) {
	op := normalizeOperation(operation)
	key := canon.RecordKey{
		TenantID:   strings.TrimSpace(recordKey.TenantID),
		RecordType: strings.TrimSpace(recordKey.RecordType),
		StableID:   strings.TrimSpace(recordKey.StableID),
	}
	if len(witnessHash) == 0 || key.TenantID == "" || key.RecordType == "" || key.StableID == "" || op == "" {
		return "", ErrInvalidAuthorization
	}
	payload := struct {
		WitnessHash string          `json:"witness_hash"`
		RecordKey   canon.RecordKey `json:"record_key"`
		Operation   string          `json:"operation"`
	}{
		WitnessHash: hex.EncodeToString(witnessHash),
		RecordKey:   key,
		Operation:   op,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("xrec remediation: encode idempotency key: %w", err)
	}
	return "xrec-remediation:" + crypto.SHA256Hex(raw), nil
}

func insertAuthorization(ctx context.Context, tx pgx.Tx, rec AuthorizationRecord) (AuthorizationRecord, bool, error) {
	recordKeyJSON, err := json.Marshal(rec.RecordKey)
	if err != nil {
		return AuthorizationRecord{}, false, fmt.Errorf("xrec remediation: encode record key: %w", err)
	}
	row := tx.QueryRow(ctx,
		`WITH inserted AS (
		     INSERT INTO xrec_remediation_authorizations
		       (tenant_id, event_type, plan_id, plan_hash, witness_id, witness_hash, authority_id, record_key, operation, signer_authorization, idempotency_key)
		     VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10)
		     ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
		     RETURNING id, tenant_id::text, plan_id, plan_hash, witness_id, witness_hash, authority_id, record_key::text, operation, signer_authorization, idempotency_key, created_at, true AS inserted
		 )
		 SELECT id, tenant_id, plan_id, plan_hash, witness_id, witness_hash, authority_id, record_key, operation, signer_authorization, idempotency_key, created_at, inserted
		   FROM inserted
		 UNION ALL
		 SELECT id, tenant_id::text, plan_id, plan_hash, witness_id, witness_hash, authority_id, record_key::text, operation, signer_authorization, idempotency_key, created_at, false AS inserted
		   FROM xrec_remediation_authorizations
		  WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid
		    AND idempotency_key = $10
		 LIMIT 1`,
		EventTypeAuthorizationRecorded, rec.PlanID, rec.PlanHash, rec.WitnessID, rec.WitnessHash, rec.AuthorityID, string(recordKeyJSON), rec.Operation, rec.Authorization, rec.IdempotencyKey)
	var stored AuthorizationRecord
	var recordKeyRaw string
	var inserted bool
	if err := row.Scan(&stored.ID, &stored.TenantID, &stored.PlanID, &stored.PlanHash, &stored.WitnessID, &stored.WitnessHash, &stored.AuthorityID, &recordKeyRaw, &stored.Operation, &stored.Authorization, &stored.IdempotencyKey, &stored.CreatedAt, &inserted); err != nil {
		return AuthorizationRecord{}, false, fmt.Errorf("xrec remediation: insert authorization: %w", err)
	}
	if err := json.Unmarshal([]byte(recordKeyRaw), &stored.RecordKey); err != nil {
		return AuthorizationRecord{}, false, fmt.Errorf("xrec remediation: decode record key: %w", err)
	}
	return stored, inserted, nil
}

func planContainsAction(plan xrecplan.Plan, want xrecplan.Action) bool {
	wantOp := normalizeOperation(want.Operation)
	for _, action := range plan.Actions {
		if normalizeOperation(action.Operation) != wantOp {
			continue
		}
		if action.RecordKey.TenantID == want.RecordKey.TenantID &&
			action.RecordKey.RecordType == want.RecordKey.RecordType &&
			action.RecordKey.StableID == want.RecordKey.StableID {
			return true
		}
	}
	return false
}

func normalizeOperation(op string) string {
	return strings.ToLower(strings.TrimSpace(op))
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
