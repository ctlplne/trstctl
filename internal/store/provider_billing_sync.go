// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
)

// Billing sync push states (MSP-2).
const (
	BillingSyncQueued    = "queued"
	BillingSyncHeld      = "held"
	BillingSyncDelivered = "delivered"
	BillingSyncFailed    = "failed"
)

// BillingSyncPush is one customer's usage period for one billing target: queued
// once when its signed evidence exists, held with the reason when it cannot be
// signed, then delivered or failed. ExternalCompanyID is the company it was
// queued for.
type BillingSyncPush struct {
	TenantID          string
	TargetID          string
	PeriodStart       time.Time
	PeriodEnd         time.Time
	Status            string
	ExternalCompanyID string
	EvidenceDigest    string
	Reason            string
	ResponseStatus    int
	FirstEventID      string
	EventSequence     uint64
	UpdatedAt         time.Time
}

// ApplyBillingSyncPushTx projects one transition. A period moves held → held
// (a newer reason), held → queued (it became signable), queued → delivered
// or queued → failed; nothing else changes a row, so a replay, a second sweep
// or an out-of-order event converges, and a delivered period is never queued
// again.
func (s *Store) ApplyBillingSyncPushTx(ctx context.Context, tx pgx.Tx, p BillingSyncPush, eventID string, sequence uint64) error {
	if sequence == 0 || sequence > math.MaxInt64 {
		return errors.New("store: billing sync event sequence is out of range")
	}
	switch p.Status {
	case BillingSyncQueued, BillingSyncHeld, BillingSyncDelivered, BillingSyncFailed:
	default:
		return fmt.Errorf("store: unknown billing sync status %q", p.Status)
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO provider_billing_sync_pushes
		  (tenant_id, target_id, period_start, period_end, status, external_company_id, evidence_digest, reason,
		   response_status, first_event_id, event_sequence, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (tenant_id, target_id, period_start) DO UPDATE SET
		  status = EXCLUDED.status,
		  external_company_id = CASE WHEN EXCLUDED.status = 'queued' THEN EXCLUDED.external_company_id
		                             ELSE provider_billing_sync_pushes.external_company_id END,
		  evidence_digest = CASE WHEN EXCLUDED.evidence_digest <> '' THEN EXCLUDED.evidence_digest
		                         ELSE provider_billing_sync_pushes.evidence_digest END,
		  reason = EXCLUDED.reason,
		  response_status = EXCLUDED.response_status,
		  event_sequence = EXCLUDED.event_sequence,
		  updated_at = EXCLUDED.updated_at
		WHERE provider_billing_sync_pushes.event_sequence < EXCLUDED.event_sequence
		  AND ((provider_billing_sync_pushes.status = 'held' AND EXCLUDED.status IN ('held', 'queued'))
		    OR (provider_billing_sync_pushes.status = 'queued' AND EXCLUDED.status IN ('delivered', 'failed')))`,
		p.TenantID, p.TargetID, p.PeriodStart.UTC(), p.PeriodEnd.UTC(), p.Status, p.ExternalCompanyID, p.EvidenceDigest,
		p.Reason, p.ResponseStatus, eventID, int64(sequence), p.UpdatedAt.UTC()) // #nosec G115 -- bounded by the check above (CWE-190)
	return err
}

// BillingSyncPushes lists a customer's most recent pushes, newest first.
func (s *Store) BillingSyncPushes(ctx context.Context, tenantID string, limit int) ([]BillingSyncPush, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var out []BillingSyncPush
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT tenant_id::text, target_id, period_start, period_end, status, external_company_id,
			evidence_digest, reason, response_status, first_event_id, event_sequence, updated_at
			FROM provider_billing_sync_pushes WHERE tenant_id = $1
			ORDER BY period_start DESC, target_id LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			p, err := scanBillingSyncPush(rows)
			if err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	return out, err
}

// BillingSyncPushFor reads one customer's push for a target and period.
func (s *Store) BillingSyncPushFor(ctx context.Context, tenantID, targetID string, periodStart time.Time) (BillingSyncPush, bool, error) {
	var out BillingSyncPush
	found := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT tenant_id::text, target_id, period_start, period_end, status, external_company_id,
			evidence_digest, reason, response_status, first_event_id, event_sequence, updated_at
			FROM provider_billing_sync_pushes WHERE tenant_id = $1 AND target_id = $2 AND period_start = $3`,
			tenantID, targetID, periodStart.UTC())
		p, err := scanBillingSyncPush(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		out, found = p, true
		return nil
	})
	return out, found, err
}

// BillingCompanyFor reads the company a customer is mapped to in a target
// (MSP-2), under the customer's own tenant.
func (s *Store) BillingCompanyFor(ctx context.Context, tenantID, targetID string) (string, bool, error) {
	var company string
	found := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT external_company_id FROM provider_billing_companies
			WHERE tenant_id = $1 AND target_id = $2`, tenantID, targetID).Scan(&company)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		found = err == nil
		return err
	})
	return company, found, err
}

// BillingCompanyMapping is one customer's company in one target.
type BillingCompanyMapping struct {
	TenantID          string
	ExternalCompanyID string
}

// BillingCompanyMappings lists every customer mapped in a target, for the
// deployment-level billing sync sweep.
func (s *Store) BillingCompanyMappings(ctx context.Context, targetID string) ([]BillingCompanyMapping, error) {
	//trstctl:system-query — cross-tenant by design: the billing sync sweep lists every customer mapped in one deployment-configured target (tenant_id and company only); each period is then read and queued in its own tenant's RLS context.
	rows, err := s.SystemPool().Query(ctx, `SELECT tenant_id::text, external_company_id FROM provider_billing_companies
		WHERE target_id = $1 ORDER BY tenant_id`, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BillingCompanyMapping
	for rows.Next() {
		var m BillingCompanyMapping
		if err := rows.Scan(&m.TenantID, &m.ExternalCompanyID); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

type billingSyncScanner interface {
	Scan(dest ...any) error
}

func scanBillingSyncPush(row billingSyncScanner) (BillingSyncPush, error) {
	var p BillingSyncPush
	var seq int64
	if err := row.Scan(&p.TenantID, &p.TargetID, &p.PeriodStart, &p.PeriodEnd, &p.Status, &p.ExternalCompanyID,
		&p.EvidenceDigest, &p.Reason, &p.ResponseStatus, &p.FirstEventID, &seq, &p.UpdatedAt); err != nil {
		return BillingSyncPush{}, err
	}
	if seq > 0 {
		p.EventSequence = uint64(seq)
	}
	p.PeriodStart, p.PeriodEnd, p.UpdatedAt = p.PeriodStart.UTC(), p.PeriodEnd.UTC(), p.UpdatedAt.UTC()
	return p, nil
}
