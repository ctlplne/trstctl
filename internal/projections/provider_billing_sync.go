// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// The Provider billing sync's usage pushes (MSP-2): one customer's closed
// period for one billing target is queued once with its signed evidence's
// digest, held with the reason when it cannot be signed, then delivered or
// failed. The tenant is the customer.
const (
	EventBillingSyncQueued    = "provider.billing_sync.queued"
	EventBillingSyncHeld      = "provider.billing_sync.held"
	EventBillingSyncDelivered = "provider.billing_sync.delivered"
	EventBillingSyncFailed    = "provider.billing_sync.failed"
)

// BillingSyncPushEvent is the payload of every provider.billing_sync.* event.
// Lines and the evidence JWS travel only on queued, as the outbox payload's
// source; ResponseStatus only on delivered and failed.
type BillingSyncPushEvent struct {
	TargetID          string             `json:"target_id"`
	PeriodStart       time.Time          `json:"period_start"`
	PeriodEnd         time.Time          `json:"period_end"`
	ExternalCompanyID string             `json:"external_company_id,omitempty"`
	EvidenceDigest    string             `json:"evidence_digest,omitempty"`
	EvidenceJWS       string             `json:"evidence_jws,omitempty"`
	Lines             []BillingUsageLine `json:"lines,omitempty"`
	Reason            string             `json:"reason,omitempty"`
	ResponseStatus    int                `json:"response_status,omitempty"`
}

// BillingUsageLine is one metered figure of a pushed period.
type BillingUsageLine struct {
	Meter string `json:"meter"`
	Kind  string `json:"kind"`
	Value int64  `json:"value"`
}

var billingTargetIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ValidateBillingSyncPushEvent checks a provider.billing_sync.* payload.
func ValidateBillingSyncPushEvent(eventType string, p BillingSyncPushEvent) error {
	if !billingTargetIDPattern.MatchString(p.TargetID) {
		return fmt.Errorf("a billing sync push names a valid target, not %q", p.TargetID)
	}
	if p.PeriodStart.IsZero() || !p.PeriodEnd.After(p.PeriodStart) {
		return fmt.Errorf("a billing sync push names a closed period")
	}
	if len(p.ExternalCompanyID) > 128 || len(p.EvidenceDigest) > 128 || len(p.Reason) > 2000 || len(p.Lines) > 64 {
		return fmt.Errorf("a billing sync push field is too long")
	}
	switch eventType {
	case EventBillingSyncQueued:
		if strings.TrimSpace(p.ExternalCompanyID) == "" || p.EvidenceDigest == "" || p.EvidenceJWS == "" {
			return fmt.Errorf("a queued period names its company and carries its signed evidence")
		}
	case EventBillingSyncHeld:
		if strings.TrimSpace(p.Reason) == "" {
			return fmt.Errorf("a held period says why it cannot be signed")
		}
	case EventBillingSyncDelivered, EventBillingSyncFailed:
	default:
		return fmt.Errorf("unknown billing sync event %q", eventType)
	}
	return nil
}

func billingSyncStatus(eventType string) string {
	switch eventType {
	case EventBillingSyncQueued:
		return store.BillingSyncQueued
	case EventBillingSyncHeld:
		return store.BillingSyncHeld
	case EventBillingSyncDelivered:
		return store.BillingSyncDelivered
	default:
		return store.BillingSyncFailed
	}
}

func (p *Projector) applyBillingSyncTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	switch e.Type {
	case EventBillingSyncQueued, EventBillingSyncHeld, EventBillingSyncDelivered, EventBillingSyncFailed:
	default:
		return false, nil
	}
	var d BillingSyncPushEvent
	if err := json.Unmarshal(e.Data, &d); err != nil {
		return true, fmt.Errorf("projections: decode %s: %w", e.Type, err)
	}
	if err := ValidateBillingSyncPushEvent(e.Type, d); err != nil {
		return true, fmt.Errorf("projections: %s: %w", e.Type, err)
	}
	return true, p.store.ApplyBillingSyncPushTx(ctx, tx, store.BillingSyncPush{
		TenantID: e.TenantID, TargetID: d.TargetID, PeriodStart: d.PeriodStart, PeriodEnd: d.PeriodEnd,
		Status: billingSyncStatus(e.Type), ExternalCompanyID: d.ExternalCompanyID, EvidenceDigest: d.EvidenceDigest,
		Reason: d.Reason, ResponseStatus: d.ResponseStatus, UpdatedAt: e.Time,
	}, e.ID, e.Sequence)
}
