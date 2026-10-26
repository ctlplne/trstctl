// SPDX-License-Identifier: LicenseRef-trstctl-EE

package auditcompliance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/auditanchor"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/events"
)

// AnchorScopes serializes one tenant's anchoring with its retention archive
// and with history rewrites, so the head timestamped is the head the log holds
// when the anchor is appended.
type AnchorScopes interface {
	WithAuditRetentionScope(context.Context, string, func(context.Context) error) error
}

// AnchorWorker anchors each tenant's full audit chain at a known cadence
// (A147). A tenant whose chain grew since its last anchor gets an RFC 3161
// timestamp over its head, recorded as an audit.anchored event in its own
// audit log; the next anchor then covers that record too. A tenant with nothing
// new is left alone — a quiet stretch has nothing to cover — so the series is
// exactly as dense as the activity it attests.
type AnchorWorker struct {
	svc      *audit.Service
	log      *events.Log
	ts       auditanchor.Timestamper
	scopes   AnchorScopes
	tenants  editionseam.AuditTenants
	interval time.Duration
}

// NewAnchorWorker constructs the worker for one cadence.
func NewAnchorWorker(svc *audit.Service, log *events.Log, ts auditanchor.Timestamper, scopes AnchorScopes, tenants editionseam.AuditTenants, interval time.Duration) *AnchorWorker {
	return &AnchorWorker{svc: svc, log: log, ts: ts, scopes: scopes, tenants: tenants, interval: interval}
}

// Interval is the cadence the server runs the worker at.
func (w *AnchorWorker) Interval() time.Duration { return w.interval }

// RunOnce anchors every tenant whose chain grew since its last anchor. It
// stops at the first failure: an authority outage fails every tenant alike, and
// the next pass retries.
func (w *AnchorWorker) RunOnce(ctx context.Context) (editionseam.AuditAnchorSummary, error) {
	var sum editionseam.AuditAnchorSummary
	if w.interval <= 0 {
		return sum, nil
	}
	tenants, err := w.tenants.ListTenants(ctx)
	if err != nil {
		return sum, fmt.Errorf("audit anchoring: list tenants: %w", err)
	}
	for _, tenant := range tenants {
		if err := ctx.Err(); err != nil {
			return sum, err
		}
		anchored, err := w.anchorTenant(ctx, tenant.TenantID)
		if err != nil {
			return sum, fmt.Errorf("audit anchoring: tenant %s: %w", tenant.TenantID, err)
		}
		if anchored {
			sum.TenantsAnchored++
		} else {
			sum.TenantsUnchanged++
		}
	}
	return sum, nil
}

func (w *AnchorWorker) anchorTenant(ctx context.Context, tenantID string) (bool, error) {
	anchored := false
	err := w.scopes.WithAuditRetentionScope(ctx, tenantID, func(scopeCtx context.Context) error {
		position, err := w.svc.ChainHead(scopeCtx, tenantID)
		if err != nil {
			return err
		}
		// Nothing to cover: an empty chain, or no record since the last
		// anchor, whose own record is then the newest.
		if position.Sequence == 0 || position.Type == auditanchor.EventTypeAnchored {
			return nil
		}
		id := "audit-anchor-" + crypto.SHA256Hex([]byte(fmt.Sprintf("%s\x00%d\x00%s", tenantID, position.Sequence, position.Head)))
		if _, found, err := w.log.EventByID(scopeCtx, id); err != nil {
			return fmt.Errorf("find anchor event: %w", err)
		} else if found {
			return nil
		}
		anchor, err := auditanchor.AnchorHead(scopeCtx, w.ts, position.Head)
		if err != nil {
			return err
		}
		if anchor.Kind != auditanchor.KindRFC3161 {
			return errors.New("the timestamp authority returned no timestamp")
		}
		data, err := json.Marshal(auditanchor.AnchoredEvent{
			ThroughSequence: position.Sequence, CadenceSeconds: int64(w.interval / time.Second), Anchor: anchor,
		})
		if err != nil {
			return err
		}
		if _, err := w.log.Append(scopeCtx, events.Event{
			ID: id, Type: auditanchor.EventTypeAnchored, TenantID: tenantID,
			SchemaVersion: auditanchor.AnchoredEventSchemaVersion, Data: data,
		}); err != nil {
			return fmt.Errorf("append anchor event: %w", err)
		}
		anchored = true
		return nil
	})
	return anchored, err
}
