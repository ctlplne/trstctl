// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// DynamicSecretLeaseAccessObserved is what an active lease reaches, as its
// target reported it to the leader's access worker (G2). Status unknown carries
// a closed-set reason and no grants; it never means the login has none.
type DynamicSecretLeaseAccessObserved struct {
	LeaseID    string   `json:"lease_id"`
	Provider   string   `json:"provider"`
	Status     string   `json:"status"`
	TargetKind string   `json:"target_kind,omitempty"`
	TargetRef  string   `json:"target_ref,omitempty"`
	Login      string   `json:"login,omitempty"`
	Grants     []string `json:"grants,omitempty"`
	Truncated  int      `json:"truncated,omitempty"`
	Reason     string   `json:"reason,omitempty"`
}

func init() {
	knownSchemaVersions[EventDynamicSecretLeaseAccessObserved] = map[int]bool{1: true}
}

func (p *Projector) applyDynamicSecretLeaseAccessObservedTx(ctx context.Context, tx pgx.Tx, e events.Event) error {
	var pl DynamicSecretLeaseAccessObserved
	if err := decode(e, &pl); err != nil {
		return err
	}
	switch {
	case pl.LeaseID == "" || pl.Provider == "" || e.Time.IsZero():
		return fmt.Errorf("projections: %s payload is incomplete", e.Type)
	case pl.Status != store.DynamicSecretAccessResolved && pl.Status != store.DynamicSecretAccessUnknown && pl.Status != store.DynamicSecretAccessUnsupported:
		return fmt.Errorf("projections: %s status %q is not a lease access status", e.Type, pl.Status)
	case pl.Status != store.DynamicSecretAccessResolved && (len(pl.Grants) > 0 || pl.Reason == ""):
		return fmt.Errorf("projections: %s %s access carries grants or no reason", e.Type, pl.Status)
	}
	return p.store.ApplyDynamicSecretLeaseAccessTx(ctx, tx, store.DynamicSecretLeaseAccess{
		TenantID: e.TenantID, LeaseID: pl.LeaseID, Provider: pl.Provider, Status: pl.Status,
		TargetKind: pl.TargetKind, TargetRef: pl.TargetRef, Login: pl.Login, Grants: pl.Grants,
		Truncated: pl.Truncated, Reason: pl.Reason, CheckedAt: e.Time,
	}, e.Sequence)
}
