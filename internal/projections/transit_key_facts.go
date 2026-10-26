// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/transit"
)

// TransitKeyFact is the schema-2 payload of transit.key.created and
// transit.key.rotated (A126): the key, its kind and the version. The event's ID
// is the fact ID the transit service saved with the version's material.
type TransitKeyFact struct {
	Key     string `json:"key"`
	Kind    string `json:"kind"`
	Version int    `json:"version"`
}

// applyTransitKeyFactTx projects a transit lifecycle fact. A schema-1 event
// is the earlier audit record, which named only the key and could precede a
// save that failed, so it projects nothing; reconcile records those versions'
// facts afresh.
func (p *Projector) applyTransitKeyFactTx(ctx context.Context, tx pgx.Tx, e events.Event) error {
	if schemaVersionOf(e) < transit.FactSchemaVersion {
		return nil
	}
	var pl TransitKeyFact
	if err := decode(e, &pl); err != nil {
		return err
	}
	if !transit.ValidFactID(e.ID) || e.Time.IsZero() || e.Sequence == 0 {
		return fmt.Errorf("projections: %s requires its fact ID as the event ID, a time and a stream sequence", e.Type)
	}
	switch transit.Kind(pl.Kind) {
	case transit.KindAEAD, transit.KindHMAC, transit.KindSign:
	default:
		return fmt.Errorf("projections: %s has unknown key kind %q", e.Type, pl.Kind)
	}
	fact := transit.Fact{ID: e.ID, Key: pl.Key, Kind: transit.Kind(pl.Kind), Version: pl.Version}
	if pl.Key == "" || pl.Version < 1 || fact.EventType() != e.Type {
		return fmt.Errorf("projections: %s needs a key and a version that matches the event (%d)", e.Type, pl.Version)
	}
	return p.store.ApplyTransitKeyFactTx(ctx, tx, store.TransitKeyFact{
		TenantID: e.TenantID, FactID: e.ID, KeyName: pl.Key, Kind: pl.Kind, Version: pl.Version,
		EventType: e.Type, EventSeq: e.Sequence, RecordedAt: e.Time,
	})
}
