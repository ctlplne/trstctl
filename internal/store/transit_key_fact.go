// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
)

// A126: transit key lifecycle facts, projected from the transit.key.created and
// transit.key.rotated events (schema 2). Each row names one key version's fact
// by the fact ID the transit service saved with that version's material; the
// key bytes stay in transit_keyrings.

// TransitKeyFact is one projected transit lifecycle fact.
type TransitKeyFact struct {
	TenantID   string
	FactID     string
	KeyName    string
	Kind       string
	Version    int
	EventType  string
	EventSeq   uint64
	RecordedAt time.Time
}

// ApplyTransitKeyFactTx projects one fact. A fact already projected is kept as
// it is, so a replay or a second apply of one event changes nothing.
func (s *Store) ApplyTransitKeyFactTx(ctx context.Context, tx pgx.Tx, f TransitKeyFact) error {
	if f.EventSeq == 0 || f.EventSeq > math.MaxInt64 {
		return errors.New("store: a transit key fact needs its event's stream sequence")
	}
	_, err := tx.Exec(ctx, `INSERT INTO transit_key_facts
		(tenant_id, fact_id, key_name, kind, version, event_type, event_seq, recorded_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (tenant_id, fact_id) DO NOTHING`,
		f.TenantID, f.FactID, f.KeyName, f.Kind, f.Version, f.EventType, int64(f.EventSeq), f.RecordedAt)
	return err
}

// TransitKeyFactsRecorded returns, by fact ID, when each of factIDs was
// recorded for the tenant; an ID the projection lacks is absent.
func (s *Store) TransitKeyFactsRecorded(ctx context.Context, tenantID string, factIDs []string) (map[string]time.Time, error) {
	out := make(map[string]time.Time, len(factIDs))
	if len(factIDs) == 0 {
		return out, nil
	}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT fact_id, recorded_at FROM transit_key_facts
			WHERE tenant_id = $1 AND fact_id = ANY($2)`, tenantID, factIDs)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				id string
				at time.Time
			)
			if err := rows.Scan(&id, &at); err != nil {
				return err
			}
			out[id] = at
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
