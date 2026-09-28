// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	corestore "trstctl.com/trstctl/internal/store"
)

// Durable metering (epic L2).
//
// The in-memory store loses usage on restart SILENTLY, so a provider invoices
// from a figure that is quietly short. This one survives, and — more
// importantly — it records WHAT IT ACTUALLY WATCHED, so MaySign can refuse a
// period the store cannot prove it covered rather than letting a gap read as a
// zero.
//
// Every access runs under the tenant's own RLS context (AN-1). An earlier draft
// put these tables outside the fence on the reasoning that billing is the
// provider's record — the doctor's ISO-1 probe rejected it, and was right: a
// table carrying tenant_id that skips RLS is the shape of an isolation hole.
// What confines this data is RLS plus the served API surface: no route lets a
// tenant alter its own usage. The grant is not the control — trstctl_app is the
// server's role, and no tenant has direct SQL.
type PGStore struct {
	store *corestore.Store
}

// NewPGStore builds the durable metering store.
func NewPGStore(s *corestore.Store) *PGStore { return &PGStore{store: s} }

var _ Store = (*PGStore)(nil)

// AddCounters accumulates deltas. Counters ADD because they are deltas; a
// gauge's value would double-count if it were added, which is why kind is
// stored alongside the value rather than inferred at read time.
func (p *PGStore) AddCounters(ctx context.Context, deltas []CounterDelta) error {
	if p == nil || p.store == nil || len(deltas) == 0 {
		return nil
	}
	byTenant := map[string][]CounterDelta{}
	for _, d := range deltas {
		byTenant[d.TenantID] = append(byTenant[d.TenantID], d)
	}
	for tenantID, group := range byTenant {
		if err := p.addForTenant(ctx, tenantID, group); err != nil {
			return err
		}
	}
	return nil
}

func (p *PGStore) addForTenant(ctx context.Context, tenantID string, deltas []CounterDelta) error {
	return p.tx(ctx, tenantID, func(tx pgx.Tx) error {
		return addCounterRows(ctx, tx, deltas)
	})
}

func addCounterRows(ctx context.Context, tx pgx.Tx, deltas []CounterDelta) error {
	for _, d := range deltas {
		if _, err := tx.Exec(ctx,
			`INSERT INTO provider_usage_meters (tenant_id, meter, period_start, kind, value)
				 VALUES ($1, $2, $3, 'counter', $4)
				 ON CONFLICT (tenant_id, meter, period_start)
				 DO UPDATE SET value = provider_usage_meters.value + EXCLUDED.value, updated_at = now()`,
			d.TenantID, d.Meter, d.Period, d.Delta); err != nil {
			return err
		}
	}
	return nil
}

// SetGauge overwrites. A gauge is a level, not a delta.
func (p *PGStore) SetGauge(ctx context.Context, tenantID, meter string, period time.Time, value int64) error {
	if p == nil || p.store == nil {
		return nil
	}
	return p.tx(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO provider_usage_meters (tenant_id, meter, period_start, kind, value)
			 VALUES ($1, $2, $3, 'gauge', $4)
			 ON CONFLICT (tenant_id, meter, period_start)
			 DO UPDATE SET value = EXCLUDED.value, kind = 'gauge', updated_at = now()`,
			tenantID, meter, period, value); err != nil {
			return err
		}
		return nil
	})
}

// FlushObservedCounters commits one recorder's counters and observed interval
// together. A point write through AddCounters or SetGauge proves no interval.
// PostgreSQL merges overlapping/adjacent ranges but preserves every gap.
func (p *PGStore) FlushObservedCounters(ctx context.Context, tenantID, registration string, from, to time.Time, deltas []CounterDelta) error {
	if p == nil || p.store == nil || tenantID == "" || registration == "" || to.Before(from) {
		return fmt.Errorf("billing: invalid recorder observation interval")
	}
	for _, delta := range deltas {
		if delta.TenantID != tenantID {
			return fmt.Errorf("billing: counter does not belong to observation tenant")
		}
	}
	return p.tx(ctx, tenantID, func(tx pgx.Tx) error {
		current, err := p.observationRegistrationTx(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		if current != registration {
			return errObservationRegistration
		}
		if err := addCounterRows(ctx, tx, deltas); err != nil {
			return err
		}
		if from.IsZero() || to.Equal(from) {
			return nil
		}
		_, err = tx.Exec(ctx,
			`INSERT INTO provider_usage_coverage (tenant_id, observed_from, observed_to, observed_ranges)
			 VALUES ($1, $2, $3, tstzmultirange(tstzrange($2, $3, '[)')))
			 ON CONFLICT (tenant_id) DO UPDATE SET
			   observed_from = LEAST(provider_usage_coverage.observed_from, EXCLUDED.observed_from),
			   observed_to = GREATEST(provider_usage_coverage.observed_to, EXCLUDED.observed_to),
			   observed_ranges = COALESCE(provider_usage_coverage.observed_ranges, '{}'::tstzmultirange) + EXCLUDED.observed_ranges,
			   updated_at = now()`, tenantID, from, to)
		return err
	})
}

// ObservationRegistration identifies the exact live tenant lifecycle before a
// delta enters the recorder's queue. Flush takes the same lifecycle fence and
// checks this identity again, so erasure cannot cross the database write.
func (p *PGStore) ObservationRegistration(ctx context.Context, tenantID string) (string, error) {
	if p == nil || p.store == nil || tenantID == "" {
		return "", errObservationRegistration
	}
	var registration string
	err := p.tx(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		registration, err = p.observationRegistrationTx(ctx, tx, tenantID)
		return err
	})
	return registration, err
}

func (p *PGStore) observationRegistrationTx(ctx context.Context, tx pgx.Tx, tenantID string) (string, error) {
	snapshot, err := p.store.LockLiveTenantRegistrationSnapshotTx(ctx, tx, tenantID)
	if errors.Is(err, corestore.ErrApplicationSecretTenantEpochMismatch) {
		return "", errObservationRegistration
	}
	if err != nil {
		return "", err
	}
	if snapshot.EventSeq > 0 {
		return fmt.Sprintf("event:%d", snapshot.EventSeq), nil
	}
	return fmt.Sprintf("%d/%s/%s", snapshot.EventSeq, snapshot.CreatedAt.UTC().Format(time.RFC3339Nano), snapshot.Name), nil
}

// CoverageFor reports what the store can vouch for, for MaySign.
func (p *PGStore) CoverageFor(ctx context.Context, tenantID string) (Coverage, error) {
	out := Coverage{Durable: true}
	if p == nil || p.store == nil {
		// A nil store is not durable, whatever the type says. Claiming
		// durability here would let MaySign approve evidence nothing backs.
		return Coverage{}, nil
	}
	err := p.tx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT lower(observed), upper(observed)
			 FROM provider_usage_coverage, LATERAL unnest(observed_ranges) AS observed
			 WHERE tenant_id = $1 ORDER BY lower(observed)`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var interval ObservationInterval
			if err := rows.Scan(&interval.From, &interval.To); err != nil {
				return err
			}
			out.Intervals = append(out.Intervals, interval)
		}
		return rows.Err()
	})
	if err != nil {
		return Coverage{}, err
	}
	if len(out.Intervals) > 0 {
		out.ObservedFrom = out.Intervals[0].From
		out.ObservedTo = out.Intervals[len(out.Intervals)-1].To
	}
	return out, nil
}

// Query returns usage records over a window.
func (p *PGStore) Query(ctx context.Context, from, to time.Time, tenantID string) ([]UsageRecord, error) {
	var out []UsageRecord
	if p == nil || p.store == nil {
		return nil, nil
	}
	err := p.tx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_id::text, meter, kind, period_start, value
			   FROM provider_usage_meters
			  WHERE period_start >= $1 AND period_start < $2 AND ($3 = '' OR tenant_id::text = $3)
			  ORDER BY period_start, meter`, from, to, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r UsageRecord
			if err := rows.Scan(&r.TenantID, &r.Meter, &r.Kind, &r.PeriodStart, &r.Value); err != nil {
				return err
			}
			r.PeriodEnd = r.PeriodStart.Add(time.Hour)
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// QuotaFor reads the tenant's durable quota. No row means no limits — the
// zero quota, in which every LimitFor returns nil and creation is unbounded,
// which is the correct default for a customer nobody has capped.
func (p *PGStore) QuotaFor(ctx context.Context, tenantID string) (Quota, error) {
	out := Quota{TenantID: tenantID}
	if p == nil || p.store == nil || tenantID == "" {
		return out, nil
	}
	err := p.tx(ctx, tenantID, func(tx pgx.Tx) error {
		scanErr := tx.QueryRow(ctx,
			`SELECT max_agents, max_tenants, max_certificates_stored, max_secrets_stored, coalesce(updated_by, '')
			   FROM provider_tenant_quotas WHERE tenant_id = $1`, tenantID).
			Scan(&out.MaxAgents, &out.MaxTenants, &out.MaxCertificatesStored, &out.MaxSecretsStored, &out.UpdatedBy)
		if scanErr != nil && scanErr.Error() == pgx.ErrNoRows.Error() {
			return nil
		}
		return scanErr
	})
	return out, err
}

// IssuedInPeriod recounts immutable managed-leaf mint facts. A renewed leaf
// counts once, even though its identity did not enter issued again. Observing
// or revoking that leaf later cannot change its original mint time. Legacy
// receipts without source classification are unknown, not a confirmed zero.
func (p *PGStore) IssuedInPeriod(ctx context.Context, tenantID string, from, to time.Time) (int64, bool, error) {
	if p == nil || p.store == nil || tenantID == "" {
		return 0, false, nil
	}
	var n int64
	var known bool
	err := p.tx(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT
			  (SELECT count(*) FROM (
			    SELECT DISTINCT ON (issuance_fingerprint) issuance_time AS minted_at
			    FROM certificate_metadata_receipts
			    WHERE tenant_id=$1 AND issuance_status='mint'
			    ORDER BY issuance_fingerprint,event_sequence
			  ) mints WHERE minted_at >= $2 AND minted_at < $3),
			  EXISTS (SELECT 1 FROM tenants WHERE tenant_id=$1 AND responder_issuance_history_known IS TRUE)
			  AND NOT EXISTS (SELECT 1 FROM certificate_metadata_receipts
			    WHERE tenant_id=$1 AND (issuance_status IS NULL OR issuance_status='unverifiable'))
			  AND NOT EXISTS (SELECT 1 FROM ca_issued_certs c WHERE c.tenant_id=$1
			    AND (c.issuance_event_id IS NULL OR
			      (c.issuance_event_type <> 'edge.delegation.issued' AND NOT EXISTS (
			        SELECT 1 FROM certificate_metadata_receipts r
			        WHERE r.tenant_id=$1 AND r.event_id=c.issuance_event_id))))`,
			tenantID, from, to).Scan(&n, &known)
	})
	if err != nil {
		return 0, false, err
	}
	return n, known, nil
}

// tx runs under the TENANT's RLS context. Not the system pool: these tables
// carry tenant_id and are FORCE-RLS, so every write is confined by the same
// policy that confines a read (AN-1).
func (p *PGStore) tx(ctx context.Context, tenantID string, fn func(pgx.Tx) error) error {
	return p.store.WithTenant(ctx, tenantID, fn)
}
