// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing

import (
	"context"
	"errors"
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
		for _, d := range deltas {
			if _, err := tx.Exec(ctx,
				`INSERT INTO provider_usage_meters (tenant_id, meter, period_start, kind, value)
				 VALUES ($1, $2, $3, 'counter', $4)
				 ON CONFLICT (tenant_id, meter, period_start)
				 DO UPDATE SET value = provider_usage_meters.value + EXCLUDED.value, updated_at = now()`,
				d.TenantID, d.Meter, d.Period, d.Delta); err != nil {
				return err
			}
			if err := p.widenCoverage(ctx, tx, d.TenantID, d.Period); err != nil {
				return err
			}
		}
		return nil
	})
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
		return p.widenCoverage(ctx, tx, tenantID, period)
	})
}

// widenCoverage records that the store was watching at this instant.
//
// This is what makes evidence signable. Without it, a period with no rows is
// indistinguishable from a period the store was not running for — and the
// second one must never be signed as zero usage.
func (p *PGStore) widenCoverage(ctx context.Context, tx pgx.Tx, tenantID string, at time.Time) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO provider_usage_coverage (tenant_id, observed_from, observed_to)
		 VALUES ($1, $2, $2)
		 ON CONFLICT (tenant_id) DO UPDATE SET
		   observed_from = LEAST(provider_usage_coverage.observed_from, EXCLUDED.observed_from),
		   observed_to   = GREATEST(provider_usage_coverage.observed_to, EXCLUDED.observed_to),
		   updated_at = now()`,
		tenantID, at)
	return err
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
		return tx.QueryRow(ctx,
			`SELECT observed_from, observed_to FROM provider_usage_coverage WHERE tenant_id = $1`,
			tenantID).Scan(&out.ObservedFrom, &out.ObservedTo)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		// No coverage row means the store never observed this customer. Zero
		// times make MaySign refuse, which is the correct answer.
		return Coverage{Durable: true}, nil
	}
	if err != nil {
		return Coverage{}, err
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

// IssuedInPeriod recounts the period's issuances from the identity_transitions
// projection of the event log — the independent record ReconcileEvidence
// checks the meter against. ok is always true here: a durable deployment
// always has the projection, and an empty count is a real zero, not an absent
// source.
func (p *PGStore) IssuedInPeriod(ctx context.Context, tenantID string, from, to time.Time) (int64, bool, error) {
	if p == nil || p.store == nil || tenantID == "" {
		return 0, false, nil
	}
	var n int64
	err := p.tx(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM identity_transitions
			  WHERE tenant_id = $1 AND to_state = 'issued'
			    AND occurred_at >= $2 AND occurred_at < $3`,
			tenantID, from, to).Scan(&n)
	})
	if err != nil {
		return 0, false, err
	}
	return n, true, nil
}

// tx runs against the SYSTEM pool, not a tenant context. These meters are the
// provider plane's record of what to bill a customer; a tenant must not be able
// to read or write the meter that bills them, so this deliberately does not go
// through WithTenant.
// tx runs under the TENANT's RLS context. Not the system pool: these tables
// carry tenant_id and are FORCE-RLS, so every write is confined by the same
// policy that confines a read (AN-1).
func (p *PGStore) tx(ctx context.Context, tenantID string, fn func(pgx.Tx) error) error {
	return p.store.WithTenant(ctx, tenantID, fn)
}
