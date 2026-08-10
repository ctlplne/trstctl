// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package billing implements Provider-tier metering, quota checks, and export.
package billing

import (
	"context"
	"time"

	"trstctl.com/trstctl/internal/usage"
)

const (
	KindCounter = "counter"
	KindGauge   = "gauge"
)

const (
	Period     = time.Hour
	RollupHour = "hour"
	RollupDay  = "day"
)

func PeriodStart(t time.Time) time.Time {
	return t.UTC().Truncate(Period)
}

func MeterKind(meter string) string {
	switch meter {
	case usage.MeterAgents, usage.MeterTenants, usage.MeterCertificatesStored, usage.MeterSecretsStored:
		return KindGauge
	default:
		return KindCounter
	}
}

func MeterUnit(string) string {
	return "count"
}

func Meters() []string {
	return []string{
		usage.MeterCertificatesIssued,
		usage.MeterCertificatesStored,
		usage.MeterSecretsStored,
		usage.MeterAgents,
		usage.MeterTenants,
	}
}

type UsageRecord struct {
	TenantID    string    `json:"tenant_id"`
	TenantSlug  string    `json:"tenant_slug"`
	Meter       string    `json:"meter"`
	Kind        string    `json:"kind"`
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
	Value       int64     `json:"value"`
	Unit        string    `json:"unit"`
}

type CounterDelta struct {
	TenantID string
	Meter    string
	Period   time.Time
	Delta    int64
}

// TenantCounts are resource counts read inside one tenant's scope.
type TenantCounts map[string]int64

type Quota struct {
	TenantID              string `json:"tenant_id"`
	MaxAgents             *int   `json:"max_agents,omitempty"`
	MaxTenants            *int   `json:"max_tenants,omitempty"`
	MaxCertificatesStored *int   `json:"max_certificates_stored,omitempty"`
	MaxSecretsStored      *int   `json:"max_secrets_stored,omitempty"`
	UpdatedBy             string `json:"updated_by,omitempty"`
}

func (q Quota) LimitFor(resource string) *int {
	switch resource {
	case usage.MeterAgents:
		return q.MaxAgents
	case usage.MeterTenants:
		return q.MaxTenants
	case usage.MeterCertificatesStored:
		return q.MaxCertificatesStored
	case usage.MeterSecretsStored:
		return q.MaxSecretsStored
	default:
		return nil
	}
}

type Store interface {
	AddCounters(ctx context.Context, deltas []CounterDelta) error
	SetGauge(ctx context.Context, tenantID, meter string, period time.Time, value int64) error
	Query(ctx context.Context, from, to time.Time, tenantID string) ([]UsageRecord, error)
	QuotaFor(ctx context.Context, tenantID string) (Quota, error)
}

func Rollup(records []UsageRecord, granularity string) []UsageRecord {
	if granularity != RollupDay {
		return records
	}
	type key struct {
		tenant string
		meter  string
		day    time.Time
	}
	agg := map[key]*UsageRecord{}
	order := []key{}
	for _, record := range records {
		day := record.PeriodStart.UTC().Truncate(24 * time.Hour)
		k := key{tenant: record.TenantID, meter: record.Meter, day: day}
		cur, ok := agg[k]
		if !ok {
			cp := record
			cp.PeriodStart = day
			cp.PeriodEnd = day.Add(24 * time.Hour)
			agg[k] = &cp
			order = append(order, k)
			continue
		}
		if record.Kind == KindGauge {
			if record.Value > cur.Value {
				cur.Value = record.Value
			}
		} else {
			cur.Value += record.Value
		}
	}
	out := make([]UsageRecord, 0, len(order))
	for _, k := range order {
		out = append(out, *agg[k])
	}
	return out
}
