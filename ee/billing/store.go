// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

type recordKey struct {
	tenant string
	meter  string
	period time.Time
}

type MemStore struct {
	mu      sync.Mutex
	records map[recordKey]*UsageRecord
	quotas  map[string]Quota
	slugs   map[string]string
	failAdd bool
}

func NewMemStore() *MemStore {
	return &MemStore{records: map[recordKey]*UsageRecord{}, quotas: map[string]Quota{}, slugs: map[string]string{}}
}

func (m *MemStore) SetSlug(tenantID, slug string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.slugs[tenantID] = slug
}

func (m *MemStore) FailNextAdd() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failAdd = true
}

func (m *MemStore) AddCounters(_ context.Context, deltas []CounterDelta) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failAdd {
		m.failAdd = false
		return errors.New("billing: forced counter write failure")
	}
	for _, delta := range deltas {
		if delta.TenantID == "" || delta.Meter == "" || delta.Delta <= 0 {
			continue
		}
		period := PeriodStart(delta.Period)
		k := recordKey{tenant: delta.TenantID, meter: delta.Meter, period: period}
		if record, ok := m.records[k]; ok {
			record.Value += delta.Delta
			continue
		}
		m.records[k] = &UsageRecord{
			TenantID:    delta.TenantID,
			TenantSlug:  m.slugLocked(delta.TenantID),
			Meter:       delta.Meter,
			Kind:        KindCounter,
			PeriodStart: period,
			PeriodEnd:   period.Add(Period),
			Value:       delta.Delta,
			Unit:        MeterUnit(delta.Meter),
		}
	}
	return nil
}

func (m *MemStore) SetGauge(_ context.Context, tenantID, meter string, period time.Time, value int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if tenantID == "" || meter == "" {
		return nil
	}
	period = PeriodStart(period)
	k := recordKey{tenant: tenantID, meter: meter, period: period}
	m.records[k] = &UsageRecord{
		TenantID:    tenantID,
		TenantSlug:  m.slugLocked(tenantID),
		Meter:       meter,
		Kind:        KindGauge,
		PeriodStart: period,
		PeriodEnd:   period.Add(Period),
		Value:       value,
		Unit:        MeterUnit(meter),
	}
	return nil
}

// CoverageFor makes MemStore an EvidenceReader so the evidence route is served
// even without a database — and always answers NOT DURABLE.
//
// The alternative was to leave the route unmounted on an in-memory install,
// which returns 404: "this feature does not exist" for a deployment that IS
// metering, just into memory. The operator needs to be told the difference
// between no metering and metering that cannot be billed from, and only a
// served document with signable=false and a reason says that.
func (m *MemStore) CoverageFor(context.Context, string) (Coverage, error) {
	return Coverage{Durable: false}, nil
}

func (m *MemStore) Query(_ context.Context, from, to time.Time, tenantID string) ([]UsageRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []UsageRecord{}
	for _, record := range m.records {
		if record.PeriodStart.Before(from) || !record.PeriodStart.Before(to) {
			continue
		}
		if tenantID != "" && record.TenantID != tenantID {
			continue
		}
		out = append(out, *record)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.TenantSlug != b.TenantSlug {
			return a.TenantSlug < b.TenantSlug
		}
		if a.Meter != b.Meter {
			return a.Meter < b.Meter
		}
		return a.PeriodStart.Before(b.PeriodStart)
	})
	return out, nil
}

func (m *MemStore) QuotaFor(_ context.Context, tenantID string) (Quota, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if quota, ok := m.quotas[tenantID]; ok {
		return quota, nil
	}
	return Quota{TenantID: tenantID}, nil
}

func (m *MemStore) SetQuota(_ context.Context, quota Quota) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.quotas[quota.TenantID] = quota
	return nil
}

func (m *MemStore) slugLocked(tenantID string) string {
	if slug, ok := m.slugs[tenantID]; ok {
		return slug
	}
	return tenantID
}
