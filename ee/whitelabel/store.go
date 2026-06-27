package whitelabel

import (
	"context"
	"sync"

	"trstctl.com/trstctl/internal/branding"
)

type MemStore struct {
	mu       sync.Mutex
	tenants  map[string]Record
	byDomain map[string]string
	master   *Record
	fail     bool
}

func NewMemStore() *MemStore {
	return &MemStore{tenants: map[string]Record{}, byDomain: map[string]string{}}
}

func (m *MemStore) FailAll(fail bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fail = fail
}

func (m *MemStore) TenantBrand(_ context.Context, tenantID string) (*Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return nil, context.DeadlineExceeded
	}
	if record, ok := m.tenants[tenantID]; ok {
		return cloneRecord(&record), nil
	}
	return nil, nil
}

func (m *MemStore) TenantByDomain(_ context.Context, host string) (*Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return nil, context.DeadlineExceeded
	}
	tenantID, ok := m.byDomain[branding.NormalizeHost(host)]
	if !ok {
		return nil, nil
	}
	record, ok := m.tenants[tenantID]
	if !ok {
		return nil, nil
	}
	return cloneRecord(&record), nil
}

func (m *MemStore) ProviderBrand(context.Context) (*Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return nil, context.DeadlineExceeded
	}
	return cloneRecord(m.master), nil
}

func (m *MemStore) SetTenantBrand(_ context.Context, record Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for host, tenantID := range m.byDomain {
		if tenantID == record.TenantID {
			delete(m.byDomain, host)
		}
	}
	record.CustomDomain = branding.NormalizeHost(record.CustomDomain)
	if record.CustomDomain != "" {
		m.byDomain[record.CustomDomain] = record.TenantID
	}
	m.tenants[record.TenantID] = *cloneRecord(&record)
	return nil
}

func (m *MemStore) SetProviderBrand(_ context.Context, record Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	record.TenantID = ""
	m.master = cloneRecord(&record)
	return nil
}
