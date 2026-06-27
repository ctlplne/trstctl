package silo

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/tenancy"
)

const (
	TenantActive      = "active"
	TenantSuspended   = "suspended"
	TenantOffboarding = "offboarding"
	TenantDeleted     = "deleted"
)

type Tenant struct {
	ID     string
	Slug   string
	Model  tenancy.IsolationModel
	Status string
}

type Registry interface {
	Snapshot(context.Context) (map[string]Tenant, error)
}

type MemRegistry struct {
	mu      sync.Mutex
	tenants map[string]Tenant
	err     error
}

func NewMemRegistry() *MemRegistry {
	return &MemRegistry{tenants: map[string]Tenant{}}
}

func (m *MemRegistry) Upsert(tenant Tenant) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tenants[tenant.ID] = tenant
}

func (m *MemRegistry) Delete(tenantID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tenants, tenantID)
}

func (m *MemRegistry) Fail(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.err = err
}

func (m *MemRegistry) Snapshot(context.Context) (map[string]Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return nil, m.err
	}
	out := map[string]Tenant{}
	for id, tenant := range m.tenants {
		out[id] = tenant
	}
	return out, nil
}

type Router struct {
	registry Registry
	ttl      time.Duration
	now      func() time.Time

	mu      sync.Mutex
	cache   map[string]Tenant
	fetched time.Time
}

func NewRouter(registry Registry, ttl time.Duration) *Router {
	if ttl <= 0 {
		ttl = 15 * time.Second
	}
	return &Router{registry: registry, ttl: ttl, now: time.Now, cache: map[string]Tenant{}}
}

func (r *Router) Invalidate() {
	r.mu.Lock()
	r.fetched = time.Time{}
	r.mu.Unlock()
}

func (r *Router) TargetsFor(ctx context.Context, tenantID string) (tenancy.Targets, error) {
	snapshot, err := r.load(ctx)
	if err != nil {
		return tenancy.Targets{}, err
	}
	tenant, ok := snapshot[tenantID]
	if !ok || tenant.Model == "" || tenant.Model == tenancy.IsolationPooled {
		return tenancy.Targets{Model: tenancy.IsolationPooled}, nil
	}
	if tenant.Status == TenantOffboarding || tenant.Status == TenantDeleted {
		return tenancy.Targets{Model: tenancy.IsolationPooled}, nil
	}
	if tenant.Model != tenancy.IsolationSiloed && tenant.Model != tenancy.IsolationHybrid {
		return tenancy.Targets{}, errors.New("silo: invalid isolation model")
	}
	targets := tenancy.Targets{
		Model:                tenant.Model,
		JetStreamSubjectLane: SubjectLane(tenant.Slug),
		ObjectKeyPrefix:      ObjectPrefix(tenant.ID),
	}
	if tenant.Model == tenancy.IsolationSiloed {
		targets.PostgresSchema = SchemaName(tenant.ID)
	}
	return targets, nil
}

func (r *Router) JetStreamSubjectLanes(ctx context.Context) ([]string, error) {
	snapshot, err := r.load(ctx)
	if err != nil {
		return nil, err
	}
	lanes := []string{}
	for _, tenant := range snapshot {
		if tenant.Status == TenantOffboarding || tenant.Status == TenantDeleted {
			continue
		}
		if tenant.Model == tenancy.IsolationSiloed || tenant.Model == tenancy.IsolationHybrid {
			lanes = append(lanes, SubjectLane(tenant.Slug))
		}
	}
	sort.Strings(lanes)
	return lanes, nil
}

func (r *Router) load(ctx context.Context) (map[string]Tenant, error) {
	r.mu.Lock()
	if r.registry == nil {
		r.mu.Unlock()
		return map[string]Tenant{}, nil
	}
	if !r.fetched.IsZero() && r.now().Sub(r.fetched) < r.ttl {
		out := cloneSnapshot(r.cache)
		r.mu.Unlock()
		return out, nil
	}
	r.mu.Unlock()

	fresh, err := r.registry.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.cache = cloneSnapshot(fresh)
	r.fetched = r.now()
	out := cloneSnapshot(r.cache)
	r.mu.Unlock()
	return out, nil
}

func cloneSnapshot(in map[string]Tenant) map[string]Tenant {
	out := map[string]Tenant{}
	for id, tenant := range in {
		out[id] = tenant
	}
	return out
}
