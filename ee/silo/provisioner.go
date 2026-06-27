package silo

import (
	"context"
	"sync"

	"trstctl.com/trstctl/internal/tenancy"
)

type Plane interface {
	EnsurePostgresSchema(ctx context.Context, schema string, ddl []string) error
	EnsureEventLane(ctx context.Context, lane string) error
	EnsureObjectPrefix(ctx context.Context, prefix string) error
	DropPostgresSchema(ctx context.Context, schema string) error
	DropEventLane(ctx context.Context, lane string) error
	DropObjectPrefix(ctx context.Context, prefix string) error
}

type Provisioner struct {
	plane        Plane
	tenantTables []string
}

func NewProvisioner(plane Plane, tenantTables []string) *Provisioner {
	return &Provisioner{plane: plane, tenantTables: append([]string(nil), tenantTables...)}
}

func (p *Provisioner) Provision(ctx context.Context, tenant Tenant) (tenancy.Targets, error) {
	targets := targetsFor(tenant)
	if p == nil || p.plane == nil || tenant.Model == tenancy.IsolationPooled || tenant.Model == "" {
		return targets, nil
	}
	if tenant.Model == tenancy.IsolationSiloed {
		if err := p.plane.EnsurePostgresSchema(ctx, targets.PostgresSchema, ProvisionPlan(targets.PostgresSchema, p.tenantTables)); err != nil {
			return tenancy.Targets{}, err
		}
	}
	if err := p.plane.EnsureEventLane(ctx, targets.JetStreamSubjectLane); err != nil {
		return tenancy.Targets{}, err
	}
	if err := p.plane.EnsureObjectPrefix(ctx, targets.ObjectKeyPrefix); err != nil {
		return tenancy.Targets{}, err
	}
	return targets, nil
}

func (p *Provisioner) Teardown(ctx context.Context, tenant Tenant) error {
	if p == nil || p.plane == nil || tenant.Model == tenancy.IsolationPooled || tenant.Model == "" {
		return nil
	}
	targets := targetsFor(tenant)
	if tenant.Model == tenancy.IsolationSiloed {
		if err := p.plane.DropPostgresSchema(ctx, targets.PostgresSchema); err != nil {
			return err
		}
	}
	if err := p.plane.DropEventLane(ctx, targets.JetStreamSubjectLane); err != nil {
		return err
	}
	return p.plane.DropObjectPrefix(ctx, targets.ObjectKeyPrefix)
}

func targetsFor(tenant Tenant) tenancy.Targets {
	if tenant.Model == "" || tenant.Model == tenancy.IsolationPooled {
		return tenancy.Targets{Model: tenancy.IsolationPooled}
	}
	targets := tenancy.Targets{
		Model:                tenant.Model,
		JetStreamSubjectLane: SubjectLane(tenant.Slug),
		ObjectKeyPrefix:      ObjectPrefix(tenant.ID),
	}
	if tenant.Model == tenancy.IsolationSiloed {
		targets.PostgresSchema = SchemaName(tenant.ID)
	}
	return targets
}

type MemPlane struct {
	mu       sync.Mutex
	schemas  map[string][]string
	ensures  map[string]int
	lanes    map[string]bool
	prefixes map[string]bool
}

func NewMemPlane() *MemPlane {
	return &MemPlane{
		schemas:  map[string][]string{},
		ensures:  map[string]int{},
		lanes:    map[string]bool{},
		prefixes: map[string]bool{},
	}
}

func (p *MemPlane) EnsurePostgresSchema(_ context.Context, schema string, ddl []string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.schemas[schema]; !ok {
		p.schemas[schema] = append([]string(nil), ddl...)
		p.ensures[schema]++
	}
	return nil
}

func (p *MemPlane) EnsureEventLane(_ context.Context, lane string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lanes[lane] = true
	return nil
}

func (p *MemPlane) EnsureObjectPrefix(_ context.Context, prefix string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.prefixes[prefix] = true
	return nil
}

func (p *MemPlane) DropPostgresSchema(_ context.Context, schema string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.schemas, schema)
	return nil
}

func (p *MemPlane) DropEventLane(_ context.Context, lane string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.lanes, lane)
	return nil
}

func (p *MemPlane) DropObjectPrefix(_ context.Context, prefix string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.prefixes, prefix)
	return nil
}

func (p *MemPlane) HasSchema(schema string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.schemas[schema]
	return ok
}

func (p *MemPlane) HasEventLane(lane string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lanes[lane]
}

func (p *MemPlane) HasObjectPrefix(prefix string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.prefixes[prefix]
}

func (p *MemPlane) EnsureCount(schema string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ensures[schema]
}

func (p *MemPlane) SchemaDDL(schema string) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.schemas[schema]...)
}
