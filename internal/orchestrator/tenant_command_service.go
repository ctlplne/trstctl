// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/tenancy"
)

type tenantCommandService struct {
	work  tenancy.ServiceWork
	check tenancy.ServiceCheck
}

// withTenantCommand keeps the same admission around command families that
// append, project and enqueue their own side effects in one SQL transaction.
// The callback receives the fenced context so nested signing/projection work
// reuses the admitted operation rather than allocating a conflicting lease.
func (o *Orchestrator) withTenantCommand(ctx context.Context, tenantID string, fn func(context.Context, pgx.Tx) error) error {
	fenced, release, err := o.beginTenantCommand(ctx, tenantID)
	if err != nil {
		return err
	}
	defer release()
	return o.store.WithTenant(fenced, tenantID, func(tx pgx.Tx) error {
		return fn(fenced, tx)
	})
}

// WithTenantCommandService supplies the served command writer's admission and
// operation lifetime. It also covers background callers that bypass the HTTP
// middleware. Standalone recovery orchestrators retain their explicit scope.
func WithTenantCommandService(work tenancy.ServiceWork, check tenancy.ServiceCheck) OrchestratorOption {
	return func(o *Orchestrator) {
		o.tenantCommandService = &tenantCommandService{work: work, check: check}
	}
}

func (o *Orchestrator) beginTenantCommand(ctx context.Context, tenantID string) (context.Context, func(), error) {
	service := o.tenantCommandService
	if service == nil {
		return ctx, func() {}, nil
	}
	if service.work == nil || service.check == nil {
		return ctx, nil, errors.New("orchestrator: tenant command admission is incomplete")
	}
	fenced, release, err := service.work.Begin(ctx, tenantID)
	if err != nil {
		return ctx, nil, err
	}
	if err := service.check.Check(fenced, tenantID); err != nil {
		release()
		return ctx, nil, err
	}
	return fenced, release, nil
}
