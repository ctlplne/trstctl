// SPDX-License-Identifier: BUSL-1.1

package tenancy

import (
	"context"
	"errors"
)

// ErrServiceUnavailable means authenticated work belongs to a paused or retired
// tenant. It is separate from a storage outage: neither permits new work, but
// callers must not report an infrastructure failure as an authorization decision.
var ErrServiceUnavailable = errors.New("tenant service is suspended or offboarded")

// ServiceCheck is a feature-neutral request-time tenant admission policy. Core
// has no Provider status or license logic; the composition root installs that
// policy where applicable. It must consult current authority, not token claims.
// This is an admission check, not proof that an already-started remote call has
// stopped. Quiescence and erasure need their own receiver evidence.
type ServiceCheck func(context.Context, string) error

// ServiceWork brackets one operation after its tenant is authenticated. The
// server supplies the database-backed implementation; standalone authorities
// may omit it. Release must follow all effects and result recording.
type ServiceWork func(context.Context, string) (context.Context, func(), error)

func (work ServiceWork) Begin(ctx context.Context, tenantID string) (context.Context, func(), error) {
	if work == nil {
		return ctx, func() {}, nil
	}
	fenced, release, err := work(ctx, tenantID)
	if err != nil || fenced == nil || release == nil {
		if release != nil {
			release()
		}
		if err == nil {
			err = errors.New("tenant work lifetime is incomplete")
		}
		return ctx, nil, err
	}
	return fenced, release, nil
}

func (check ServiceCheck) Check(ctx context.Context, tenantID string) error {
	if check == nil {
		return nil
	}
	if tenantID == "" {
		return ErrServiceUnavailable
	}
	return check(ctx, tenantID)
}
