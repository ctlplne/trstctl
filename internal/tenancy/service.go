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

// Refusal is an ErrServiceUnavailable that knows which condition refused. It
// reads as ErrServiceUnavailable word for word: callers answer with an error's
// text on many surfaces (an enrollment's 403, an agent's PermissionDenied, an
// ACME problem, a SPIFFE status), and every one of them answers the same way
// for every condition. The reason is the server's, read with RefusalReason.
type Refusal struct {
	Reason string
}

// Refused is the refusal for one condition.
func Refused(reason string) error { return &Refusal{Reason: reason} }

func (r *Refusal) Error() string { return ErrServiceUnavailable.Error() }

// Unwrap keeps errors.Is(err, ErrServiceUnavailable) true.
func (r *Refusal) Unwrap() error { return ErrServiceUnavailable }

// RefusalReason names the condition behind a refusal, or "" when err carries
// none.
func RefusalReason(err error) string {
	var r *Refusal
	if errors.As(err, &r) {
		return r.Reason
	}
	return ""
}

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
