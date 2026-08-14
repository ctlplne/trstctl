// SPDX-License-Identifier: MPL-2.0

package app

import (
	"context"

	"trstctl.com/trstctl/internal/orchestrator"
)

var idem *orchestrator.Idempotency

//trstctl:mutation
func RegisterGood(ctx context.Context, idempotencyKey string) error {
	_, err := orchestrator.ExecuteTenantRegistration(ctx, nil, nil, nil, idem,
		orchestrator.TenantRegistrationCommand{
			Name: "tenant", IdempotencyKey: idempotencyKey,
		})
	return err
}

//trstctl:mutation
func RegisterFixed(ctx context.Context, idempotencyKey string) error { // want "must thread an approved Idempotency-Key value"
	_, err := orchestrator.ExecuteTenantRegistration(ctx, nil, nil, nil, idem,
		orchestrator.TenantRegistrationCommand{
			Name: "tenant", IdempotencyKey: "fixed",
		})
	return err
}

//trstctl:mutation
func RegisterWrongField(ctx context.Context, idempotencyKey string) error { // want "must thread an approved Idempotency-Key value"
	_, err := orchestrator.ExecuteTenantRegistration(ctx, nil, nil, nil, idem,
		orchestrator.TenantRegistrationCommand{
			Name: idempotencyKey, IdempotencyKey: "fixed",
		})
	return err
}

// A same-spelled local function is not the typed orchestrator sink.
func ExecuteTenantRegistration(ctx context.Context, command orchestrator.TenantRegistrationCommand) error {
	return nil
}

//trstctl:mutation
func RegisterLookalike(ctx context.Context, idempotencyKey string) error { // want "must thread an approved Idempotency-Key value"
	return ExecuteTenantRegistration(ctx, orchestrator.TenantRegistrationCommand{
		IdempotencyKey: idempotencyKey,
	})
}
