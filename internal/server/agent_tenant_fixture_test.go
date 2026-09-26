// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// Operating-tenant tests opt into real registration explicitly. Keep the base
// fixture empty for installation, missing-tenant and erasure behavior tests.
func newOperatingServedHarness(t *testing.T, protocols config.Protocols, opts ...func(*Deps)) *servedHarness {
	t.Helper()
	h := newServedHarness(t, protocols, opts...)
	registerServedTenant(t, h, "Operating tenant fixture")
	return h
}

// Successful-agent fixtures provision a real tenant before enrollment. The base
// harness stays empty so cold-start and missing-registration tests remain real.
// Never resurrect an erased tenant as a side effect of obtaining a test client.
func prepareServedAgentTenant(t *testing.T, h *servedHarness) {
	t.Helper()
	if _, err := h.store.GetTenant(t.Context(), h.tenant); err == nil {
		return
	} else if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal(err)
	}
	hadRegistration := false
	if err := h.log.Replay(t.Context(), 0, func(e events.Event) error {
		if e.TenantID == h.tenant && (e.Type == projections.EventTenantRegistered || e.Type == projections.EventTenantOffboarded) {
			hadRegistration = true
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if hadRegistration {
		t.Fatal("agent fixture requires explicit tenant recovery or re-registration; refusing to recreate retained tenant history")
	}
	registerServedTenant(t, h, "Agent fixture")
}
