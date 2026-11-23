// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"io"
	"log/slog"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/storetest"
)

func TestOpenMigratedStoreCarriesVerifiedRewrapFleetCutover(t *testing.T) {
	admin := newServerTestStore(t)
	fixture := storetest.ProvisionRewrapCutover(t, admin, serverTestPostgresDSN(t))
	cfg := &config.Config{Postgres: config.Postgres{
		Mode: config.PostgresExternal, DSN: fixture.DSN,
		RewrapOldLoginRole:           fixture.Cutover.OldLoginRole,
		RewrapNewLoginRole:           fixture.Cutover.NewLoginRole,
		RewrapMaintenanceAttestation: fixture.Cutover.MaintenanceAttestation,
	}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s, stop, err := openMigratedStore(t.Context(), cfg, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	if stop != nil {
		t.Cleanup(func() { _ = stop() })
	}
	t.Cleanup(s.Close)
	const tenantID = "49900000-0000-4000-8000-0000000000ca"
	if err := s.UpsertTenant(t.Context(), store.Tenant{TenantID: tenantID, Name: "cutover config fixture"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplicationSecretTenantEpoch(t.Context(), tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BeginTenantApplicationSecretRewrap(t.Context(), tenantID, "migrate"); err != nil {
		t.Fatalf("runtime config did not carry the verified login cutover: %v", err)
	}
}
