// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/secrets"
	"trstctl.com/trstctl/internal/store"
)

// openConfiguredEventSourceFixture gives an event-producing integration test
// its own deployment key and the same tenant-custody core production attaches
// before opening the source. Read-only and missing-custody tests use the
// ordinary constructor directly.
func openConfiguredEventSourceFixture(t *testing.T, cfg *config.Config, st *store.Store,
	key *jose.SigningKey, sanitized bool, backupRoots []string,
	extra ...events.OpenOption,
) (*events.Log, *eventProtectionRuntime, error) {
	t.Helper()
	deployment, err := secrets.LoadOrCreateKEK(cfg.Secrets.KEKFile)
	if err != nil {
		return nil, nil, err
	}
	t.Cleanup(deployment.Destroy)
	core, err := newRunTenantCustodyCore(cfg, st, deployment, nil)
	if err != nil {
		return nil, nil, err
	}
	return openConfiguredEventSourceWithCustody(t.Context(), cfg, st, key, sanitized, backupRoots, core, extra...)
}
