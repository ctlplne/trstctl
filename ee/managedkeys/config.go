// SPDX-License-Identifier: LicenseRef-trstctl-EE

package managedkeys

import (
	"context"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/egress"
	"trstctl.com/trstctl/internal/server"
)

// FactoryFromConfig is retained as a source-compatible composition helper. It
// deliberately does not construct or receive a KMS/HSM backend: provider
// construction moved into cmd/trstctl-signer and every external action is
// reached through the durable managedkey.command outbox worker.
func FactoryFromConfig(_ context.Context, cfg config.ManagedKeys, _ *egress.Guard) (server.ManagedKeyServiceFactory, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	return NewDurableFactory(cfg.Provider), nil
}
