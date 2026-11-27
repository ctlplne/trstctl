// SPDX-License-Identifier: BUSL-1.1
package events

import (
	"context"

	"trstctl.com/trstctl/internal/config"
)

func openFixture(ctx context.Context, cfg config.NATS, opts ...OpenOption) (*Log, error) {
	if cfg.Mode == config.NATSExternal {
		cfg.AllowPlaintextDev = true // disposable test brokers do not provide production TLS
	}
	options := make([]OpenOption, 0, len(opts)+1)
	options = append(options, WithFixtureAppendAdmission())
	options = append(options, opts...)
	return Open(ctx, cfg, options...)
}
