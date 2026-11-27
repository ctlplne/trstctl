// SPDX-License-Identifier: BUSL-1.1

// Package eventstest composes standalone event-log fixtures for test and
// performance harnesses. It must not be imported by a production server.
package eventstest

import (
	"context"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

// OpenFixture makes the absence of a production ingress adapter explicit.
// A required-production option still makes events.Open refuse this fixture.
func OpenFixture(ctx context.Context, cfg config.NATS, opts ...events.OpenOption) (*events.Log, error) {
	// Tests open disposable external brokers without production credentials.
	// The bypass is explicit here and never appears in the serving constructor.
	if cfg.Mode == config.NATSExternal {
		cfg.AllowPlaintextDev = true
	}
	options := make([]events.OpenOption, 0, len(opts)+1)
	options = append(options, events.WithFixtureAppendAdmission())
	options = append(options, opts...)
	return events.Open(ctx, cfg, options...)
}
