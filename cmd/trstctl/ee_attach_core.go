// SPDX-License-Identifier: BUSL-1.1

//go:build trstctl_core

package main

import (
	"context"
	"io"
	"log/slog"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/server"
	"trstctl.com/trstctl/internal/store"
)

// eeLocalCommand is the core-only twin: the core build has no EE subcommands.
func eeLocalCommand(context.Context, []string, func(string) string, io.Writer, io.Writer) (bool, error) {
	return false, nil
}

// attachEE is the core-only no-op twin. The trstctl_core build links this file
// instead of ee_attach.go, proving core stands alone with zero ee/ packages.
func attachEE(_ context.Context, cfg *config.Config, _ *slog.Logger, _ *license.Manager, deps *server.Deps) error {
	return requireTenantAuthAttachment(cfg, deps)
}

func attachEEProjectionOptions(
	context.Context,
	*config.Config,
	*license.Manager,
	*store.Store,
	*events.Log,
) ([]projections.Option, error) {
	return nil, nil
}
