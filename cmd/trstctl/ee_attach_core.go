//go:build trstctl_core

package main

import (
	"context"
	"log/slog"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/server"
)

// attachEE is the core-only no-op twin. The trstctl_core build links this file
// instead of ee_attach.go, proving core stands alone with zero ee/ packages.
func attachEE(context.Context, *config.Config, *slog.Logger, *license.Manager, *server.Deps) error {
	return nil
}
