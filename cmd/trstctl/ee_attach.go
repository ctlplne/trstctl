//go:build !trstctl_core

package main

import (
	"context"
	"log/slog"

	_ "trstctl.com/trstctl/ee"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/server"
)

// attachEE is the single sanctioned open-core seam. S-E0 attaches no features:
// the table is empty and behavior stays Community. Later cards add exactly one
// lic.Has(feature) block per gated capability here.
func attachEE(context.Context, *config.Config, *slog.Logger, *license.Manager, *server.Deps) error {
	return nil
}
