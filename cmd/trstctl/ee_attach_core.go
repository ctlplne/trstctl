// SPDX-License-Identifier: MPL-2.0

//go:build trstctl_core

package main

import (
	"context"
	"io"
	"io/fs"
	"log/slog"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/server"
)

func extraMigrationSources() []fs.FS { return nil }

// eeLocalCommand is the core-only twin: the core build has no EE subcommands.
func eeLocalCommand(context.Context, []string, func(string) string, io.Writer, io.Writer) (bool, error) {
	return false, nil
}

// attachEE is the core-only no-op twin. The trstctl_core build links this file
// instead of ee_attach.go, proving core stands alone with zero ee/ packages.
func attachEE(context.Context, *config.Config, *slog.Logger, *license.Manager, *server.Deps) error {
	return nil
}
