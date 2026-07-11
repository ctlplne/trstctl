//go:build trstctl_dodproof

// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"fmt"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// DODOpenBundledStore starts the same bundled PostgreSQL implementation used by
// single-node production, applies core migrations, and returns a bounded cleanup.
func DODOpenBundledStore(ctx context.Context, dataDir string, port int) (*store.Store, func(), error) {
	dsn, stop, err := startBundledPostgres(config.Postgres{Mode: config.PostgresBundled, DataDir: dataDir, Port: port})
	if err != nil {
		return nil, nil, err
	}
	st, err := store.Open(ctx, dsn)
	if err != nil {
		_ = stop()
		return nil, nil, err
	}
	if err := st.Migrate(ctx); err != nil {
		st.Close()
		_ = stop()
		return nil, nil, fmt.Errorf("migrate DOD bundled store: %w", err)
	}
	return st, func() {
		st.Close()
		_ = stop()
	}, nil
}
