//go:build trstctl_dodproof

// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"fmt"
	"os"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

const (
	dodRuntimeTempRootEnv = "TRSTCTL_DOD_RUNTIME_TEMP_ROOT"
	dodRuntimeTempRoot    = "/dod-tmp"
)

// DODOpenBundledStore starts the same bundled PostgreSQL implementation used by
// single-node production, applies core migrations, and returns a bounded cleanup.
func DODOpenBundledStore(ctx context.Context, dataDir string, port int) (*store.Store, func(), error) {
	dataDir, removeDataDir, err := dodPostgresDataDir(dataDir)
	if err != nil {
		return nil, nil, err
	}
	dsn, stop, err := startBundledPostgres(config.Postgres{Mode: config.PostgresBundled, DataDir: dataDir, Port: port})
	if err != nil {
		removeDataDir()
		return nil, nil, err
	}
	st, err := store.Open(ctx, dsn)
	if err != nil {
		_ = stop()
		removeDataDir()
		return nil, nil, err
	}
	if err := st.Migrate(ctx); err != nil {
		st.Close()
		_ = stop()
		removeDataDir()
		return nil, nil, fmt.Errorf("migrate DOD bundled store: %w", err)
	}
	return st, func() {
		st.Close()
		_ = stop()
		removeDataDir()
	}, nil
}

// dodPostgresDataDir keeps Postgres data on the runner's private tmpfs. The
// host-visible /dod-tmp bind mount is required for independently produced proof
// receipts, but Docker Desktop can report files created there as root-owned even
// after the runner drops to the host UID. PostgreSQL correctly refuses such a
// directory. No receipt is stored here, so the database belongs on /tmp.
func dodPostgresDataDir(requested string) (string, func(), error) {
	if os.Getenv(dodRuntimeTempRootEnv) != dodRuntimeTempRoot {
		return requested, func() {}, nil
	}
	dir, err := os.MkdirTemp("/tmp", "trstctl-dod-postgres-")
	if err != nil {
		return "", func() {}, fmt.Errorf("create DOD Postgres tmpfs directory: %w", err)
	}
	return dir, func() { _ = os.RemoveAll(dir) }, nil
}
