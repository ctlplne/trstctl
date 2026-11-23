// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"trstctl.com/trstctl/internal/buildinfo"
)

func TestEveryStorePoolLabelsLiveConnectionsWithBuildVersion(t *testing.T) {
	dsn := os.Getenv("TRSTCTL_STORE_TEST_DSN")
	if dsn == "" {
		t.Fatal("store TestMain did not configure the embedded PostgreSQL fixture")
	}
	s, err := Open(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for name, pool := range map[string]*pgxpool.Pool{
		"request": s.pool, "probe": s.probePool, "reserved": s.reservedPool,
		"bookkeeping": s.bookkeepingPool, "lock": s.lockPool, "restore": s.restorePool,
	} {
		var label string
		if err := pool.QueryRow(t.Context(), `SELECT current_setting('application_name')`).Scan(&label); err != nil {
			t.Fatalf("%s pool: %v", name, err)
		}
		if !strings.HasPrefix(label, "trstctl/") ||
			!strings.Contains(label, buildinfo.Version()) ||
			!strings.Contains(label, buildinfo.Commit()) {
			t.Errorf("%s pool application_name=%q lacks build version %q and commit %q",
				name, label, buildinfo.Version(), buildinfo.Commit())
		}
	}
}
