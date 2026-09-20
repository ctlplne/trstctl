// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/store"
)

func TestDiscoveryErrorResponsesSanitizeHistoricalRowsAUD71(t *testing.T) {
	t.Parallel()
	secret := "trst_" + strings.Repeat("s", 64)
	raw := "CT get-sth returned 503; Authorization: Bearer " + secret

	run := toDiscoveryRunResponse(store.DiscoveryRun{Error: raw})
	if !strings.Contains(run.Error, "503") || strings.Contains(run.Error, secret) {
		t.Fatalf("run error is not safely actionable: %q", run.Error)
	}

	monitoring := toDiscoveryMonitoringSource(store.DiscoveryMonitoringSource{LastRunError: raw})
	if !strings.Contains(monitoring.LastRunError, "503") || strings.Contains(monitoring.LastRunError, secret) {
		t.Fatalf("monitoring error is not safely actionable: %q", monitoring.LastRunError)
	}
}
