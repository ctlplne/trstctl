// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/orchestrator"
)

func TestConnectorPluginDeployerFromManagerPreservesNil(t *testing.T) {
	var manager *PluginManager
	if got := connectorPluginDeployerFromManager(manager); got != nil {
		t.Fatalf("nil plugin manager became a non-nil interface of type %T", got)
	}
}

func TestUnconfiguredConnectorPluginSurfaceFailsClosedWithoutPanic(t *testing.T) {
	dispatcher := &issuanceDispatcher{
		idem:    orchestrator.NewMemoryIdempotency(),
		plugins: connectorPluginDeployerFromManager(nil),
	}
	err := dispatcher.Deliver(context.Background(),
		connectorDeployTestMessage(t, "not-loaded", "unconfigured-plugin-surface"))
	if err == nil || !strings.Contains(err.Error(), "plugin surface is not configured") {
		t.Fatalf("unconfigured plugin delivery error = %v, want fail-closed configuration error", err)
	}
}
