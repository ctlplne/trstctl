// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"testing"

	"trstctl.com/trstctl/internal/store"
)

func TestIncidentFailedTargetsRequiresAWorkerFailure(t *testing.T) {
	for _, status := range []string{"queued", "delivered"} {
		if got := incidentFailedTargets(store.ConnectorDeliveryReceipt{
			Connector: "nginx", Target: "edge/prod", Status: status,
		}); len(got) != 0 {
			t.Errorf("%s intent/outcome was presented as a failed target: %#v", status, got)
		}
	}
	if got := incidentFailedTargets(store.ConnectorDeliveryReceipt{
		Connector: "nginx", Target: "edge/prod", Status: "failed",
	}); len(got) != 1 || got[0] != "nginx:edge/prod:failed" {
		t.Fatalf("worker failure targets = %#v, want the failed receiver", got)
	}
}
