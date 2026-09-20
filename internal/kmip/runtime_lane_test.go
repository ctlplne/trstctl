// SPDX-License-Identifier: BUSL-1.1

package kmip

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/server"
)

func kmipLaneTestDeps(bulk *bulkhead.Set) server.KMIPFactoryDeps {
	return server.KMIPFactoryDeps{
		Protocols: config.Protocols{KMIP: config.KMIPProtocol{
			Enabled:      true,
			TenantID:     "11111111-1111-1111-1111-111111111111",
			Addr:         ":0",
			CertFile:     "/nonexistent/kmip.crt",
			KeyFile:      "/nonexistent/kmip.key",
			ClientCAFile: "/nonexistent/kmip-clients.crt",
		}},
		Bulkhead: bulk,
	}
}

// TestFactoryRefusesASetWithoutTheKMIPLane pins the A2/V11 fix: a bulkhead set
// with no kmip lane used to fall back SILENTLY to the shared protocols pool —
// under a comment promising the opposite — which let idle KMIP connections
// starve ACME/EST/SCEP/CMP/SSH/SPIFFE (AN-7). The factory must now refuse
// loudly instead of borrowing a lane other subsystems depend on.
func TestFactoryRefusesASetWithoutTheKMIPLane(t *testing.T) {
	withoutKMIP := bulkhead.NewSet(bulkhead.Config{Name: bulkhead.SubsystemProtocols, Workers: 2, Queue: 8})
	t.Cleanup(withoutKMIP.Close)

	runtime, err := NewFactory()(kmipLaneTestDeps(withoutKMIP))
	if err == nil {
		if runtime != nil {
			if closer, ok := runtime.(interface{ Close() }); ok {
				closer.Close()
			}
		}
		t.Fatal("factory accepted a bulkhead set with no kmip lane; KMIP would run on a pool other subsystems depend on")
	}
	if !strings.Contains(err.Error(), "bulkheads.kmip") {
		t.Fatalf("refusal must name the missing lane so an operator can fix the config, got: %v", err)
	}
}

// TestFactorySelectsTheKMIPLaneWhenPresent proves the refusal above is about
// the missing lane, not the sparse test deps: with the lane present the
// factory advances past pool selection and fails on the NEXT missing
// dependency (the event log), which it names.
func TestFactorySelectsTheKMIPLaneWhenPresent(t *testing.T) {
	withKMIP := bulkhead.NewSet(
		bulkhead.Config{Name: bulkhead.SubsystemProtocols, Workers: 2, Queue: 8},
		bulkhead.Config{Name: bulkhead.SubsystemKMIP, Workers: 2, Queue: 8},
	)
	t.Cleanup(withKMIP.Close)

	runtime, err := NewFactory()(kmipLaneTestDeps(withKMIP))
	if err == nil {
		if runtime != nil {
			if closer, ok := runtime.(interface{ Close() }); ok {
				closer.Close()
			}
		}
		t.Fatal("factory built a runtime with no event log; expected the event-log dependency error")
	}
	if strings.Contains(err.Error(), "bulkheads.kmip") {
		t.Fatalf("factory still complains about the kmip lane although the set has one: %v", err)
	}
	if !strings.Contains(err.Error(), "event log") {
		t.Fatalf("expected the next dependency (event log) to be the failure, got: %v", err)
	}
}
