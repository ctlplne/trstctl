// SPDX-License-Identifier: LicenseRef-trstctl-EE

package orchestrator

import (
	"context"
	"testing"

	agidapi "trstctl.com/trstctl/ee/agentid/api"
	"trstctl.com/trstctl/ee/agentid/revoke"
	coreorch "trstctl.com/trstctl/internal/orchestrator"
)

// TestDestinations_MatchAPI asserts the worker drains exactly the destinations the API
// enqueues, and the cascade job destinations it re-exports. A drift would silently break a
// journey (an enqueued message no handler drains).
func TestDestinations_MatchAPI(t *testing.T) {
	if IssuanceRequestDestination != agidapi.IssuanceRequestDestination {
		t.Errorf("IssuanceRequestDestination %q != API %q", IssuanceRequestDestination, agidapi.IssuanceRequestDestination)
	}
	if RevocationDirectiveDestination != agidapi.RevocationDirectiveDestination {
		t.Errorf("RevocationDirectiveDestination %q != API %q", RevocationDirectiveDestination, agidapi.RevocationDirectiveDestination)
	}
	if RevocationJobDestination != revoke.DestinationRevocationJob {
		t.Errorf("RevocationJobDestination %q != revoke %q", RevocationJobDestination, revoke.DestinationRevocationJob)
	}
	if DownstreamPlaneDestination != revoke.DestinationDownstreamPlane {
		t.Errorf("DownstreamPlaneDestination %q != revoke %q", DownstreamPlaneDestination, revoke.DestinationDownstreamPlane)
	}
}

// TestDeliverLicensed_UnknownPassThrough asserts the composed handler returns handled=false
// (no error) for a non-AGID destination, so the chained handler in cmd/trstctl can try the
// next edition's handler. This path does not touch the workers, so it needs no substrate.
func TestDeliverLicensed_UnknownPassThrough(t *testing.T) {
	h := &handler{}
	handled, err := h.DeliverLicensed(context.Background(), coreorch.Message{Destination: "some.other.feature.job"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if handled {
		t.Fatalf("handled = true for a non-AGID destination, want false (pass-through)")
	}
}

// TestDeliverLicensed_DownstreamAck asserts the downstream-plane destination is a
// successful ack (handled=true, nil error) so the outbox row marks delivered — the
// downstream trust plane consumes the KRL/CRL entry, mirroring PCAS's pcas.rp-publish ack.
func TestDeliverLicensed_DownstreamAck(t *testing.T) {
	h := &handler{}
	handled, err := h.DeliverLicensed(context.Background(), coreorch.Message{Destination: DownstreamPlaneDestination})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !handled {
		t.Fatalf("handled = false for the downstream-plane ack, want true")
	}
}
