// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/observ"
	"trstctl.com/trstctl/internal/orchestrator"
)

func TestOutboxMetricLabelsUseBoundedDestinationFamilies(t *testing.T) {
	registry := observ.NewRegistry()
	s := &Server{
		mOutboxDeliveryTimeouts:   registry.CounterVec("trstctl_outbox_delivery_timeouts_total", "test", []string{"destination"}),
		mOutboxCircuitTransitions: registry.CounterVec("trstctl_outbox_circuit_transitions_total", "test", []string{"destination", "from", "to"}),
	}
	s.recordOutboxDeliveryTimeoutMetric("managedkey.command:private-coordinate")
	s.recordOutboxDeliveryTimeoutMetric("custom.private-coordinate")
	s.recordOutboxCircuitTransitionMetric(orchestrator.CircuitTransition{
		Destination: "managedkey.command", Lane: "managedkey.command:private-coordinate",
		From: orchestrator.CircuitClosed, To: orchestrator.CircuitOpen,
	})
	var output strings.Builder
	if err := registry.WriteProm(&output); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`trstctl_outbox_delivery_timeouts_total{destination="managedkey"} 1`,
		`trstctl_outbox_delivery_timeouts_total{destination="other"} 1`,
		`trstctl_outbox_circuit_transitions_total{destination="managedkey",from="closed",to="open"} 1`,
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("metrics missing %q: %s", want, output.String())
		}
	}
	if strings.Contains(output.String(), "private-coordinate") {
		t.Fatal("metrics retained a receiver coordinate")
	}
}
