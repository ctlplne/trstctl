// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"strings"

	"trstctl.com/trstctl/internal/orchestrator"
)

// outboxMetricDestination folds configured destinations into a closed set of
// families. Exact receiver coordinates remain in tenant-scoped circuit status.
func outboxMetricDestination(destination string) string {
	family, _, _ := strings.Cut(destination, ".")
	family, _, _ = strings.Cut(family, ":")
	switch family {
	case "agent", "audit", "billing", "ca", "cmdb", "codesign", "connector",
		"discovery", "dynsecret", "endpoint", "eventprivacy", "external-ca",
		"federation", "managedkey", "notification", "pam", "pcas", "pqc",
		"revocation", "secret", "secrets", "ssh", "ticket", "tsa", "vault",
		"webhook", "workload":
		return family
	default:
		return "other"
	}
}

func (s *Server) recordOutboxDeliveryTimeoutMetric(destination string) {
	if s.mOutboxDeliveryTimeouts != nil {
		s.mOutboxDeliveryTimeouts.WithLabelValues(outboxMetricDestination(destination)).Inc()
	}
}

func (s *Server) recordOutboxCircuitTransitionMetric(transition orchestrator.CircuitTransition) {
	if s.mOutboxCircuitTransitions != nil {
		s.mOutboxCircuitTransitions.WithLabelValues(outboxMetricDestination(transition.Destination),
			string(transition.From), string(transition.To)).Inc()
	}
}
