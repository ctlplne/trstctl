// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/json"

	"trstctl.com/trstctl/internal/connector"
)

// Per-row claim demands for connector work (epic A3).
//
// A2 could only gate agent claims per job KIND, and connector.deploy is
// legitimately both roles' work — which role a given deploy needs is a property
// of the TARGET. The enqueue path is the one moment the control plane holds the
// unsealed payload and knows the connector name, so that is where the demand is
// classified and stamped onto the outbox row; the claim SQL then filters on a
// plain column instead of decoding a sealed payload.

// agentRoleForVantage maps the census's answer about where work executes onto
// the claim vocabulary stored in outbox.required_agent_role.
func agentRoleForVantage(v connector.TargetVantage) string {
	switch v {
	case connector.VantageHostAgent:
		return "host"
	case connector.VantageNetworkRelay:
		return "network"
	default:
		// Control-plane vantage — including everything undeclared — stamps a
		// value that matches no agent role, so the row is never agent-claimable.
		// This is deliberately NOT the empty string: empty means "kind-level
		// rules only", and a cloud-store deploy handed to whichever agent asked
		// first is exactly the mistake this column exists to prevent.
		return "control_plane"
	}
}

// connectorSideEffectRoleClassifier builds the orchestrator's side-effect role
// classifier over the shipped connector registry. It sees the RAW payload,
// before sealing: for connector deploys that is a connector.DeployPayload whose
// Connector field names the implementation, and the census answers for the
// implementation. Non-connector destinations carry no per-row demand.
//
// A payload that fails to decode classifies as control_plane — never claimable —
// rather than as unrestricted: if the control plane cannot tell what a deploy
// is, it must not hand it to an agent.
func connectorSideEffectRoleClassifier(registry *connector.Registry) func(destination string, payload []byte) string {
	return func(destination string, payload []byte) string {
		switch destination {
		case "connector.deploy", "connector.rollback":
		default:
			return ""
		}
		var p connector.DeployPayload
		if err := json.Unmarshal(payload, &p); err != nil || p.Connector == "" {
			return "control_plane"
		}
		return agentRoleForVantage(registry.TargetVantageFor(p.Connector))
	}
}
