// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/orchestrator"
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
// relayPluginCarrier answers whether one of a tenant's enrolled network relays
// reported carrying a named WASM connector plugin (A63). The store implements
// it; nil means no relay can be consulted and plugin work stays control-plane.
type relayPluginCarrier interface {
	TenantNetworkRelayCarriesPlugin(ctx context.Context, tenantID, pluginName string) (bool, error)
}

func connectorSideEffectRoleClassifier(registry *connector.Registry, carriers relayPluginCarrier) orchestrator.SideEffectRoleClassifier {
	return func(ctx context.Context, tenantID, destination string, payload []byte) string {
		switch destination {
		case "connector.deploy", "connector.rollback", "connector.test":
		default:
			// Non-connector kinds carry no per-row demand from the connector
			// census; their vantage is decided by the kind-level table.
			return ""
		}
		var p connector.DeployPayload
		if err := json.Unmarshal(payload, &p); err != nil || p.Connector == "" {
			return "control_plane"
		}
		// A61: a target may declare its own executor where the family admits
		// one (a remote Envoy driven by a relay); the row follows the target.
		if override, ok, err := connector.TargetVantageOverride(p.Connector, p.TargetConfig); err == nil && ok {
			return agentRoleForVantage(override)
		}
		// A63: a connector no shipped family owns is plugin work. It is relay
		// work where one of this tenant's network relays has reported, in its
		// signed census, that it loaded the plugin; otherwise it stays with the
		// control plane's own plugin surface. A lookup failure keeps it on the
		// control plane rather than queueing work no relay may carry.
		if _, shipped := connector.ShippedTargetVantage(p.Connector); !shipped && (registry == nil || !registry.Has(p.Connector)) && carriers != nil && destination != "connector.rollback" {
			if carries, err := carriers.TenantNetworkRelayCarriesPlugin(ctx, tenantID, p.Connector); err == nil && carries {
				return "network"
			}
		}
		return agentRoleForVantage(registry.TargetVantageFor(p.Connector))
	}
}
