// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/custody"
)

// ValidateHostTargetAssignment checks tenant ownership and the displayed role
// grant before accepting work. Claim authorization still uses the authenticated
// certificate. An offline host remains assigned; no other host inherits its work.
func (s *Store) ValidateHostTargetAssignment(ctx context.Context, tenantID, family string, config json.RawMessage) (string, error) {
	// A61: a declared executor is validated here so an impermissible one is
	// refused before the target is saved, and a remote Envoy declared for a
	// relay needs no host assignment.
	if _, _, err := connector.TargetVantageOverride(family, config); err != nil {
		return "", err
	}
	if vantage, known := connector.EffectiveTargetVantage(family, config); !known || vantage != connector.VantageHostAgent {
		return "", nil
	}
	// The agent inside the cluster generates a Kubernetes Secret's key. Without
	// the marker the target would route through control-plane key generation
	// and ship a key into the cluster.
	if family == "k8s_secret" && !custody.TargetExecutorIsAgent(config) {
		return "", fmt.Errorf(`a k8s_secret destination is delivered by the agent inside the cluster, which generates the key there: set "executor": "agent" in its configuration; no work was queued`)
	}
	id, err := connector.TargetHostAgentID(config)
	if err != nil {
		return "", err
	}
	if id == "" {
		return "", fmt.Errorf("destination requires a host agent: select the enrolled machine serving this application and save its agent UUID as required_agent_id; no work was queued")
	}
	a, err := s.GetAgent(ctx, tenantID, id)
	if err != nil {
		return "", fmt.Errorf("destination host agent is unavailable in this tenant; select an enrolled host agent")
	}
	if a.OffboardedAt != nil || !slices.Contains(a.Roles, "host") {
		return "", fmt.Errorf("destination agent must be enrolled with the host role and must not be offboarded")
	}
	return id, nil
}

// ValidateRelayTargetAssignment is the network-relay counterpart for a target
// that declares vantage network (A104). Work whose rollback restores a
// predecessor kept on the executing agent, such as a remote Envoy's TLS
// posture, pins to one relay: the target's required_agent_id must name an
// enrolled network-role relay in this tenant that is not offboarded.
func (s *Store) ValidateRelayTargetAssignment(ctx context.Context, tenantID, family string, config json.RawMessage) (string, error) {
	if vantage, known := connector.EffectiveTargetVantage(family, config); !known || vantage != connector.VantageNetworkRelay {
		return "", fmt.Errorf("destination does not declare a network relay as its executor")
	}
	id, err := connector.TargetHostAgentID(config)
	if err != nil {
		return "", err
	}
	if id == "" {
		return "", fmt.Errorf("destination requires a network relay: save the relay's agent UUID as required_agent_id; no work was queued")
	}
	a, err := s.GetAgent(ctx, tenantID, id)
	if err != nil {
		return "", fmt.Errorf("destination network relay is unavailable in this tenant; select an enrolled network relay")
	}
	if a.OffboardedAt != nil || !slices.Contains(a.Roles, "network") {
		return "", fmt.Errorf("destination relay must be enrolled with the network role and must not be offboarded")
	}
	return id, nil
}
