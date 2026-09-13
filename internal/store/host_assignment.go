// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"trstctl.com/trstctl/internal/connector"
)

// ValidateHostTargetAssignment checks tenant ownership and the displayed role
// grant before accepting work. Claim authorization still uses the authenticated
// certificate. An offline host remains assigned; no other host inherits its work.
func (s *Store) ValidateHostTargetAssignment(ctx context.Context, tenantID, family string, config json.RawMessage) (string, error) {
	if vantage, known := connector.ShippedTargetVantage(family); !known || vantage != connector.VantageHostAgent {
		return "", nil
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
