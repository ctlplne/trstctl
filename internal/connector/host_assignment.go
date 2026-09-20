// SPDX-License-Identifier: BUSL-1.1

package connector

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// TargetHostAgentID reads routing metadata from an immutable destination config.
// Empty means unassigned, never permission to select an arbitrary host.
func TargetHostAgentID(config json.RawMessage) (string, error) {
	var routing struct {
		AgentID string `json:"required_agent_id"`
	}
	if len(config) == 0 {
		return "", nil
	}
	if err := json.Unmarshal(config, &routing); err != nil {
		return "", fmt.Errorf("destination host assignment must be a UUID in required_agent_id")
	}
	id := strings.TrimSpace(routing.AgentID)
	if id == "" {
		return "", nil
	}
	parsed, err := uuid.Parse(id)
	if err != nil || parsed == uuid.Nil {
		return "", fmt.Errorf("destination required_agent_id must be a nonzero agent UUID")
	}
	return parsed.String(), nil
}
