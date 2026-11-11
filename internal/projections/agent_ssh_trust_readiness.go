// SPDX-License-Identifier: BUSL-1.1

package projections

import "errors"

const AgentHeartbeatSSHTrustSchemaVersion = 7

func validateAgentHeartbeatSSHTrust(schemaVersion int, heartbeat AgentHeartbeat) error {
	present := heartbeat.Executors != nil && heartbeat.Executors.SSHTrust != nil
	if schemaVersion == AgentHeartbeatRelayEgressSchemaVersion {
		// A v8 heartbeat is introduced by the relay's egress policy (A190-L1);
		// SSH fleet readiness stays independently optional.
		if !present {
			return nil
		}
		return heartbeat.Executors.SSHTrust.Validate()
	}
	if schemaVersion != AgentHeartbeatSSHTrustSchemaVersion {
		if present {
			return errors.New("SSH fleet readiness requires agent heartbeat schema v7")
		}
		return nil
	}
	if !present {
		return errors.New("agent heartbeat v7 requires this host's SSH fleet readiness")
	}
	return heartbeat.Executors.SSHTrust.Validate()
}
