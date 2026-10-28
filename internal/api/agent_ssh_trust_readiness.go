// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/json"
	"trstctl.com/trstctl/internal/sshtrustrollout"
	"trstctl.com/trstctl/internal/store"
)

func agentReportedSSHTrustReadiness(agent store.Agent) *sshtrustrollout.Readiness {
	if agent.ExecutorsReportedAt == nil || len(agent.Executors) == 0 {
		return nil
	}
	var census struct {
		SSHTrust *sshtrustrollout.Readiness `json:"ssh_trust,omitempty"`
	}
	if err := json.Unmarshal(agent.Executors, &census); err != nil || census.SSHTrust == nil {
		return nil
	}
	if err := census.SSHTrust.Validate(); err != nil {
		return nil
	}
	return census.SSHTrust
}
