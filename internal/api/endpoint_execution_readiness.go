// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"net/http"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/custody"
)

// WithAgentJobClaimability checks the assembled channel at request time. It
// exposes only runtime claim authority, not another tenant's queue contents.
// An absent provider refuses agent-owned endpoint work.
func WithAgentJobClaimability(provider func(string) bool) Option {
	return func(c *config) { c.agentJobClaimable = provider }
}

// Preview and durable execution must require the same job kind the dispatcher
// will enqueue. Host key generation uses endpoint.renew even for first issuance;
// connector.deploy alone cannot execute that CSR-and-install workflow.
func (a *API) validateEndpointExecutionReady(target endpointBindingTargetSummary) error {
	kind := ""
	if custody.TargetExecutorIsAgent(target.Config) {
		kind = "endpoint.renew"
	} else if a.connectorRegistry.TargetVantageFor(target.Connector) != connector.VantageControlPlane {
		kind = "connector.deploy"
	}
	if kind == "" {
		return nil
	}
	if a.agentJobClaimable == nil || !a.agentJobClaimable(kind) {
		return errStatus(http.StatusServiceUnavailable,
			"endpoint execution requires an assembled agent channel with "+kind+
				" enabled in agent_channel.claimable_job_kinds; ask the control-plane operator to enable that exact job kind, then preview again")
	}
	return nil
}
