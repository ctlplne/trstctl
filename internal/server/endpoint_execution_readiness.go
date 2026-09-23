// SPDX-License-Identifier: BUSL-1.1

package server

// Read only the actual mounted service and its immutable operator allowlist.
// Configuring a kind without an assembled channel is not execution readiness.
func (s *Server) agentJobClaimable(kind string) bool {
	if !s.AgentChannelServed() {
		return false
	}
	svc, ok := s.agentSvc.(*bulkheadedAgentService)
	if !ok || svc == nil {
		return false
	}
	inner, ok := svc.next.(*agentService)
	return ok && inner != nil && inner.claimableJobKinds[kind]
}
