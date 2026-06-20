package server

import "trstctl.com/trstctl/internal/observ"

type agentChannelMetrics struct {
	heartbeats         *observ.CounterVec
	bulkheadRejections *observ.CounterVec
}

func newAgentChannelMetrics(reg *observ.Registry) *agentChannelMetrics {
	if reg == nil {
		return nil
	}
	m := &agentChannelMetrics{
		heartbeats: reg.CounterVec("trstctl_agent_heartbeats_total",
			"Agent steady-state heartbeat RPCs by result.", []string{"result"}),
		bulkheadRejections: reg.CounterVec("trstctl_agent_bulkhead_rejections_total",
			"Agent-channel RPCs rejected by the agent bulkhead.", []string{"method"}),
	}
	for _, result := range []string{"success", "failed"} {
		m.heartbeats.WithLabelValues(result)
	}
	for _, method := range []string{"heartbeat", "renew"} {
		m.bulkheadRejections.WithLabelValues(method)
	}
	return m
}

func (m *agentChannelMetrics) observeHeartbeat(result string) {
	if m == nil || m.heartbeats == nil {
		return
	}
	m.heartbeats.WithLabelValues(result).Inc()
}

func (m *agentChannelMetrics) observeBulkheadRejection(method string) {
	if m == nil || m.bulkheadRejections == nil {
		return
	}
	m.bulkheadRejections.WithLabelValues(method).Inc()
}
