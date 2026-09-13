// SPDX-License-Identifier: MPL-2.0

package server

import (
	"time"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/observ"
)

type agentChannelMetrics struct {
	serverCertificateExpiry   *observ.GaugeVec
	serverCertificateRenewals *observ.CounterVec
	heartbeats                *observ.CounterVec
	bulkheadRejections        *observ.CounterVec
	// Job-ledger telemetry (epic A6). Gauges rather than counters, because the
	// operationally interesting facts are levels — how deep is the queue, how
	// long has the oldest job waited, how much credential material is live —
	// not rates. All process-wide and label-free except by job kind: never a
	// tenant, an agent, a payload or a reference name.
	jobsPending        *observ.GaugeVec
	jobsClaimed        *observ.GaugeVec
	jobsOldestWait     *observ.GaugeVec
	redemptionsLive    *observ.Gauge
	redemptionsOldest  *observ.Gauge
	claims             *observ.CounterVec
	redemptionRefusals *observ.CounterVec
}

func newAgentChannelMetrics(reg *observ.Registry) *agentChannelMetrics {
	if reg == nil {
		return nil
	}
	m := &agentChannelMetrics{
		serverCertificateExpiry:   reg.GaugeVec("trstctl_agent_server_certificate_expiry_timestamp_seconds", "Current verified server certificate expiry for an agent listener.", []string{"listener"}),
		serverCertificateRenewals: reg.CounterVec("trstctl_agent_server_certificate_issuances_total", "Initial and renewal server certificate issuance results by agent listener.", []string{"listener", "result"}),
		heartbeats: reg.CounterVec("trstctl_agent_heartbeats_total",
			"Agent steady-state heartbeat RPCs by result.", []string{"result"}),
		bulkheadRejections: reg.CounterVec("trstctl_agent_bulkhead_rejections_total",
			"Agent-channel RPCs rejected by the agent bulkhead.", []string{"method"}),
		jobsPending: reg.GaugeVec("trstctl_agent_jobs_pending",
			"Agent-claimable jobs waiting for an agent, by kind.", []string{"kind"}),
		jobsClaimed: reg.GaugeVec("trstctl_agent_jobs_claimed",
			"Agent-claimable jobs currently held under a live claim lease, by kind.", []string{"kind"}),
		jobsOldestWait: reg.GaugeVec("trstctl_agent_jobs_oldest_unclaimed_seconds",
			"How long the oldest unclaimed job of each kind has waited. This is the number that distinguishes a busy fabric from a stalled one; depth alone cannot.", []string{"kind"}),
		redemptionsLive: reg.Gauge("trstctl_agent_credential_redemptions_live",
			"Redeemed credentials currently held by agents outside the seal. Each one is live material on a machine in the estate."),
		redemptionsOldest: reg.Gauge("trstctl_agent_credential_redemption_oldest_seconds",
			"Age of the oldest live credential redemption. Past the maximum claim lease this means an attempt is stuck holding material."),
		claims: reg.CounterVec("trstctl_agent_job_claims_total",
			"Jobs handed to agents, by kind.", []string{"kind"}),
		redemptionRefusals: reg.CounterVec("trstctl_agent_credential_redemptions_refused_total",
			"Credential redemptions refused, by closed-set reason.", []string{"reason"}),
	}
	for _, result := range []string{"success", "failed"} {
		m.heartbeats.WithLabelValues(result)
		for _, listener := range []string{"grpc", "https"} {
			m.serverCertificateRenewals.WithLabelValues(listener, result)
		}
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

// observeJobLedger publishes the job-ledger levels (epic A6). It is called from
// the same posture read the operations API serves, so the metrics and the
// console can never disagree about what the fabric is doing.
func (m *agentChannelMetrics) observeJobLedger(posture api.AgentJobPosture) {
	if m == nil {
		return
	}
	for _, queue := range posture.Queues {
		if m.jobsPending != nil {
			m.jobsPending.WithLabelValues(queue.Kind).Set(float64(queue.Pending))
		}
		if m.jobsClaimed != nil {
			m.jobsClaimed.WithLabelValues(queue.Kind).Set(float64(queue.Claimed))
		}
		if m.jobsOldestWait != nil {
			m.jobsOldestWait.WithLabelValues(queue.Kind).Set(float64(queue.OldestUnclaimedSeconds))
		}
	}
	if m.redemptionsLive != nil {
		m.redemptionsLive.Set(float64(posture.Redemptions.Live))
	}
	if m.redemptionsOldest != nil {
		m.redemptionsOldest.Set(float64(posture.Redemptions.OldestLiveSeconds))
	}
}

// observeClaim counts work actually handed out.
func (m *agentChannelMetrics) observeClaim(kind string, n int) {
	if m == nil || m.claims == nil || n <= 0 {
		return
	}
	m.claims.WithLabelValues(kind).Add(float64(n))
}

// observeRedemptionRefusal counts refusals by their closed-set reason. The
// reasons are a fixed vocabulary, so this cannot become a high-cardinality label
// no matter what an agent does.
func (m *agentChannelMetrics) observeRedemptionRefusal(reason string) {
	if m == nil || m.redemptionRefusals == nil {
		return
	}
	m.redemptionRefusals.WithLabelValues(reason).Inc()
}

// Both labels are closed sets supplied by the listener assembly, never tenants.
func (m *agentChannelMetrics) observeServerCertificate(listener string, expiry time.Time, err error) {
	if m == nil {
		return
	}
	if m.serverCertificateExpiry != nil {
		m.serverCertificateExpiry.WithLabelValues(listener).Set(float64(expiry.Unix()))
	}
	result := "success"
	if err != nil {
		result = "failed"
	}
	if m.serverCertificateRenewals != nil {
		m.serverCertificateRenewals.WithLabelValues(listener, result).Inc()
	}
}
