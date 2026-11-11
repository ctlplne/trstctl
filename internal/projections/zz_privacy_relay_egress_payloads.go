// SPDX-License-Identifier: BUSL-1.1

package projections

import "trstctl.com/trstctl/internal/sshtrustrollout"

// The v7 shape is closed before v8 adds the relay's egress policy (A190-L1).
type agentHeartbeatBeforeRelayEgress struct {
	ID                 string                                `json:"id"`
	Agent              string                                `json:"agent"`
	Version            string                                `json:"version"`
	Status             string                                `json:"status"`
	CertSerial         string                                `json:"cert_serial,omitempty"`
	Roles              []string                              `json:"roles,omitempty"`
	WorkloadAPIServed  *bool                                 `json:"workload_api_served,omitempty"`
	WorkloadAPISVIDs   *int64                                `json:"workload_api_svids,omitempty"`
	EnrollmentProxy    *EnrollmentProxyReport                `json:"enrollment_proxy,omitempty"`
	RelayPlugins       *AgentRelayPluginCensus               `json:"relay_plugins,omitempty"`
	RevocationCaches   *AgentRevocationCachePosture          `json:"revocation_caches,omitempty"`
	Executors          *agentExecutorCensusBeforeRelayEgress `json:"executors,omitempty"`
	SSHKRL             *AgentSSHKRLReceipt                   `json:"ssh_krl,omitempty"`
	AgentTimeUnixMilli int64                                 `json:"agent_time_unix_ms,omitempty"`
}

type agentExecutorCensusBeforeRelayEgress struct {
	SSHTrust           *sshtrustrollout.Readiness `json:"ssh_trust,omitempty"`
	Version            string                     `json:"version"`
	Kinds              []AgentExecutorKind        `json:"kinds"`
	HostTLSProbe       bool                       `json:"host_tls_probe,omitempty"`
	HostProfileError   string                     `json:"host_profile_error,omitempty"`
	PendingReportError string                     `json:"pending_report_error,omitempty"`
	RelayCABundle      *AgentRelayCABundle        `json:"relay_ca_bundle,omitempty"`
}
