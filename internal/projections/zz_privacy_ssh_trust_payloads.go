// SPDX-License-Identifier: BUSL-1.1

package projections

// Historical v1-v6 shapes are closed before v7 adds host SSH readiness.
type agentHeartbeatBeforeSSHTrust struct {
	ID         string `json:"id"`
	Agent      string `json:"agent"`
	Version    string `json:"version"`
	Status     string `json:"status"`
	CertSerial string `json:"cert_serial,omitempty"`
	// Roles is the capability grant read off the certificate the agent presented
	// on this call (epic A2), so the fleet view reflects what the agent actually
	// holds rather than what it was granted at some earlier enrollment. It is
	// carried on the event so a replay reconstructs the same row.
	Roles []string `json:"roles,omitempty"`
	// WorkloadAPIServed and WorkloadAPISVIDs are this host's SPIFFE Workload API
	// posture (epic B3), carried on the event so a replay reconstructs the row.
	//
	// A POINTER for the boolean, because three states matter: serving, not
	// serving, and never reported. An older agent that does not know about this
	// feature sends nothing, and rendering that as "not serving" would tell an
	// operator their host declined to serve when it simply cannot say.
	WorkloadAPIServed *bool  `json:"workload_api_served,omitempty"`
	WorkloadAPISVIDs  *int64 `json:"workload_api_svids,omitempty"`
	// EnrollmentProxy is nil for an older agent and present for a current build,
	// including when that build explicitly reports that its relay is off.
	EnrollmentProxy *EnrollmentProxyReport `json:"enrollment_proxy,omitempty"`
	// RelayPlugins is present only on v2 events after the server verified the
	// report against the exact mTLS peer certificate and freshness window.
	RelayPlugins *AgentRelayPluginCensus `json:"relay_plugins,omitempty"`
	// RevocationCaches is present only on v3 events after the server verified
	// the report against the exact mTLS peer certificate and freshness window.
	RevocationCaches *AgentRevocationCachePosture `json:"revocation_caches,omitempty"`
	// Executors is present only on v4 events: the enrolled binary's own
	// executor census (A62), bounded by the server before it is recorded.
	Executors *agentExecutorCensusBeforeSSHTrust `json:"executors,omitempty"`
	// SSHKRL is present only on v5 events: the host's signed receipt for the
	// OpenSSH KRL its sshd enforces (A109), verified against the exact mTLS
	// peer certificate and freshness window before it is recorded.
	SSHKRL *AgentSSHKRLReceipt `json:"ssh_krl,omitempty"`
	// AgentTimeUnixMilli is the agent's clock when it sent the heartbeat, on
	// v6 events (A194). The projection compares it with the event's time to
	// record how far the agent's clock is from the control plane's.
	AgentTimeUnixMilli int64 `json:"agent_time_unix_ms,omitempty"`
}

type agentExecutorCensusBeforeSSHTrust struct {
	Version string              `json:"version"`
	Kinds   []AgentExecutorKind `json:"kinds"`
	// HostTLSProbe: the host exec profile pins tls_probe_openssl (B6-1).
	HostTLSProbe bool `json:"host_tls_probe,omitempty"`
	// HostProfileError: why the host exec profile could not be loaded (B7);
	// empty when it loaded.
	HostProfileError string `json:"host_profile_error,omitempty"`
	// PendingReportError: why the agent has paused job claims over a pending
	// report it cannot send under its current registration (B13-R1); empty
	// while claims run.
	PendingReportError string `json:"pending_report_error,omitempty"`
	// RelayCABundle: the --relay-ca-bundle in force on the relay (A86).
	RelayCABundle *AgentRelayCABundle `json:"relay_ca_bundle,omitempty"`
}
