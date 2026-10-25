// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/agent/discovery"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/store"
)

const agentInventoryReportPath = "agent.mtls.ReportInventory"

// Where an agent's reported roles came from (epic A2). The console shows this so
// an operator can tell a real grant from a gap in reporting.
const (
	// agentRoleSourceCertificate: read off the SANs of the certificate the agent
	// presented on its last heartbeat. This is the same source the claim path
	// authorizes against.
	agentRoleSourceCertificate = "certificate"
	// agentRoleSourceUnreported: the agent has not heartbeated since roles
	// shipped, so nothing is known. Not the same as having no capability.
	agentRoleSourceUnreported = "unreported"
)

type agentDiscoveryCapabilityResponse struct {
	SourceKind      string `json:"source_kind"`
	Label           string `json:"label"`
	ReportedOver    string `json:"reported_over"`
	MetadataOnly    bool   `json:"metadata_only"`
	PrivateKeyBytes bool   `json:"private_key_bytes"`
	// EnableFlags are the agent flags that switch this source on. A source with
	// flags collects nothing until an operator configures it, so listing the
	// capability without listing its flags reads as coverage that is not running.
	EnableFlags []string `json:"enable_flags,omitempty"`
}

// agentDiscoveryCapabilityLabels names each source kind for the console. The list
// of kinds actually advertised comes from discovery.ShippedSourceKinds, not from
// here, so a label cannot resurrect a capability the agent binary does not have.
var agentDiscoveryCapabilityLabels = map[string]string{
	"filesystem":    "Filesystem certificates",
	"pkcs11":        "PKCS#11 token certificates",
	"windows-store": "Windows certificate store",
	"k8s-secret":    "Kubernetes TLS Secrets",
	"trust-store":   "OS, Java, NSS, and browser trust stores",
	"private-key":   "Private-key material locations", // #nosec G101 -- source-kind label naming where key material was located; no credential value present (CWE-798)
	"ssh":           "SSH keys, authorized access, known hosts, and trusted CAs",
}

// agentDiscoveryCapabilities advertises exactly the source kinds the shipped
// agent binary can collect (truth-integrity 1).
//
// This list used to be hardcoded and named all seven declared kinds. The agent
// binary constructs enumerators for four of them; PKCS#11, the Windows
// certificate store, and Kubernetes Secrets are declared at the collector
// boundary and never built. An operator reading the panel concluded their Windows
// estate was inventoried. It was not. Advertising is now derived from the agent
// package's own record of what it ships, and a guard test proves every entry has
// a constructor the agent binary reaches. Epic C1 ships the missing three; they
// appear here when they are real.
func agentDiscoveryCapabilities() []agentDiscoveryCapabilityResponse {
	shipped := discovery.ShippedSourceKinds()
	out := make([]agentDiscoveryCapabilityResponse, 0, len(shipped))
	for _, s := range shipped {
		label := agentDiscoveryCapabilityLabels[s.Kind]
		if label == "" {
			label = s.Kind
		}
		out = append(out, agentDiscoveryCapabilityResponse{
			SourceKind: s.Kind, Label: label, ReportedOver: agentInventoryReportPath,
			MetadataOnly: true, EnableFlags: append([]string(nil), s.Flags...),
		})
	}
	return out
}

// agentResponse is an in-network agent in the API's JSON shape.
type agentResponse struct {
	ID                    string                             `json:"id"`
	Name                  string                             `json:"name"`
	Status                string                             `json:"status"`
	Version               string                             `json:"version,omitempty"`
	LastSeenAt            *string                            `json:"last_seen_at,omitempty"`
	Presence              agentPresenceResponse              `json:"presence"`
	OffboardedAt          *string                            `json:"offboarded_at,omitempty"`
	OffboardedBy          string                             `json:"offboarded_by,omitempty"`
	OffboardReason        string                             `json:"offboard_reason,omitempty"`
	InventoryReportPath   string                             `json:"inventory_report_path"`
	DiscoveryCapabilities []agentDiscoveryCapabilityResponse `json:"discovery_capabilities"`
	// Roles is the capability grant read off the certificate the agent last
	// presented (epic A2): host, network, or both. It is a projection of the
	// certificate, not an editable field — changing an agent's role is a
	// re-enrollment, because the role lives in a signed SAN.
	//
	// Empty means the agent has not heartbeated since roles shipped, which is not
	// the same as host-only and is shown differently.
	Roles []string `json:"roles"`
	// RoleSource says where the roles above came from, so the console never
	// presents a projection as if it were the authority.
	RoleSource string `json:"role_source"`
	// RelayCapabilities is what this server's agent build can claim for the
	// roles last reported from this agent's certificate. It is not a report of
	// the enrolled binary's version, configured flags, or completed work.
	RelayCapabilities []agentRelayCapabilityResponse `json:"relay_capabilities"`
	// ReportedCapabilities is what the ENROLLED BINARY itself reported on its
	// newest heartbeat (A62), filtered by the same certificate roles: the
	// kinds and connector families it ships and the enabling flags it was
	// started without. Absent for an agent that has never reported one.
	ReportedCapabilities []agentReportedCapabilityResponse `json:"reported_capabilities,omitempty"`
	// CapabilitySource says which list describes this agent: "reported" when
	// the binary has said what it carries, "server_census" when only this
	// server build's census is available (an older agent).
	CapabilitySource        string  `json:"capability_source"`
	CapabilitiesReportedAt  *string `json:"capabilities_reported_at,omitempty"`
	ReportedExecutorVersion string  `json:"reported_executor_version,omitempty"`
	// ReportedHostTLSProbe says whether the binary's host exec profile pins
	// tls_probe_openssl (B6-1); absent until the binary has reported a census.
	ReportedHostTLSProbe *bool `json:"reported_host_tls_probe,omitempty"`
	// ReportedHostProfileError is the binary's own reason its host exec
	// profile could not be loaded (B7); absent when it loaded.
	ReportedHostProfileError string `json:"reported_host_profile_error,omitempty"`
	// ReportedPendingReportError is the binary's own reason it has paused job
	// claims (B13-R1): a pending job report it cannot send under its current
	// registration; absent while claims run.
	ReportedPendingReportError string `json:"reported_pending_report_error,omitempty"`
	// ReportedRelayCABundle is the relay's own account of its --relay-ca-bundle
	// (A86): the digest and load time of the bundle in force and the last
	// reload error; absent until a relay with a bundle has reported.
	ReportedRelayCABundle *AgentRelayCABundleReport `json:"reported_relay_ca_bundle,omitempty"`
	// WorkloadAPI is this host's SPIFFE Workload API posture (epic B3).
	// LiveClaims are the jobs this agent holds under an unexpired lease (A67):
	// job id, kind, attempt and lease expiry from the ledger, never a payload.
	LiveClaims []agentLiveClaimResponse `json:"live_claims"`
	// ClaimQuota is the per-agent lease cap the channel enforces (A66); zero
	// means none beyond the shared bulkhead. ClaimQuotaReached says new claims
	// are being withheld until a lease completes, fails or lapses.
	ClaimQuota        int                    `json:"claim_quota"`
	ClaimQuotaReached bool                   `json:"claim_quota_reached"`
	WorkloadAPI       agentWorkloadAPIStatus `json:"workload_api"`
	// EnrollmentProxy is this certificate-bound relay's measured A4 topology
	// and health. It is evidence only; no capability is granted from the report.
	EnrollmentProxy agentEnrollmentProxyStatus `json:"enrollment_proxy"`
}

// agentPresenceResponse separates durable lifecycle (Agent.Status) from the
// transient question "can this agent be considered connected right now?". The
// server owns the answer because it also owns the heartbeat interval and the
// fleet-health alert threshold. A browser-side duration would inevitably drift.
type agentPresenceResponse struct {
	State       string  `json:"state"`
	Online      bool    `json:"online"`
	EvaluatedAt string  `json:"evaluated_at"`
	FreshUntil  *string `json:"fresh_until,omitempty"`
	Detail      string  `json:"detail"`
}

const (
	agentPresenceOnline     = "online"
	agentPresenceStale      = "stale"
	agentPresenceUnreported = "unreported"
	agentPresenceOffboarded = "offboarded"
	agentPresenceClockSkew  = "clock_skew"

	defaultAgentPresenceHeartbeatInterval = 30 * time.Second
)

func agentPresenceFor(a store.Agent, now time.Time, heartbeatInterval time.Duration) agentPresenceResponse {
	now = now.UTC()
	if heartbeatInterval <= 0 {
		heartbeatInterval = defaultAgentPresenceHeartbeatInterval
	}
	out := agentPresenceResponse{EvaluatedAt: now.Format(time.RFC3339Nano)}
	if a.OffboardedAt != nil || strings.EqualFold(a.Status, "offboarded") {
		out.State = agentPresenceOffboarded
		out.Detail = "This agent is offboarded. A heartbeat cannot make it online until it is deliberately re-enrolled."
		return out
	}
	if a.LastSeenAt == nil {
		out.State = agentPresenceUnreported
		out.Detail = "No heartbeat has been recorded, so trstctl cannot call this agent online."
		return out
	}
	lastSeen := a.LastSeenAt.UTC()
	if lastSeen.After(now.Add(heartbeatInterval)) {
		out.State = agentPresenceClockSkew
		out.Detail = "The last heartbeat is later than the control-plane clock allows. Treat this agent as offline until the clocks agree and a new heartbeat arrives."
		return out
	}
	freshUntil := lastSeen.Add(2 * heartbeatInterval)
	freshUntilText := freshUntil.Format(time.RFC3339Nano)
	out.FreshUntil = &freshUntilText
	if now.After(freshUntil) {
		out.State = agentPresenceStale
		out.Detail = "This agent has a stale heartbeat: the last report is older than two expected heartbeat intervals, so it is offline until it reports again."
		return out
	}
	out.State = agentPresenceOnline
	out.Online = true
	out.Detail = "A heartbeat arrived within two expected heartbeat intervals, so this agent is online."
	return out
}

type agentEnrollmentProxyStatus struct {
	State              string `json:"state"`
	Segment            string `json:"segment,omitempty"`
	PublicURL          string `json:"public_url,omitempty"`
	HealthyUpstreams   int    `json:"healthy_upstreams"`
	UnhealthyUpstreams int    `json:"unhealthy_upstreams"`
	UnknownUpstreams   int    `json:"unknown_upstreams"`
	UpstreamFailures   int64  `json:"upstream_failures"`
	ForwardedRequests  int64  `json:"forwarded_requests"`
	RefusedRequests    int64  `json:"refused_requests"`
	LastForwardedAt    string `json:"last_forwarded_at,omitempty"`
	LastFailoverAt     string `json:"last_failover_at,omitempty"`
	ReportedAt         string `json:"reported_at,omitempty"`
	Detail             string `json:"detail"`
}

const (
	enrollmentProxyServing     = "serving"
	enrollmentProxyDegraded    = "degraded"
	enrollmentProxyUnavailable = "unavailable"
	enrollmentProxyUnverified  = "unverified"
	enrollmentProxyNotServing  = "not_serving"
	enrollmentProxyUnreported  = "unreported"
)

func agentEnrollmentProxyFor(a store.Agent) agentEnrollmentProxyStatus {
	out := agentEnrollmentProxyStatus{
		Segment: a.EnrollmentProxySegment, PublicURL: a.EnrollmentProxyPublicURL,
		HealthyUpstreams:   a.EnrollmentProxyHealthyUpstreams,
		UnhealthyUpstreams: a.EnrollmentProxyUnhealthyUpstreams,
		UnknownUpstreams:   a.EnrollmentProxyUnknownUpstreams,
		UpstreamFailures:   a.EnrollmentProxyUpstreamFailures,
		ForwardedRequests:  a.EnrollmentProxyForwarded,
		RefusedRequests:    a.EnrollmentProxyRefused,
	}
	if a.EnrollmentProxyLastForwardedAt != nil {
		out.LastForwardedAt = a.EnrollmentProxyLastForwardedAt.UTC().Format(time.RFC3339)
	}
	if a.EnrollmentProxyLastFailoverAt != nil {
		out.LastFailoverAt = a.EnrollmentProxyLastFailoverAt.UTC().Format(time.RFC3339)
	}
	if a.EnrollmentProxyReportedAt != nil {
		out.ReportedAt = a.EnrollmentProxyReportedAt.UTC().Format(time.RFC3339)
	}
	switch {
	case a.EnrollmentProxyReportedAt == nil:
		out.State = enrollmentProxyUnreported
		out.Detail = "This agent has never reported enrollment-relay posture. Upgrade it before treating the segment as uncovered."
	case !a.EnrollmentProxyServing:
		out.State = enrollmentProxyNotServing
		out.Detail = "This agent explicitly reports that its enrollment proxy is not serving."
	case a.EnrollmentProxyHealthyUpstreams == 0 && a.EnrollmentProxyUnknownUpstreams > 0:
		out.State = enrollmentProxyUnverified
		out.Detail = "The relay is serving, but no configured control-plane endpoint has completed a response in this process yet."
	case a.EnrollmentProxyHealthyUpstreams == 0:
		out.State = enrollmentProxyUnavailable
		out.Detail = "The relay process is serving, but no configured control-plane endpoint currently answers."
	case a.EnrollmentProxyUnhealthyUpstreams > 0 || a.EnrollmentProxyUnknownUpstreams > 0:
		out.State = enrollmentProxyDegraded
		out.Detail = "The relay has a verified control-plane route, but at least one other endpoint is unavailable or has not answered yet."
	default:
		out.State = enrollmentProxyServing
		out.Detail = "The relay is serving and every configured control-plane endpoint currently answers."
	}
	return out
}

// agentWorkloadAPIStatus is what a host reports about the Workload API it
// serves for the workloads on its own machine (epic B3).
type agentWorkloadAPIStatus struct {
	// State is one of "serving", "not_serving", "unreported".
	//
	// Three values, not a boolean, because "unreported" is a real and different
	// answer: an agent predating this epic says nothing, and rendering that as
	// "not serving" would tell an operator their host declined when it simply
	// cannot say. One is fixed by upgrading the agent, the other by changing a
	// flag, and a console that conflates them sends people to the wrong place.
	State string `json:"state"`
	// SVIDsIssued is how many SVIDs this host has issued since its agent
	// started. It RESETS on restart, which is stated rather than smoothed over:
	// the agent is the only thing that can count them and it does not persist.
	SVIDsIssued int64 `json:"svids_issued"`
	// ReportedAt is when this host last reported the fields above. Empty when
	// it never has.
	ReportedAt string `json:"reported_at,omitempty"`
	// Detail is the operator-facing sentence for this state.
	Detail string `json:"detail"`
}

// Workload API state vocabulary (epic B3).
const (
	workloadAPIServing    = "serving"
	workloadAPINotServing = "not_serving"
	workloadAPIUnreported = "unreported"
)

// agentWorkloadAPIFor renders a host's Workload API posture.
func agentWorkloadAPIFor(a store.Agent) agentWorkloadAPIStatus {
	switch {
	case a.WorkloadAPIReportedAt == nil:
		return agentWorkloadAPIStatus{
			State: workloadAPIUnreported,
			Detail: "This agent has never reported Workload API state. That usually means it " +
				"predates the host-served Workload API; it is not the same as reporting that " +
				"the socket is off.",
		}
	case a.WorkloadAPIServed:
		return agentWorkloadAPIStatus{
			State: workloadAPIServing, SVIDsIssued: a.WorkloadAPISVIDs,
			ReportedAt: a.WorkloadAPIReportedAt.UTC().Format(time.RFC3339),
			Detail: "Workloads on this host obtain SVIDs from its local socket. The SVID key is " +
				"generated here and never reaches the control plane.",
		}
	default:
		return agentWorkloadAPIStatus{
			State:      workloadAPINotServing,
			ReportedAt: a.WorkloadAPIReportedAt.UTC().Format(time.RFC3339),
			Detail: "This agent is not serving a Workload API socket. Workloads on this host must " +
				"reach the control plane's own socket, which generates their SVID keys there.",
		}
	}
}

// agentRelayCapabilityResponse is one job kind a relay build executes.
type agentRelayCapabilityResponse struct {
	// Kind is the job kind claimed over the channel.
	Kind string `json:"kind"`
	// Connectors are the connector implementations this build carries for it.
	Connectors []string `json:"connectors"`
	// EnableFlags are the agent flags that switch it on. A capability with
	// flags executes nothing until an operator sets them, so listing the
	// capability without its flags would read as coverage that is not running.
	EnableFlags []string `json:"enable_flags,omitempty"`
}

// agentReportedCapabilityResponse is one job kind as the enrolled binary
// reported it (A62).
type agentReportedCapabilityResponse struct {
	Kind       string   `json:"kind"`
	Connectors []string `json:"connectors"`
	// MissingFlags are the enabling flags the process was started without;
	// Enabled is true only when none are missing.
	MissingFlags []string `json:"missing_flags"`
	Enabled      bool     `json:"enabled"`
}

const (
	agentCapabilitySourceReported     = "reported"
	agentCapabilitySourceServerCensus = "server_census"
)

// agentReportedCapabilities decodes the binary's self-reported census and
// filters it by the certificate roles, the way the server census is filtered,
// so an operator sees one role-scoped answer from each source.
// agentReportedHostTLSProbe reads the census's probe flag; nil until a
// census was reported.
func agentReportedHostTLSProbe(a store.Agent) *bool {
	if a.ExecutorsReportedAt == nil || len(a.Executors) == 0 {
		return nil
	}
	var census struct {
		HostTLSProbe bool `json:"host_tls_probe"`
	}
	if err := json.Unmarshal(a.Executors, &census); err != nil {
		return nil
	}
	return &census.HostTLSProbe
}

// AgentReportedHostProfileError reads the census's host profile load error
// (B7); empty until a census was reported or when the profile loaded.
func AgentReportedHostProfileError(a store.Agent) string {
	if a.ExecutorsReportedAt == nil || len(a.Executors) == 0 {
		return ""
	}
	var census struct {
		HostProfileError string `json:"host_profile_error"`
	}
	if err := json.Unmarshal(a.Executors, &census); err != nil {
		return ""
	}
	return strings.TrimSpace(census.HostProfileError)
}

// AgentReportedPendingReportError reads the census's paused-claims reason
// (B13-R1); empty until a census was reported or while claims run.
func AgentReportedPendingReportError(a store.Agent) string {
	if a.ExecutorsReportedAt == nil || len(a.Executors) == 0 {
		return ""
	}
	var census struct {
		PendingReportError string `json:"pending_report_error"`
	}
	if err := json.Unmarshal(a.Executors, &census); err != nil {
		return ""
	}
	return strings.TrimSpace(census.PendingReportError)
}

// RequireHostAgentProfileUsable refuses work bound to a host agent whose
// executor census says it claims no host work: its host execution profile
// could not be loaded (B7), or it paused job claims over a pending report it
// cannot send under its current registration (B13-R1). The row would wait on a
// claim that never comes and the operator would see only a timeout. An agent
// that reported no census, or no error, is admitted.
func RequireHostAgentProfileUsable(agent store.Agent, work string) error {
	if reason := AgentReportedHostProfileError(agent); reason != "" {
		return ErrStatus(http.StatusConflict, fmt.Sprintf(
			"%s is bound to host agent %s, whose host execution profile could not be loaded (%s); repair the profile and restart the agent first; nothing was queued or changed",
			work, agent.Name, reason))
	}
	if reason := AgentReportedPendingReportError(agent); reason != "" {
		return ErrStatus(http.StatusConflict, fmt.Sprintf(
			"%s is bound to host agent %s, which has paused job claims (%s); nothing was queued or changed",
			work, agent.Name, reason))
	}
	return nil
}

func agentReportedCapabilities(a store.Agent) []agentReportedCapabilityResponse {
	if a.ExecutorsReportedAt == nil || len(a.Executors) == 0 {
		return nil
	}
	var census struct {
		Kinds []struct {
			Kind         string   `json:"kind"`
			Connectors   []string `json:"connectors"`
			MissingFlags []string `json:"missing_flags"`
		} `json:"kinds"`
	}
	if err := json.Unmarshal(a.Executors, &census); err != nil {
		return nil
	}
	shippedRoles := map[string][]string{}
	for _, kind := range relay.ShippedJobKinds() {
		shippedRoles[kind.Kind] = kind.Roles
	}
	out := make([]agentReportedCapabilityResponse, 0, len(census.Kinds))
	for _, kind := range census.Kinds {
		roles, known := shippedRoles[kind.Kind]
		if known && !slices.ContainsFunc(a.Roles, func(role string) bool { return slices.Contains(roles, role) }) {
			continue
		}
		connectors := make([]string, 0, len(kind.Connectors))
		for _, name := range kind.Connectors {
			if (slices.Contains(a.Roles, mtls.AgentRoleHost) && relay.ExecutesOnHost(name)) ||
				(slices.Contains(a.Roles, mtls.AgentRoleNetwork) && relay.Executes(name)) ||
				(!relay.ExecutesOnHost(name) && !relay.Executes(name)) {
				connectors = append(connectors, name)
			}
		}
		missing := append([]string(nil), kind.MissingFlags...)
		if missing == nil {
			missing = []string{}
		}
		out = append(out, agentReportedCapabilityResponse{Kind: kind.Kind, Connectors: connectors, MissingFlags: missing, Enabled: len(missing) == 0})
	}
	return out
}

// agentListResponse is the envelope for GET /api/v1/agents.
type agentListResponse struct {
	Agents     []agentResponse `json:"agents"`
	NextCursor string          `json:"next_cursor,omitempty"`
}

// agentRelayCapabilities reports what a relay build executes, from the agent
// package's shipped census. Like the discovery capabilities, it is derived
// rather than hand-listed so the console cannot advertise a capability the
// binary does not carry (C1a) — and here the stakes are higher, because a
// falsely advertised relay capability would take a claim and burn a credential
// redemption before failing.
func agentRelayCapabilities(roles []string) []agentRelayCapabilityResponse {
	shipped := relay.ShippedJobKinds()
	out := make([]agentRelayCapabilityResponse, 0, len(shipped))
	for _, kind := range shipped {
		if !slices.ContainsFunc(roles, func(role string) bool { return slices.Contains(kind.Roles, role) }) {
			continue
		}
		connectors := make([]string, 0, len(kind.Connectors))
		for _, connector := range kind.Connectors {
			if (slices.Contains(roles, mtls.AgentRoleHost) && relay.ExecutesOnHost(connector)) ||
				(slices.Contains(roles, mtls.AgentRoleNetwork) && relay.Executes(connector)) {
				connectors = append(connectors, connector)
			}
		}
		flags := make([]string, 0, len(kind.Flags))
		for _, flag := range kind.Flags {
			if slices.Contains(roles, mtls.AgentRoleHost) ||
				(flag != "--host-exec-profile" && flag != "--host-rollback-dir") {
				flags = append(flags, flag)
			}
		}
		out = append(out, agentRelayCapabilityResponse{
			Kind:        kind.Kind,
			Connectors:  connectors,
			EnableFlags: flags,
		})
	}
	return out
}

func toAgentResponse(a store.Agent) agentResponse {
	return toAgentResponseAt(a, time.Now().UTC(), defaultAgentPresenceHeartbeatInterval)
}

func toAgentResponseAt(a store.Agent, now time.Time, heartbeatInterval time.Duration) agentResponse {
	out := agentResponse{
		ID: a.ID, Name: a.Name, Status: a.Status, Version: a.Version,
		Presence:              agentPresenceFor(a, now, heartbeatInterval),
		InventoryReportPath:   agentInventoryReportPath,
		DiscoveryCapabilities: agentDiscoveryCapabilities(),
		Roles:                 a.Roles,
		RoleSource:            agentRoleSourceCertificate,
		RelayCapabilities:     agentRelayCapabilities(a.Roles),
		ReportedCapabilities:  agentReportedCapabilities(a),
		LiveClaims:            []agentLiveClaimResponse{},
		CapabilitySource:      agentCapabilitySourceServerCensus,
		WorkloadAPI:           agentWorkloadAPIFor(a),
		EnrollmentProxy:       agentEnrollmentProxyFor(a),
	}
	if out.ReportedCapabilities != nil {
		out.CapabilitySource = agentCapabilitySourceReported
		reported := a.ExecutorsReportedAt.UTC().Format(time.RFC3339)
		out.CapabilitiesReportedAt = &reported
		var census struct {
			Version string `json:"version"`
		}
		_ = json.Unmarshal(a.Executors, &census)
		out.ReportedExecutorVersion = census.Version
		out.ReportedHostTLSProbe = agentReportedHostTLSProbe(a)
		out.ReportedHostProfileError = AgentReportedHostProfileError(a)
		out.ReportedPendingReportError = AgentReportedPendingReportError(a)
		out.ReportedRelayCABundle = agentReportedRelayCABundle(a)
	}
	if len(out.Roles) == 0 {
		out.Roles = []string{}
		out.RoleSource = agentRoleSourceUnreported
	}
	if a.LastSeenAt != nil {
		s := a.LastSeenAt.UTC().Format(time.RFC3339Nano)
		out.LastSeenAt = &s
	}
	if a.OffboardedAt != nil {
		s := a.OffboardedAt.UTC().Format(time.RFC3339Nano)
		out.OffboardedAt = &s
	}
	out.OffboardedBy = a.OffboardedBy
	out.OffboardReason = a.OffboardReason
	return out
}

func (a *API) agentResponse(ag store.Agent) agentResponse {
	return a.agentResponseAt(ag, time.Now().UTC())
}

func (a *API) agentResponseAt(ag store.Agent, evaluatedAt time.Time) agentResponse {
	out := toAgentResponseAt(ag, evaluatedAt, a.agentHeartbeatInterval)
	out.ClaimQuota = a.agentClaimQuota
	return out
}

// agentLiveClaimResponse is one lease an agent holds right now (A67).
type agentLiveClaimResponse struct {
	JobID          int64  `json:"job_id"`
	Kind           string `json:"kind"`
	Attempt        int    `json:"attempt"`
	LeaseExpiresAt string `json:"lease_expires_at"`
}

// attachLiveClaims fills each agent's live claims from the ledger's unexpired
// leases (A67) and says whether the per-agent quota (A66) is reached.
func (a *API) attachLiveClaims(ctx context.Context, tenantID string, items []agentResponse, now time.Time) error {
	if len(items) == 0 {
		return nil
	}
	held, err := a.store.LiveAgentClaims(ctx, tenantID, now)
	if err != nil {
		return err
	}
	for i := range items {
		claims := make([]agentLiveClaimResponse, 0, len(held[items[i].ID]))
		for _, claim := range held[items[i].ID] {
			claims = append(claims, agentLiveClaimResponse{
				JobID: claim.JobID, Kind: claim.Destination, Attempt: claim.Attempt,
				LeaseExpiresAt: claim.ClaimExpiresAt.UTC().Format(time.RFC3339),
			})
		}
		items[i].LiveClaims = claims
		items[i].ClaimQuotaReached = a.agentClaimQuota > 0 && len(claims) >= a.agentClaimQuota
	}
	return nil
}

// listAgents returns the tenant's in-network agents (F3). The web first-run
// wizard polls it to detect a freshly-installed agent's registration.
func (a *API) listAgents(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit, err := pageLimit(r)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	afterID := store.ZeroUUID
	var afterCreatedAt *time.Time
	if c := r.URL.Query().Get("cursor"); c != "" {
		ts, id, perr := decodeAgentCursor(c)
		if perr != nil {
			a.writeError(w, errStatus(http.StatusBadRequest, "invalid cursor"))
			return
		}
		afterCreatedAt = ts
		afterID = id
	}
	agents, err := a.store.ListAgentsPage(r.Context(), tenantID, afterCreatedAt, afterID, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]agentResponse, 0, len(agents))
	evaluatedAt := time.Now().UTC()
	for _, ag := range agents {
		items = append(items, a.agentResponseAt(ag, evaluatedAt))
	}
	if err := a.attachLiveClaims(r.Context(), tenantID, items, evaluatedAt); err != nil {
		a.writeError(w, err)
		return
	}
	next := ""
	if len(agents) == limit {
		next = encodeAgentCursor(agents[len(agents)-1])
	}
	a.writeJSON(w, http.StatusOK, agentListResponse{Agents: items, NextCursor: next})
}

const agentCursorSep = "|"

func encodeAgentCursor(a store.Agent) string {
	return base64.RawURLEncoding.EncodeToString([]byte(a.CreatedAt.UTC().Format(time.RFC3339Nano) + agentCursorSep + a.ID))
}

func decodeAgentCursor(c string) (*time.Time, string, error) {
	b, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return nil, "", err
	}
	tsStr, id, found := strings.Cut(string(b), agentCursorSep)
	if !found || len(id) != 36 {
		return nil, "", errors.New("cursor is not a valid agent cursor")
	}
	ts, err := time.Parse(time.RFC3339Nano, tsStr)
	if err != nil {
		return nil, "", errors.New("cursor created_at is not a valid timestamp")
	}
	return &ts, id, nil
}

// enrollmentTokenResponse carries a one-time agent bootstrap token and the path
// an agent presents it to when enrolling.
type enrollmentTokenResponse struct {
	Token           secretJSONBytes `json:"token"`
	EnrollURL       string          `json:"enroll_path"`
	AgentServer     string          `json:"agent_server"`
	AgentServerName string          `json:"agent_server_name"`
	// Roles echoes the grant recorded with the token, so the operator can see what
	// they just authorized rather than inferring it from what they typed. It is
	// the effective grant after normalization — an empty request comes back as
	// ["host"], because that is what the certificate will actually say.
	Roles []string `json:"roles"`
}

type agentEnrollmentConnection struct {
	Server     string
	ServerName string
}

const agentEnrollmentRenewalPath = "/enroll/renewal"

const agentEnrollmentRenewalAuthentication = "Current verified agent certificate over mTLS"

func (r enrollmentTokenResponse) wipeSecrets() { r.Token.wipe() }

// enrollmentTokenRequest optionally pins a one-time bootstrap token to the
// single agent identity that may redeem it. Empty preserves the legacy "any
// identity within the tenant" behavior for existing clients.
type enrollmentTokenRequest struct {
	AllowedIdentity string `json:"allowed_identity,omitempty"`
	// Roles is the capability grant the enrolled agent's certificate will carry
	// (epic A2): "host", "network", or both. Empty means host-only, which is what
	// every agent enrolled before roles existed effectively had.
	Roles []string `json:"roles,omitempty"`
}

// enrollmentPlanPreview is the exact, effect-free contract shown before a
// one-time token exists. It deliberately contains connection and capability
// metadata only: the secret token is created by the separate confirmed route.
type enrollmentPlanPreview struct {
	Ready                 bool     `json:"ready"`
	SideEffects           bool     `json:"side_effects"`
	AllowedIdentity       string   `json:"allowed_identity,omitempty"`
	Roles                 []string `json:"roles"`
	RequiredPermissions   []string `json:"required_permissions"`
	EnrollPath            string   `json:"enroll_path"`
	AgentServer           string   `json:"agent_server"`
	AgentServerName       string   `json:"agent_server_name"`
	RenewalReady          bool     `json:"renewal_ready"`
	RenewalPath           string   `json:"renewal_path"`
	RenewalAuthentication string   `json:"renewal_authentication"`
	DataHandling          string   `json:"data_handling"`
	BlockedReasons        []string `json:"blocked_reasons"`
}

// agentEnrollmentBlockers is the one lifecycle-readiness decision shared by
// preview and execution. It prevents the console/API disagreement where a plan
// says an endpoint is usable but the mutating route mints a credential anyway.
func (a *API) agentEnrollmentBlockers() []string {
	blocked := make([]string, 0, 3)
	if strings.TrimSpace(a.agentConnection.Server) == "" {
		blocked = append(blocked, "Configure the public agent address before minting a token; the console will not invent a destination for a one-time credential.")
	}
	if strings.TrimSpace(a.agentConnection.ServerName) == "" {
		blocked = append(blocked, "Configure the agent TLS server name before minting a token so the new agent can verify the control plane it reaches.")
	}
	if !a.agentRenewalReady {
		blocked = append(blocked, "Enable the dedicated agent-channel renewal listener before minting a token; an enrolled machine needs current-certificate mTLS renewal before its first certificate expires.")
	}
	return blocked
}

// agentCertRevocationRequest identifies one public certificate selector to deny
// for an agent. Serial and fingerprint are public certificate identifiers; no key
// material or certificate bytes are accepted on this API.
type agentCertRevocationRequest struct {
	Agent       string `json:"agent,omitempty"`
	Serial      string `json:"serial,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

type agentCertRevocationResponse struct {
	AgentID     string    `json:"agent_id"`
	Agent       string    `json:"agent,omitempty"`
	Serial      string    `json:"serial,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	Reason      string    `json:"reason,omitempty"`
	RevokedAt   time.Time `json:"revoked_at"`
}

type agentOffboardRequest struct {
	Reason string `json:"reason,omitempty"`
}

type agentOffboardResponse struct {
	Agent              agentResponse `json:"agent"`
	RevocationEvidence string        `json:"revocation_evidence"`
}

// previewEnrollmentToken validates the same identity, role, relay authority, and
// public connection facts as the mint route without calling the token issuer.
// POST carries a typed request body, but this is a read-only calculation: no event,
// projection, idempotency record, token, or agent job is created.
func (a *API) previewEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	if a.agentTokens == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "agent enrollment is not configured"))
		return
	}
	req, roles, err := a.parseEnrollmentTokenGrant(r)
	if err != nil {
		a.writeError(w, err)
		return
	}

	blocked := a.agentEnrollmentBlockers()
	permissions := []string{string(authz.AgentsWrite)}
	if slices.Contains(roles, mtls.AgentRoleNetwork) {
		permissions = append(permissions, string(authz.AgentsGrantRelay))
	}
	a.writeJSON(w, http.StatusOK, enrollmentPlanPreview{
		Ready:                 len(blocked) == 0,
		SideEffects:           false,
		AllowedIdentity:       req.AllowedIdentity,
		Roles:                 effectiveAgentRoles(roles),
		RequiredPermissions:   permissions,
		EnrollPath:            "/enroll/bootstrap",
		AgentServer:           a.agentConnection.Server,
		AgentServerName:       a.agentConnection.ServerName,
		RenewalReady:          a.agentRenewalReady,
		RenewalPath:           agentEnrollmentRenewalPath,
		RenewalAuthentication: agentEnrollmentRenewalAuthentication,
		DataHandling:          "This preview contains the selected agent identity, certificate roles, and public connection metadata only. A one-time token is not minted or returned.",
		BlockedReasons:        blocked,
	})
}

// createEnrollmentToken mints a one-time agent bootstrap token (S5.1/F15) bound to
// the caller's tenant (WIRE-003/AN-1) so the web wizard can build the agent
// install command. The mint runs under an idempotency key (AN-5): a retried
// request returns the original token rather than minting a second one. The token
// is tenant-attributed, so the certificate the agent later receives carries this
// tenant. When no issuer is wired, the capability is reported unavailable.
//
//trstctl:mutation
func (a *API) createEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if a.agentTokens == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "agent enrollment is not configured"))
		return
	}
	req, roles, err := a.parseEnrollmentTokenGrant(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	if blocked := a.agentEnrollmentBlockers(); len(blocked) > 0 {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, strings.Join(blocked, " ")))
		return
	}
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		token, err := a.agentTokens.IssueBootstrapTokenWithRoles(ctx, tenantID, req.AllowedIdentity, roles)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, enrollmentTokenResponse{
			Token:           secretJSONBytes(token),
			EnrollURL:       "/enroll/bootstrap",
			AgentServer:     a.agentConnection.Server,
			AgentServerName: a.agentConnection.ServerName,
			Roles:           effectiveAgentRoles(roles),
		}, nil
	})
}

// parseEnrollmentTokenGrant is the one server-owned decision used by preview
// and execution. Keeping it shared prevents a reviewed host plan from becoming a
// relay grant, or a valid preview from disagreeing with queue admission.
func (a *API) parseEnrollmentTokenGrant(r *http.Request) (enrollmentTokenRequest, []string, error) {
	var req enrollmentTokenRequest
	if r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0 {
		if err := decodeJSON(r, &req); err != nil {
			return enrollmentTokenRequest{}, nil, errWithStatus(http.StatusBadRequest, err)
		}
	}
	req.AllowedIdentity = strings.TrimSpace(req.AllowedIdentity)
	roles, err := normalizeEnrollmentRoles(req.Roles)
	if err != nil {
		return enrollmentTokenRequest{}, nil, errWithStatus(http.StatusBadRequest, err)
	}
	// Granting the network role is a separate authority from enrolling agents: a
	// relay holds the credentials for the appliances it fronts, so placing one is
	// a different decision from adding a host agent (epic A2).
	if slices.Contains(roles, mtls.AgentRoleNetwork) && !a.canGrantRelayRole(r) {
		return enrollmentTokenRequest{}, nil, errStatus(http.StatusForbidden,
			"granting an agent the network relay role requires the agents:relay.grant permission")
	}
	return req, roles, nil
}

// revokeAgentCertificate records an event-sourced revocation for one agent mTLS
// client certificate. The served gRPC channel checks this projected deny-list
// before any heartbeat, renewal, or inventory work.
//
//trstctl:mutation
func (a *API) revokeAgentCertificate(w http.ResponseWriter, r *http.Request) {
	agentID := strings.TrimSpace(r.PathValue("id"))
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.orch == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "agent certificate revocation is not configured")
		}
		if agentID == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "agent id is required")
		}
		var req agentCertRevocationRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		req.Agent = strings.TrimSpace(req.Agent)
		req.Serial = normalizeAgentCertSerial(req.Serial)
		req.Fingerprint = normalizeAgentCertFingerprint(req.Fingerprint)
		req.Reason = strings.TrimSpace(req.Reason)
		if req.Serial == "" && req.Fingerprint == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "serial or fingerprint is required")
		}
		revokedAt := time.Now().UTC()
		result, err := a.orch.RevokeAgentCertificate(ctx, tenantID, agentID, req.Agent, req.Serial, req.Fingerprint, req.Reason, revokedAt)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, agentCertRevocationResponse{
			AgentID: agentID, Agent: result.Agent, Serial: result.Serial, Fingerprint: result.Fingerprint,
			Reason: result.Reason, RevokedAt: result.RevokedAt,
		}, nil
	})
}

// offboardAgent records a terminal agent tombstone and makes the served mTLS
// channel reject future RPCs from that agent id. The row remains visible in
// GET /api/v1/agents so operators see evidence instead of a silent deletion.
//
//trstctl:mutation
func (a *API) offboardAgent(w http.ResponseWriter, r *http.Request) {
	agentID := strings.TrimSpace(r.PathValue("id"))
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.orch == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "agent offboarding is not configured")
		}
		if agentID == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "agent id is required")
		}
		var req agentOffboardRequest
		if r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0 {
			if err := decodeJSON(r, &req); err != nil {
				return 0, nil, errWithStatus(http.StatusBadRequest, err)
			}
		}
		agent, err := a.orch.OffboardAgent(ctx, tenantID, agentID, req.Reason)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, agentOffboardResponse{
			Agent:              a.agentResponse(agent),
			RevocationEvidence: "offboarded agent certificates are rejected by the served mTLS channel before heartbeat, renewal, or inventory RPCs",
		}, nil
	})
}

func normalizeAgentCertSerial(v string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(v)), ":", "")
}

func normalizeAgentCertFingerprint(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimPrefix(v, "sha256:")
	return strings.ReplaceAll(v, ":", "")
}

// normalizeEnrollmentRoles validates an operator's requested capability grant. An
// unknown role is rejected rather than dropped: an operator who asked for a
// capability that does not exist should be told, not handed a token that quietly
// grants less than they believe it does.
func normalizeEnrollmentRoles(requested []string) ([]string, error) {
	for _, role := range requested {
		if strings.TrimSpace(role) == "" {
			continue
		}
		if !mtls.ValidAgentRole(role) {
			return nil, fmt.Errorf("unknown agent role %q: expected %q or %q",
				role, mtls.AgentRoleHost, mtls.AgentRoleNetwork)
		}
	}
	return mtls.NormalizeAgentRoles(requested), nil
}

// effectiveAgentRoles is what the issued certificate will actually say. An empty
// grant is reported as host rather than as nothing, because host is what a
// certificate with no role SAN is read as — reporting "no roles" would describe a
// capability-less agent that does not exist.
func effectiveAgentRoles(roles []string) []string {
	if len(roles) == 0 {
		return []string{mtls.AgentRoleHost}
	}
	return roles
}

// canGrantRelayRole reports whether the calling principal may mint a token that
// carries the network relay role (epic A2). The route itself is already gated on
// AgentsWrite; this is the additional authority, checked against the principal
// guard placed in the request context.
func (a *API) canGrantRelayRole(r *http.Request) bool {
	principal, ok := a.principalFor(r)
	if !ok {
		return false
	}
	return principal.Can(authz.AgentsGrantRelay, authz.Scope{TenantID: principal.TenantID})
}

// AgentRelayCABundleReport is the served shape of a relay's self-reported
// appliance CA bundle (A86).
type AgentRelayCABundleReport struct {
	SHA256   string `json:"sha256"`
	LoadedAt string `json:"loaded_at"`
	Error    string `json:"error,omitempty"`
}

func agentReportedRelayCABundle(a store.Agent) *AgentRelayCABundleReport {
	if len(a.Executors) == 0 {
		return nil
	}
	var census struct {
		RelayCABundle *struct {
			SHA256   string    `json:"sha256"`
			LoadedAt time.Time `json:"loaded_at"`
			Error    string    `json:"error"`
		} `json:"relay_ca_bundle"`
	}
	if err := json.Unmarshal(a.Executors, &census); err != nil || census.RelayCABundle == nil {
		return nil
	}
	return &AgentRelayCABundleReport{
		SHA256: census.RelayCABundle.SHA256, LoadedAt: census.RelayCABundle.LoadedAt.UTC().Format(time.RFC3339),
		Error: strings.TrimSpace(census.RelayCABundle.Error),
	}
}
