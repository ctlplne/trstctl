// SPDX-License-Identifier: MPL-2.0

package transport

// This file defines the served agent steady-state RPC contract (WIRE-004): the
// steady-state methods an enrolled agent calls on the control plane over the mutual-TLS
// channel, plus a self-contained gRPC wire codec so the contract needs no protoc
// toolchain in the build. Its committed compatibility contract is
// agent_service_schema.json plus testdata/agent_service_wire.golden.json; tests fail
// if service names, method names, JSON tags, metadata keys, or encoded bytes drift.
//
// Wire format. The agent methods carry plain Go structs encoded as JSON under
// a registered gRPC codec named "agent.json" (content-subtype "agent.json"). gRPC
// selects a message codec by the request's content-subtype, so this codec applies
// ONLY to calls the agent client tags with it (see Dial wiring in agent.go); the
// standard health service the server also registers keeps using the default
// protobuf codec untouched. The codec is registered once at init, is stateless and
// concurrency-safe, and depends only on encoding/json + the grpc/mem types already
// in the module graph (no new dependency, AN-4 budget unchanged on the agent side).
//
// Security. Transport security (mTLS, TLS 1.3, AEAD-only, mutual pinning) and the
// tenant attribution (derived from the agent's client-certificate SPIFFE SAN, never
// a request field — AN-1/WIRE-003) live entirely in internal/crypto/mtls and the
// server handler; this file is the codec + message + service descriptor only and
// names no crypto symbol.

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/mem"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/protocol"
)

// AgentCodecName is the content-subtype under which the agent steady-state RPCs are
// encoded. It is distinct from "proto" so the server's standard health service is
// unaffected; the agent client requests it per-call.
const AgentCodecName = "agent.json"

// Agent steady-state capability tokens. These values are wire-visible in gRPC
// metadata, so changing one is a compatibility event even if the JSON messages stay
// unchanged.
const (
	AgentCapabilityHeartbeat         = "heartbeat"
	AgentCapabilityRenew             = "renew"
	AgentCapabilityInventory         = "inventory"
	AgentCapabilityKubernetesPosture = "kubernetes-posture"
	// AgentCapabilityJobs advertises that this side speaks the job claim protocol
	// (A1). An agent that does not advertise it is never handed estate-touching
	// work, which is how a fleet upgrades one host at a time.
	AgentCapabilityJobs = "jobs"
	// AgentCapabilityRelay advertises that this side speaks the just-in-time
	// credential redemption protocol (A3) — the agent can take a job that
	// carries only references and redeem the material for one attempt. An agent
	// that does not advertise it is never handed credential-bearing work.
	AgentCapabilityRelay = "relay"
)

const agentCapabilitiesValue = AgentCapabilityHeartbeat + "," + AgentCapabilityRenew + "," + AgentCapabilityInventory + "," + AgentCapabilityKubernetesPosture + "," + AgentCapabilityJobs + "," + AgentCapabilityRelay

// HeartbeatRequest is what an agent reports on each steady-state beat: its identity
// and the inventory/status snapshot the control plane records. The authorizing
// TENANT is NOT in this message — the server derives it from the agent's verified
// client-certificate SPIFFE SAN (AN-1), so an agent cannot claim another tenant's
// scope by setting a field.
type HeartbeatRequest struct {
	// AgentID is the agent's stable identifier (its certificate common name today).
	AgentID string `json:"agent_id"`
	// Version is the agent build version, recorded for fleet/compat visibility.
	Version string `json:"version"`
	// Status is a coarse health/operational status the agent reports ("active", ...).
	Status string `json:"status"`
	// CertSerial is the serial of the client certificate the agent is currently
	// presenting (observability; the served value is the verified peer cert's).
	CertSerial string `json:"cert_serial,omitempty"`
	// Inventory is a small set of inventory counters the agent reports (e.g. number
	// of certificates/keys it manages). Kept coarse; the rich inventory flows over
	// the discovery path.
	Inventory map[string]int64 `json:"inventory,omitempty"`
	// EnrollmentProxy is the relay's measured dark-segment enrollment posture.
	// Nil means this agent build cannot report the feature; a non-nil report with
	// Serving=false means the current build explicitly says it is off.
	// Nothing is authorized from these values. The server derives tenant, agent
	// identity, and relay role from the verified client certificate.
	EnrollmentProxy *EnrollmentProxyReport `json:"enrollment_proxy,omitempty"`
}

// EnrollmentProxyReport is metadata-only evidence from one relay process.
// Counters are process-lifetime values. Timestamps let the event-sourced control
// plane preserve which relay most recently carried traffic and when its own
// control-plane endpoint pool last failed over, even after that process exits.
type EnrollmentProxyReport struct {
	Serving            bool       `json:"serving"`
	Segment            string     `json:"segment,omitempty"`
	PublicURL          string     `json:"public_url,omitempty"`
	HealthyUpstreams   int        `json:"healthy_upstreams"`
	UnhealthyUpstreams int        `json:"unhealthy_upstreams"`
	UnknownUpstreams   int        `json:"unknown_upstreams"`
	UpstreamFailures   int64      `json:"upstream_failures"`
	ForwardedRequests  int64      `json:"forwarded_requests"`
	RefusedRequests    int64      `json:"refused_requests"`
	LastForwardedAt    *time.Time `json:"last_forwarded_at,omitempty"`
	LastFailoverAt     *time.Time `json:"last_failover_at,omitempty"`
}

// HeartbeatResponse acknowledges a beat and tells the agent when the control plane
// expects the next one and the tenant the server attributed it to (so the agent can
// log/verify its own scope).
type HeartbeatResponse struct {
	// TenantID is the tenant the server derived from the agent's certificate (echoed
	// for the agent's own observability; it is authoritative server-side regardless).
	TenantID string `json:"tenant_id"`
	// NextHeartbeatSeconds is the server's requested beat interval.
	NextHeartbeatSeconds int64 `json:"next_heartbeat_seconds"`
}

// RenewRequest carries the agent's rotation CSR (DER) for its own client
// certificate. The agent generates a fresh key locally and submits only the CSR;
// the private key never leaves the host. The tenant is NOT carried here — the server
// binds the renewed certificate to the SAME tenant the presented (current)
// certificate carries (WIRE-003/AN-1), never the CSR subject.
type RenewRequest struct {
	// CSRDER is the PKCS#10 certificate request (DER) for the agent's new key.
	CSRDER []byte `json:"csr_der"`
}

// RenewResponse returns the freshly minted client-certificate chain (PEM, leaf||CA),
// signed by the agent CA whose key lives in the isolated signer (AN-3/AN-4).
type RenewResponse struct {
	// CertChainPEM is the issued chain (leaf || agent CA), PEM-encoded.
	CertChainPEM []byte `json:"cert_chain_pem"`
	// NotAfterUnix is the new leaf's expiry (unix seconds), for the agent's timer.
	NotAfterUnix int64 `json:"not_after_unix"`
}

// InventoryFinding is one metadata-only credential reference found by the agent on
// its host. It carries identifiers and public metadata only, never secret values or
// private key material.
type InventoryFinding struct {
	Kind        string            `json:"kind"`
	Ref         string            `json:"ref"`
	Provenance  string            `json:"provenance,omitempty"`
	Fingerprint string            `json:"fingerprint,omitempty"`
	RiskScore   int               `json:"risk_score,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// InventoryRequest carries a bounded batch of local host inventory findings. The
// tenant is still derived from the verified mTLS peer certificate, not this request.
type InventoryRequest struct {
	SourceKind string             `json:"source_kind"`
	Findings   []InventoryFinding `json:"findings"`
}

// InventoryResponse summarizes the evented discovery run the server created from an
// inventory batch.
type InventoryResponse struct {
	TenantID string `json:"tenant_id"`
	RunID    string `json:"run_id"`
	Recorded int    `json:"recorded"`
	Rejected int    `json:"rejected"`
}

// AgentServiceServer is the control-plane side of the agent steady-state channel.
// Implementations derive the tenant from the verified peer certificate in ctx
// (never a request field) and enforce AN-1/AN-2/AN-5 there.
type AgentServiceServer interface {
	// Heartbeat records the agent's inventory/status under its (certificate-derived)
	// tenant and returns the next-beat hint.
	Heartbeat(ctx context.Context, req *HeartbeatRequest) (*HeartbeatResponse, error)
	// Renew signs the agent's rotation CSR into a fresh client certificate bound to
	// the agent's existing tenant, through the signer-held agent CA.
	Renew(ctx context.Context, req *RenewRequest) (*RenewResponse, error)
	// ReportInventory records metadata-only host inventory findings under the
	// certificate-derived tenant.
	ReportInventory(ctx context.Context, req *InventoryRequest) (*InventoryResponse, error)
	// Kubernetes posture reporting is an optional extension described by
	// KubernetesPostureServiceServer so older service implementations remain
	// source-compatible while new servers expose the method on this same service.
}

// agentServiceName / method names are the gRPC routing identifiers. They are fixed
// strings the client and server both use; changing them is a wire-breaking change.
const (
	agentServiceName            = "trstctl.agent.v1.AgentService"
	methodHeartbeat             = "Heartbeat"
	methodRenew                 = "Renew"
	methodInventory             = "ReportInventory"
	methodKubernetesPosture     = "ReportKubernetesPosture"
	fullMethodHeartbeat         = "/" + agentServiceName + "/" + methodHeartbeat
	fullMethodRenew             = "/" + agentServiceName + "/" + methodRenew
	fullMethodInventory         = "/" + agentServiceName + "/" + methodInventory
	fullMethodKubernetesPosture = "/" + agentServiceName + "/" + methodKubernetesPosture
)

// RegisterAgentService registers srv on s under the agent service descriptor. The
// server must have been built with the mTLS credentials (NewServer); this adds the
// agent RPCs alongside the health service.
func RegisterAgentService(s *grpc.Server, srv AgentServiceServer) {
	s.RegisterService(&agentServiceDesc, srv)
}

var agentServiceDesc = grpc.ServiceDesc{
	ServiceName: agentServiceName,
	HandlerType: (*AgentServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: methodHeartbeat, Handler: heartbeatHandler},
		{MethodName: methodRenew, Handler: renewHandler},
		{MethodName: methodInventory, Handler: inventoryHandler},
		{MethodName: methodKubernetesPosture, Handler: kubernetesPostureHandler},
		{MethodName: methodClaimJobs, Handler: claimJobsHandler},
		{MethodName: methodReportJobResult, Handler: reportJobResultHandler},
		{MethodName: methodRedeemJobCredential, Handler: redeemJobCredentialHandler},
		{MethodName: methodSignJobCSR, Handler: signJobCSRHandler},
		{MethodName: methodFetchWorkloadSVID, Handler: fetchWorkloadSVIDHandler},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "trstctl.agent.v1",
}

func heartbeatHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(HeartbeatRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AgentServiceServer).Heartbeat(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: fullMethodHeartbeat}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(AgentServiceServer).Heartbeat(ctx, req.(*HeartbeatRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func renewHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(RenewRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AgentServiceServer).Renew(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: fullMethodRenew}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(AgentServiceServer).Renew(ctx, req.(*RenewRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func inventoryHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(InventoryRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AgentServiceServer).ReportInventory(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: fullMethodInventory}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(AgentServiceServer).ReportInventory(ctx, req.(*InventoryRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func agentProtocolInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	switch info.FullMethod {
	case fullMethodHeartbeat, fullMethodRenew, fullMethodInventory, fullMethodKubernetesPosture:
	default:
		return handler(ctx, req)
	}
	md, _ := metadata.FromIncomingContext(ctx)
	version := 0
	if vals := md.Get(protocol.MetadataAgentProtocol); len(vals) > 0 {
		version = protocol.ParseAgentProtocolValue(vals[0])
	}
	if !protocol.Supported(version) {
		return nil, status.Errorf(codes.FailedPrecondition,
			"unsupported agent protocol %d (server supports %d..%d)",
			version, protocol.MinSupportedVersion, protocol.MaxSupportedVersion)
	}
	if err := grpc.SetHeader(ctx, metadata.Pairs(
		protocol.MetadataServerProtocol, protocol.VersionString(),
		protocol.MetadataServerCapabilities, agentCapabilitiesValue,
	)); err != nil {
		return nil, status.Errorf(codes.Internal, "set agent protocol response header: %v", err)
	}
	return handler(ctx, req)
}

// jsonCodec is a stateless gRPC CodecV2 that JSON-encodes the agent messages. It is
// selected only for calls whose content-subtype is AgentCodecName, so it never
// touches the health service's protobuf traffic.
type jsonCodec struct{}

func (jsonCodec) Name() string { return AgentCodecName }

func (jsonCodec) Marshal(v any) (mem.BufferSlice, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("transport: marshal %T: %w", v, err)
	}
	return mem.BufferSlice{mem.SliceBuffer(data)}, nil
}

func (jsonCodec) Unmarshal(data mem.BufferSlice, v any) error {
	if err := json.Unmarshal(data.Materialize(), v); err != nil {
		return fmt.Errorf("transport: unmarshal %T: %w", v, err)
	}
	return nil
}

func init() {
	encoding.RegisterCodecV2(jsonCodec{})
}

// AgentClient is the agent-side stub for the steady-state channel. It pins the
// agent-JSON content-subtype on every call so the JSON codec (not protobuf) encodes
// the messages, while the same connection's health check still uses protobuf.
type AgentClient struct {
	cc                 *grpc.ClientConn
	agentVersion       string
	protocolVersion    int
	protocolVersionSet bool
}

// ClientOption adjusts the agent steady-state client handshake metadata.
type ClientOption func(*AgentClient)

// WithAgentVersion includes the human-readable agent build version in gRPC
// metadata. Compatibility decisions use the integer protocol version, not this
// display value.
func WithAgentVersion(version string) ClientOption {
	return func(c *AgentClient) { c.agentVersion = version }
}

// WithProtocolVersion overrides the announced protocol version. Production agents
// should use the default; compatibility tests use this to pin N-1/N+1 behavior.
func WithProtocolVersion(version int) ClientOption {
	return func(c *AgentClient) {
		c.protocolVersion = version
		c.protocolVersionSet = true
	}
}

// NewAgentClient wraps an established mTLS connection (from Dial) as the agent
// service client.
func NewAgentClient(cc *grpc.ClientConn, opts ...ClientOption) *AgentClient {
	c := &AgentClient{cc: cc}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *AgentClient) withProtocol(ctx context.Context) context.Context {
	version := protocol.Version
	if c.protocolVersionSet {
		version = c.protocolVersion
	}
	pairs := []string{
		protocol.MetadataAgentProtocol, strconv.Itoa(version),
		protocol.MetadataAgentCapabilities, agentCapabilitiesValue,
	}
	if c.agentVersion != "" {
		pairs = append(pairs, protocol.MetadataAgentVersion, c.agentVersion)
	}
	return metadata.AppendToOutgoingContext(ctx, pairs...)
}

// Heartbeat sends one steady-state beat and returns the server's acknowledgement.
func (c *AgentClient) Heartbeat(ctx context.Context, req *HeartbeatRequest) (*HeartbeatResponse, error) {
	out := new(HeartbeatResponse)
	if err := c.cc.Invoke(c.withProtocol(ctx), fullMethodHeartbeat, req, out, grpc.CallContentSubtype(AgentCodecName)); err != nil {
		return nil, err
	}
	return out, nil
}

// Renew submits the agent's rotation CSR and returns the freshly minted chain.
func (c *AgentClient) Renew(ctx context.Context, req *RenewRequest) (*RenewResponse, error) {
	out := new(RenewResponse)
	if err := c.cc.Invoke(c.withProtocol(ctx), fullMethodRenew, req, out, grpc.CallContentSubtype(AgentCodecName)); err != nil {
		return nil, err
	}
	return out, nil
}

// ReportInventory sends one metadata-only host inventory batch.
func (c *AgentClient) ReportInventory(ctx context.Context, req *InventoryRequest) (*InventoryResponse, error) {
	out := new(InventoryResponse)
	if err := c.cc.Invoke(c.withProtocol(ctx), fullMethodInventory, req, out, grpc.CallContentSubtype(AgentCodecName)); err != nil {
		return nil, err
	}
	return out, nil
}

// The job claim protocol (epic A1).
//
// Estate-touching work is decided in the control plane and executed in the
// customer's environment. The control plane has no route into a host and never
// gets one, so the agent asks for work over the connection it already opened —
// the same mTLS channel it heartbeats on, the same certificate-derived tenant, no
// inbound port anywhere.
//
// ClaimJobs is a poll rather than a server-pushed stream. It is the same
// property — the agent initiates, the control plane answers — with far less
// machinery, and it degrades honestly: an agent that stops polling simply stops
// taking work, and its leases lapse.

// ClaimJobsRequest asks for up to Limit jobs of the given kinds. The tenant and
// the agent identity come from the client certificate, never from these fields.
type ClaimJobsRequest struct {
	// Kinds are the job kinds this agent is willing to execute. The server
	// intersects them with what the agent's certificate role permits; asking for
	// a kind outside that role is refused rather than quietly ignored.
	Kinds []string `json:"kinds,omitempty"`
	// Limit caps the batch. The server clamps it — an agent cannot ask for the
	// whole queue.
	Limit int `json:"limit,omitempty"`
	// LeaseSeconds is how long the agent expects to need. The server clamps this
	// too: a lease long enough to hide a dead agent for an hour is not a lease.
	LeaseSeconds int `json:"lease_seconds,omitempty"`
}

// ClaimedJob is one unit of work leased to this agent.
type ClaimedJob struct {
	JobID          int64  `json:"job_id"`
	Kind           string `json:"kind"`
	Payload        []byte `json:"payload,omitempty"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	// LeaseExpiresUnix is when this claim lapses. Past it the job is claimable by
	// anyone, so an agent that has not finished must extend or expect to lose it.
	LeaseExpiresUnix int64 `json:"lease_expires_unix,omitempty"`
	// Attempt counts how many times this job has been claimed, ever. An agent can
	// use it to back off from work it has already failed.
	Attempt int `json:"attempt,omitempty"`
}

type ClaimJobsResponse struct {
	Jobs []ClaimedJob `json:"jobs,omitempty"`
	// NextPollSeconds is the server's hint for when to ask again, jittered by the
	// server so a fleet does not synchronize into a thundering herd.
	NextPollSeconds int `json:"next_poll_seconds,omitempty"`
}

// JobResultOutcome values an agent may report.
const (
	// JobOutcomeExecuted means the agent performed the work.
	JobOutcomeExecuted = "executed"
	// JobOutcomeFailed means the agent tried and could not. The job returns to
	// the queue: a failure on one host is not evidence the work is impossible.
	JobOutcomeFailed = "failed"
	// JobOutcomeVerified means the agent performed the work AND observed the
	// endpoint serving the expected identity afterwards (epic D2). Distinct
	// from executed because "we applied it" and "it is live" are different
	// claims, and only the second one is what an operator actually wanted.
	JobOutcomeVerified = "verified"
	// JobOutcomeVerifyFailed means the work was applied and the endpoint is
	// NOT serving it. Terminal, not retryable: the job did what it was asked
	// to do, and re-running it against a listener that ignored the reload
	// would loop forever. It is the outcome that justifies a rollback, which
	// plain failure is not — rolling back a deploy that never applied would
	// undo something that was never done.
	JobOutcomeVerifyFailed = "verify_failed"
	// JobOutcomeExtend means the agent is still working and wants more lease.
	JobOutcomeExtend = "extend"
)

// ReportJobResultRequest is the agent's report on a job it holds.
type ReportJobResultRequest struct {
	JobID   int64  `json:"job_id"`
	Outcome string `json:"outcome"`
	// Detail is operator-facing text explaining a failure. It must never carry
	// credential material; the server treats it as opaque and stores it as the
	// entry's last error.
	Detail string `json:"detail,omitempty"`
	// EvidenceDigest is a digest of whatever transcript the agent produced. The
	// transcript itself stays on the agent until the verification work (WS-D)
	// defines its shape; the digest is what binds this report to it.
	EvidenceDigest string `json:"evidence_digest,omitempty"`
	// LeaseSeconds is how much more time an "extend" is asking for.
	LeaseSeconds int `json:"lease_seconds,omitempty"`
	// Attempt echoes the claim generation this report belongs to. It is part of
	// the signed statement, so a receipt cannot be replayed against a later
	// attempt of the same job after a lease lapse requeued it.
	Attempt int `json:"attempt,omitempty"`
	// IssuedAtUnix is when the agent signed. The server bounds it against its
	// own clock: a receipt held and replayed hours later is refused even though
	// its signature is perfectly valid.
	IssuedAtUnix int64 `json:"issued_at_unix,omitempty"`
	// Signature is the agent's detached signature over the canonical receipt
	// statement (epic A1), made with the same key behind its channel
	// certificate.
	//
	// mTLS already proved who is on the connection; this is what survives it.
	// Without it, "agent-7 executed this deploy" is a sentence the control plane
	// wrote about itself, and anyone who can write to the event store can write
	// that sentence. With it, the record is evidence the control plane could not
	// have produced.
	//
	// It is required for terminal outcomes. An "extend" is a lease request, not
	// a claim about the world, and is left unsigned deliberately: signing a
	// keepalive would put the agent's key on the hot path of every heartbeat for
	// no evidentiary gain.
	Signature []byte `json:"signature,omitempty"`
}

// SignedReport builds a signed terminal report for a claimed job.
//
// Both sides construct the statement through JobReceiptStatement so the bytes
// cannot drift apart, and the agent's tenant and name come from its own
// identity rather than from anything it was told — the server independently
// rebuilds them from the certificate on the connection and will not match a
// statement that claims otherwise.
func SignedReport(id StatementSigner, tenantID, commonName string, jobID int64, attempt int,
	outcome, detail, evidenceDigest string, issuedAtUnix int64) (*ReportJobResultRequest, error) {
	statement := JobReceiptStatement{
		TenantID: tenantID, AgentCommonName: commonName, JobID: jobID, Attempt: attempt,
		Outcome: outcome, EvidenceDigest: evidenceDigest,
		DetailDigest: DetailDigest(detail), IssuedAtUnix: issuedAtUnix,
	}
	if err := statement.Validate(); err != nil {
		return nil, err
	}
	sig, err := id.SignStatement(statement.Canonical())
	if err != nil {
		return nil, err
	}
	return &ReportJobResultRequest{
		JobID: jobID, Outcome: outcome, Detail: detail, EvidenceDigest: evidenceDigest,
		Attempt: attempt, IssuedAtUnix: issuedAtUnix, Signature: sig,
	}, nil
}

// StatementSigner is the agent identity's signing capability, named as an
// interface so this package never touches a private key or imports a crypto
// package (AN-3).
type StatementSigner interface {
	SignStatement(statement []byte) ([]byte, error)
}

type ReportJobResultResponse struct {
	// Accepted is false when the agent no longer holds the job — its lease
	// lapsed and somebody else took the work. The agent must stop, not retry:
	// two agents finishing the same deploy is the failure this prevents.
	Accepted bool `json:"accepted"`
	// LeaseExpiresUnix is the new lease after an accepted extend.
	LeaseExpiresUnix int64 `json:"lease_expires_unix,omitempty"`
}

// RedeemJobCredentialRequest asks for the credential material a claimed job
// references (epic A3). It carries ONLY the job id and the claim attempt: the
// tenant and the agent identity come from the certificate the caller
// authenticated with, exactly like every other call on this channel — a request
// field naming either would be a request field an attacker chooses.
type RedeemJobCredentialRequest struct {
	JobID int64 `json:"job_id"`
	// Attempt echoes the claim generation from ClaimedJob.Attempt. A redemption
	// is single-use per (job, agent, attempt): a stale generation — the lease
	// lapsed and someone else reclaimed — fails closed.
	Attempt int `json:"attempt"`
}

// RedeemedSecret is one named piece of credential material, alive for one
// attempt. Value is secret.JSONBytes so decoding never materializes a Go string
// (AN-8): the receiver moves it into a locked buffer and wipes it.
type RedeemedSecret struct {
	// Name says which reference this item satisfies: "credential.cert_pem",
	// "credential.key_pem", or the secret:// name from the target config.
	Name  string           `json:"name"`
	Value secret.JSONBytes `json:"value"`
}

// RedeemJobCredentialResponse hands over the material for exactly one attempt.
type RedeemJobCredentialResponse struct {
	// AuditRef is the public reference of the redemption row the control plane
	// recorded before answering. The console shows it; the agent includes it in
	// its evidence.
	AuditRef string `json:"audit_ref"`
	// ExpiresUnix is when this material's authorization lapses — bound to the
	// claim lease, never longer. The agent must wipe by then regardless of
	// where the attempt stands.
	ExpiresUnix int64            `json:"expires_unix"`
	Items       []RedeemedSecret `json:"items,omitempty"`
}

// AgentJobServiceServer is the optional job-claim extension of AgentService. It
// is a separate interface so an older service implementation stays
// source-compatible while a newer server exposes these methods on the same
// service.
type AgentJobServiceServer interface {
	ClaimJobs(ctx context.Context, req *ClaimJobsRequest) (*ClaimJobsResponse, error)
	ReportJobResult(ctx context.Context, req *ReportJobResultRequest) (*ReportJobResultResponse, error)
	RedeemJobCredential(ctx context.Context, req *RedeemJobCredentialRequest) (*RedeemJobCredentialResponse, error)
	// SignJobCSR signs a subject CSR the agent generated for a job it holds
	// (epic B2). It is the direction-reversal that makes host-generated keys
	// possible: everything else on this service sends material DOWN to an
	// agent, and this sends a public request UP.
	SignJobCSR(ctx context.Context, req *SignJobCSRRequest) (*SignJobCSRResponse, error)
	// FetchWorkloadSVID issues SVIDs for a workload this agent attested locally
	// (epic B3). It is the SPIRE node-API shape: the agent inspects the calling
	// process, reports what it observed, and the control plane decides which
	// identities that observation unlocks.
	FetchWorkloadSVID(ctx context.Context, req *FetchWorkloadSVIDRequest) (*FetchWorkloadSVIDResponse, error)
}

// FetchWorkloadSVIDRequest asks for the SVIDs a locally attested workload is
// entitled to (epic B3).
//
// The key is the workload's, generated on the host that runs it, and only its
// PUBLIC half travels — the same inversion B2 made for endpoint certificates.
// Before this, the Workload API lived on the control plane and minted SVID
// private keys there, which meant a workload's identity key existed on a machine
// the workload does not run on.
type FetchWorkloadSVIDRequest struct {
	// PublicKeyDER is the workload's public key, PKIX DER. There is no private
	// counterpart in this message and there must never be one.
	PublicKeyDER []byte `json:"public_key_der"`
	// Selectors are what the agent OBSERVED about the calling process — uid,
	// gid, binary path. They are a claim, and the control plane bounds what that
	// claim can unlock by scoping registration entries to this node: the agent
	// is authenticated by its channel certificate, and only entries whose
	// ParentID names that agent are considered. An agent asserting selectors it
	// did not observe can therefore reach the workloads on its own machine and
	// nothing else in the trust domain.
	Selectors []string `json:"selectors,omitempty"`
	// Audience requests JWT-SVIDs instead of X.509-SVIDs when non-empty.
	Audience []string `json:"audience,omitempty"`
}

// FetchWorkloadSVIDResponse returns the issued SVIDs and the trust bundle.
type FetchWorkloadSVIDResponse struct {
	X509SVIDs []WorkloadX509SVID `json:"x509_svids,omitempty"`
	JWTSVIDs  []WorkloadJWTSVID  `json:"jwt_svids,omitempty"`
	// Bundle is the trust domain's X.509 authorities, DER-encoded.
	Bundle [][]byte `json:"bundle,omitempty"`
}

// WorkloadX509SVID is one issued X.509-SVID.
//
// Certificate material only. The workload already holds the private half —
// it never left the host — so there is nothing for this message to carry.
type WorkloadX509SVID struct {
	SPIFFEID      string   `json:"spiffe_id"`
	CertChainDER  [][]byte `json:"cert_chain_der"`
	ExpiresAtUnix int64    `json:"expires_at_unix,omitempty"`
	FederatesWith []string `json:"federates_with,omitempty"`
	Hint          string   `json:"hint,omitempty"`
}

// WorkloadJWTSVID is one issued JWT-SVID.
type WorkloadJWTSVID struct {
	SPIFFEID      string `json:"spiffe_id"`
	Token         string `json:"token"`
	ExpiresAtUnix int64  `json:"expires_at_unix,omitempty"`
}

// SignJobCSRRequest carries a PKCS#10 the agent built from a key it generated
// locally (epic B2).
//
// It carries no key and cannot: a CSR is the public half plus the requested
// names. That is the entire point — the previous flow shipped a private key
// down to the agent, and this replaces it with a public request coming up.
type SignJobCSRRequest struct {
	// JobID scopes the request to work this agent actually holds. The control
	// plane re-reads the job's own payload to decide what may be certified, so
	// an agent cannot widen its request by asking for extra names: the CSR's
	// subject is validated against the binding the job was queued for, not
	// taken on trust.
	JobID int64 `json:"job_id"`
	// Attempt is the claim generation, so a CSR from a lapsed lease cannot be
	// signed after the work has been reassigned.
	Attempt int `json:"attempt"`
	// CSRDER is the PKCS#10, DER-encoded.
	CSRDER []byte `json:"csr_der"`
}

// SignJobCSRResponse returns the issued chain.
//
// Certificate material only. There is no key field and there must never be one:
// a response shape that could carry a key would make the security property of
// this epic a convention rather than a structure.
type SignJobCSRResponse struct {
	// CertificatePEM is the issued leaf, PEM-encoded.
	CertificatePEM []byte `json:"certificate_pem"`
	// ChainPEM is the issuer chain to serve alongside it.
	ChainPEM []byte `json:"chain_pem,omitempty"`
	// Fingerprint is the SHA-256 of the leaf, so the agent can verify against
	// exactly what was issued without re-deriving it.
	Fingerprint string `json:"fingerprint,omitempty"`
}

// gRPC method names and their full paths. "RedeemJobCredential" names an RPC;
// it holds no credential and never has — the material it returns is byte-backed
// in RedeemedSecret.Value and wiped by the handler.
const (
	methodClaimJobs       = "ClaimJobs"
	methodReportJobResult = "ReportJobResult"
	// #nosec G101 -- an RPC method name, not a credential. The material this
	// call returns is byte-backed in RedeemedSecret.Value and wiped by the
	// handler; nothing here holds a secret (CWE-798).
	methodRedeemJobCredential     = "RedeemJobCredential"
	fullMethodClaimJobs           = "/" + agentServiceName + "/" + methodClaimJobs
	fullMethodReportJobResult     = "/" + agentServiceName + "/" + methodReportJobResult
	fullMethodRedeemJobCredential = "/" + agentServiceName + "/" + methodRedeemJobCredential
	// #nosec G101 -- an RPC method name. This call carries a CSR up and returns
	// certificates down; no key material crosses it in either direction, which
	// is the entire point of epic B2 (CWE-798).
	methodSignJobCSR     = "SignJobCSR"
	fullMethodSignJobCSR = "/" + agentServiceName + "/" + methodSignJobCSR
	// B3: the workload-identity node API. Carries a public key up and SVIDs
	// down; no private key crosses it in either direction.
	methodFetchWorkloadSVID     = "FetchWorkloadSVID"
	fullMethodFetchWorkloadSVID = "/" + agentServiceName + "/" + methodFetchWorkloadSVID
)

func claimJobsHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(ClaimJobsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	jobs, ok := srv.(AgentJobServiceServer)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "this control plane does not serve the agent job ledger")
	}
	if interceptor == nil {
		return jobs.ClaimJobs(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: fullMethodClaimJobs}
	handler := func(ctx context.Context, req any) (any, error) {
		return jobs.ClaimJobs(ctx, req.(*ClaimJobsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func redeemJobCredentialHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(RedeemJobCredentialRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	jobs, ok := srv.(AgentJobServiceServer)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "this control plane does not serve the agent job ledger")
	}
	if interceptor == nil {
		return jobs.RedeemJobCredential(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: fullMethodRedeemJobCredential}
	handler := func(ctx context.Context, req any) (any, error) {
		return jobs.RedeemJobCredential(ctx, req.(*RedeemJobCredentialRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func signJobCSRHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(SignJobCSRRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	jobs, ok := srv.(AgentJobServiceServer)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "this control plane does not serve the agent job ledger")
	}
	if interceptor == nil {
		return jobs.SignJobCSR(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: fullMethodSignJobCSR}
	handler := func(ctx context.Context, req any) (any, error) {
		return jobs.SignJobCSR(ctx, req.(*SignJobCSRRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func fetchWorkloadSVIDHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(FetchWorkloadSVIDRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	jobs, ok := srv.(AgentJobServiceServer)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "this control plane does not serve the agent job ledger")
	}
	if interceptor == nil {
		return jobs.FetchWorkloadSVID(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: fullMethodFetchWorkloadSVID}
	handler := func(ctx context.Context, req any) (any, error) {
		return jobs.FetchWorkloadSVID(ctx, req.(*FetchWorkloadSVIDRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func reportJobResultHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(ReportJobResultRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	jobs, ok := srv.(AgentJobServiceServer)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "this control plane does not serve the agent job ledger")
	}
	if interceptor == nil {
		return jobs.ReportJobResult(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: fullMethodReportJobResult}
	handler := func(ctx context.Context, req any) (any, error) {
		return jobs.ReportJobResult(ctx, req.(*ReportJobResultRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// ClaimJobs asks the control plane for work this agent may execute.
func (c *AgentClient) ClaimJobs(ctx context.Context, req *ClaimJobsRequest) (*ClaimJobsResponse, error) {
	out := new(ClaimJobsResponse)
	if err := c.cc.Invoke(c.withProtocol(ctx), fullMethodClaimJobs, req, out, grpc.CallContentSubtype(AgentCodecName)); err != nil {
		return nil, err
	}
	return out, nil
}

// RedeemJobCredential asks for the credential material a claimed job
// references (epic A3). It is callable once per (job, attempt): a replay, or a
// call after the lease lapsed, returns PermissionDenied with no detail. The
// caller must move each returned value into a locked buffer and wipe it when
// the attempt ends.
func (c *AgentClient) RedeemJobCredential(ctx context.Context, req *RedeemJobCredentialRequest) (*RedeemJobCredentialResponse, error) {
	out := new(RedeemJobCredentialResponse)
	if err := c.cc.Invoke(c.withProtocol(ctx), fullMethodRedeemJobCredential, req, out, grpc.CallContentSubtype(AgentCodecName)); err != nil {
		return nil, err
	}
	return out, nil
}

// SignJobCSR sends a locally generated CSR up to be signed (epic B2).
//
// The request carries a PKCS#10 and a job reference. It cannot carry a key, and
// the response cannot return one: that structural fact is what lets an operator
// say the private half never left the host and have it be true rather than a
// promise about how the code is used.
func (c *AgentClient) SignJobCSR(ctx context.Context, req *SignJobCSRRequest) (*SignJobCSRResponse, error) {
	out := new(SignJobCSRResponse)
	if err := c.cc.Invoke(c.withProtocol(ctx), fullMethodSignJobCSR, req, out, grpc.CallContentSubtype(AgentCodecName)); err != nil {
		return nil, err
	}
	return out, nil
}

// FetchWorkloadSVID asks for SVIDs for a workload this agent attested (epic B3).
func (c *AgentClient) FetchWorkloadSVID(ctx context.Context, req *FetchWorkloadSVIDRequest) (*FetchWorkloadSVIDResponse, error) {
	out := new(FetchWorkloadSVIDResponse)
	if err := c.cc.Invoke(c.withProtocol(ctx), fullMethodFetchWorkloadSVID, req, out, grpc.CallContentSubtype(AgentCodecName)); err != nil {
		return nil, err
	}
	return out, nil
}

// ReportJobResult reports the outcome of a job this agent holds.
func (c *AgentClient) ReportJobResult(ctx context.Context, req *ReportJobResultRequest) (*ReportJobResultResponse, error) {
	out := new(ReportJobResultResponse)
	if err := c.cc.Invoke(c.withProtocol(ctx), fullMethodReportJobResult, req, out, grpc.CallContentSubtype(AgentCodecName)); err != nil {
		return nil, err
	}
	return out, nil
}
