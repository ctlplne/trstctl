package transport

// This file defines the served agent steady-state RPC contract (WIRE-004): the
// two methods an enrolled agent calls on the control plane over the mutual-TLS
// channel, plus a self-contained gRPC wire codec so the contract needs no protoc
// toolchain in the build.
//
// Wire format. The two agent methods carry plain Go structs encoded as JSON under
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

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/mem"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

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
	AgentCapabilityHeartbeat = "heartbeat"
	AgentCapabilityRenew     = "renew"
)

const agentCapabilitiesValue = AgentCapabilityHeartbeat + "," + AgentCapabilityRenew

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
}

// agentServiceName / method names are the gRPC routing identifiers. They are fixed
// strings the client and server both use; changing them is a wire-breaking change.
const (
	agentServiceName    = "trstctl.agent.v1.AgentService"
	methodHeartbeat     = "Heartbeat"
	methodRenew         = "Renew"
	fullMethodHeartbeat = "/" + agentServiceName + "/" + methodHeartbeat
	fullMethodRenew     = "/" + agentServiceName + "/" + methodRenew
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

func agentProtocolInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	switch info.FullMethod {
	case fullMethodHeartbeat, fullMethodRenew:
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
