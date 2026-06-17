package transport_test

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/protocol"
)

const bufSize = 1024 * 1024

type compatAgentService struct{}

func (compatAgentService) Heartbeat(context.Context, *transport.HeartbeatRequest) (*transport.HeartbeatResponse, error) {
	return &transport.HeartbeatResponse{TenantID: "11111111-1111-1111-1111-111111111111", NextHeartbeatSeconds: 30}, nil
}

func (compatAgentService) Renew(context.Context, *transport.RenewRequest) (*transport.RenewResponse, error) {
	return &transport.RenewResponse{CertChainPEM: []byte("test-chain"), NotAfterUnix: time.Now().Add(time.Hour).Unix()}, nil
}

func startCompatAgentService(t *testing.T, svc transport.AgentServiceServer) *grpc.ClientConn {
	t.Helper()
	if svc == nil {
		svc = compatAgentService{}
	}
	lis := bufconn.Listen(bufSize)
	srv := transport.NewServer(insecure.NewCredentials(), svc)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///agent-bufconn",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestAgentHeartbeatProtocolCompatWindow(t *testing.T) {
	conn := startCompatAgentService(t, nil)
	for _, version := range []int{0, protocol.MinSupportedVersion, protocol.Version, protocol.MaxSupportedVersion} {
		client := transport.NewAgentClient(conn, transport.WithProtocolVersion(version), transport.WithAgentVersion("test-agent"))
		if _, err := client.Heartbeat(context.Background(), &transport.HeartbeatRequest{AgentID: "edge", Status: "active"}); err != nil {
			t.Fatalf("Heartbeat protocol %d rejected: %v", version, err)
		}
	}
}

func TestAgentRenewProtocolCompatWindow(t *testing.T) {
	conn := startCompatAgentService(t, nil)
	for _, version := range []int{0, protocol.MinSupportedVersion, protocol.Version, protocol.MaxSupportedVersion} {
		client := transport.NewAgentClient(conn, transport.WithProtocolVersion(version))
		if _, err := client.Renew(context.Background(), &transport.RenewRequest{CSRDER: []byte{0x30, 0x01}}); err != nil {
			t.Fatalf("Renew protocol %d rejected: %v", version, err)
		}
	}
}

func TestAgentProtocolRejectsTooNewHeartbeatAndRenew(t *testing.T) {
	conn := startCompatAgentService(t, nil)
	client := transport.NewAgentClient(conn, transport.WithProtocolVersion(protocol.MaxSupportedVersion+1))
	for name, call := range map[string]func() error{
		"Heartbeat": func() error {
			_, err := client.Heartbeat(context.Background(), &transport.HeartbeatRequest{AgentID: "edge"})
			return err
		},
		"Renew": func() error {
			_, err := client.Renew(context.Background(), &transport.RenewRequest{CSRDER: []byte{0x30, 0x01}})
			return err
		},
	} {
		err := call()
		if err == nil {
			t.Fatalf("%s accepted protocol %d", name, protocol.MaxSupportedVersion+1)
		}
		if got := status.Code(err); got != codes.FailedPrecondition {
			t.Fatalf("%s rejection code = %s, want FailedPrecondition (%v)", name, got, err)
		}
	}
}

func TestAgentProtocolResponseHeaderAndLegacyMissingMetadata(t *testing.T) {
	conn := startCompatAgentService(t, nil)
	var hdr metadata.MD
	ctx := metadata.AppendToOutgoingContext(context.Background(),
		protocol.MetadataAgentProtocol, strconv.Itoa(protocol.Version),
		protocol.MetadataAgentCapabilities, transport.AgentCapabilityHeartbeat+","+transport.AgentCapabilityRenew,
		protocol.MetadataAgentVersion, "test-agent")
	var out transport.HeartbeatResponse
	if err := conn.Invoke(ctx, "/trstctl.agent.v1.AgentService/Heartbeat", &transport.HeartbeatRequest{AgentID: "edge"}, &out,
		grpc.CallContentSubtype(transport.AgentCodecName), grpc.Header(&hdr)); err != nil {
		t.Fatalf("raw heartbeat with protocol metadata failed: %v", err)
	}
	if got := hdr.Get(protocol.MetadataServerProtocol); len(got) != 1 || got[0] != protocol.VersionString() {
		t.Fatalf("server protocol header = %v, want %s", got, protocol.VersionString())
	}
	wantCapabilities := transport.AgentCapabilityHeartbeat + "," + transport.AgentCapabilityRenew
	if got := hdr.Get(protocol.MetadataServerCapabilities); len(got) != 1 || got[0] != wantCapabilities {
		t.Fatalf("server capabilities header = %v, want %s", got, wantCapabilities)
	}

	var legacyOut transport.HeartbeatResponse
	if err := conn.Invoke(context.Background(), "/trstctl.agent.v1.AgentService/Heartbeat", &transport.HeartbeatRequest{AgentID: "legacy"}, &legacyOut,
		grpc.CallContentSubtype(transport.AgentCodecName)); err != nil {
		t.Fatalf("legacy heartbeat with no protocol metadata should be treated as baseline: %v", err)
	}
}

type recordingAgentService struct {
	compatAgentService
	seen chan metadata.MD
}

func (s recordingAgentService) Heartbeat(ctx context.Context, req *transport.HeartbeatRequest) (*transport.HeartbeatResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	s.seen <- md.Copy()
	return s.compatAgentService.Heartbeat(ctx, req)
}

func TestAgentClientSendsProtocolCapabilitiesAndVersionMetadata(t *testing.T) {
	seen := make(chan metadata.MD, 1)
	conn := startCompatAgentService(t, recordingAgentService{seen: seen})
	client := transport.NewAgentClient(conn, transport.WithAgentVersion("test-agent"))
	if _, err := client.Heartbeat(context.Background(), &transport.HeartbeatRequest{AgentID: "edge"}); err != nil {
		t.Fatalf("heartbeat failed: %v", err)
	}
	md := <-seen
	if got := md.Get(protocol.MetadataAgentProtocol); len(got) != 1 || got[0] != protocol.VersionString() {
		t.Fatalf("agent protocol metadata = %v, want %s", got, protocol.VersionString())
	}
	wantCapabilities := transport.AgentCapabilityHeartbeat + "," + transport.AgentCapabilityRenew
	if got := md.Get(protocol.MetadataAgentCapabilities); len(got) != 1 || got[0] != wantCapabilities {
		t.Fatalf("agent capabilities metadata = %v, want %s", got, wantCapabilities)
	}
	if got := md.Get(protocol.MetadataAgentVersion); len(got) != 1 || got[0] != "test-agent" {
		t.Fatalf("agent version metadata = %v, want test-agent", got)
	}
}
