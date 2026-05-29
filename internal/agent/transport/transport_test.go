package transport_test

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"certctl.io/certctl/internal/agent/transport"
	"certctl.io/certctl/internal/crypto/mtls"
)

const serverName = "agent.certctl.local"

// serve issues a server cert from ca and serves the agent gRPC over mTLS,
// returning the listen address.
func serve(t *testing.T, ca *mtls.CA) string {
	t.Helper()
	serverCert, err := ca.IssueServerCertificate([]string{serverName}, time.Hour)
	if err != nil {
		t.Fatalf("issue server cert: %v", err)
	}
	srv := transport.NewServer(mtls.ServerCredentials(serverCert, ca.Pool()))
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String()
}

// checkHealth dials the server with the given credentials and calls the health
// RPC, returning the call error (nil on a successful mTLS handshake + call).
func checkHealth(t *testing.T, addr string, creds credentials.TransportCredentials) error {
	t.Helper()
	conn, err := transport.Dial(addr, creds)
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	return err
}

func TestAgentEstablishesMTLS(t *testing.T) {
	ca, err := mtls.NewCA("ca")
	if err != nil {
		t.Fatal(err)
	}
	addr := serve(t, ca)
	clientCert, err := ca.IssueClientCertificate("agent-1", mtls.ClientCertTTL)
	if err != nil {
		t.Fatal(err)
	}
	creds := mtls.ClientCredentials(mtls.StaticSource(clientCert), ca.Pool(), serverName, nil)
	if err := checkHealth(t, addr, creds); err != nil {
		t.Fatalf("valid mTLS health check failed: %v", err)
	}
}

func TestAgentRefusedWithoutClientCert(t *testing.T) {
	ca, err := mtls.NewCA("ca")
	if err != nil {
		t.Fatal(err)
	}
	addr := serve(t, ca)
	// A client that presents no certificate (nil source).
	creds := mtls.ClientCredentials(nil, ca.Pool(), serverName, nil)
	if err := checkHealth(t, addr, creds); err == nil {
		t.Fatal("server accepted a connection with no client certificate")
	}
}

func TestAgentRefusedWithUntrustedCA(t *testing.T) {
	ca, err := mtls.NewCA("ca")
	if err != nil {
		t.Fatal(err)
	}
	addr := serve(t, ca)
	other, err := mtls.NewCA("other")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := other.IssueClientCertificate("imposter", mtls.ClientCertTTL)
	if err != nil {
		t.Fatal(err)
	}
	creds := mtls.ClientCredentials(mtls.StaticSource(cert), ca.Pool(), serverName, nil)
	if err := checkHealth(t, addr, creds); err == nil {
		t.Fatal("server accepted a client cert issued by an untrusted CA")
	}
}

func TestNoPlaintextFallback(t *testing.T) {
	ca, err := mtls.NewCA("ca")
	if err != nil {
		t.Fatal(err)
	}
	addr := serve(t, ca)
	if err := checkHealth(t, addr, insecure.NewCredentials()); err == nil {
		t.Fatal("server accepted a plaintext (insecure) connection")
	}
}

func TestServerCertPinning(t *testing.T) {
	ca, err := mtls.NewCA("ca")
	if err != nil {
		t.Fatal(err)
	}
	serverCert, err := ca.IssueServerCertificate([]string{serverName}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srv := transport.NewServer(mtls.ServerCredentials(serverCert, ca.Pool()))
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	addr := lis.Addr().String()

	clientCert, err := ca.IssueClientCertificate("agent-1", mtls.ClientCertTTL)
	if err != nil {
		t.Fatal(err)
	}

	goodPin := mtls.PinServer(serverCert)
	if err := checkHealth(t, addr, mtls.ClientCredentials(mtls.StaticSource(clientCert), ca.Pool(), serverName, &goodPin)); err != nil {
		t.Fatalf("agent rejected the server it correctly pinned: %v", err)
	}

	// A pin for a different server certificate must be refused.
	otherServer, err := ca.IssueServerCertificate([]string{serverName}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	wrongPin := mtls.PinServer(otherServer)
	if err := checkHealth(t, addr, mtls.ClientCredentials(mtls.StaticSource(clientCert), ca.Pool(), serverName, &wrongPin)); err == nil {
		t.Fatal("agent accepted a server whose certificate did not match the pin")
	}
}
