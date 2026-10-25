// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/protocols/spiffe/workloadpb"
)

// A85: the control plane's own Workload API socket was retained for one
// release so operators could see which workloads had not moved to their host
// agent's socket. That release is over. By default the socket now refuses to
// issue SVIDs, naming the host socket and the explicit switch, while still
// serving trust bundles and JWT validation to validators; the refusal is
// recorded in the same audit event the retention used, so the operator still
// sees who is dialing the old path. protocols.spiffe.serve_local_workloads
// keeps issuance on, explicitly and audited, for the rare single-box case.

func servedSPIFFEWorkloadClient(t *testing.T, serveLocal bool) (*servedHarness, workloadpb.SpiffeWorkloadAPIClient, string) {
	t.Helper()
	socketDir, err := os.MkdirTemp("", "trstctl-spiffe-a85-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "s.sock")
	h := newOperatingServedHarness(t, config.Protocols{SPIFFE: config.SPIFFEProtocol{
		Enabled: true, TenantID: servedTestTenant, TrustDomain: "served.test", SocketPath: socket, ServeLocalWorkloads: serveLocal,
	}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); h.srv.RunSPIFFE(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	waitForSocket(t, socket, 5*time.Second)
	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return h, workloadpb.NewSpiffeWorkloadAPIClient(conn), socket
}

func servedSPIFFEQualificationA85(t *testing.T, h *servedHarness) api.SPIFFEQualification {
	t.Helper()
	readToken := seedAPITokenWithScopes(t, h.store, servedTestTenant, []string{"certs:read"})
	req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/api/v1/protocols/spiffe/qualification", nil)
	req.Header.Set("Authorization", "Bearer "+readToken)
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := readAllClose(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("qualification status %d: %s", resp.StatusCode, body)
	}
	var out api.SPIFFEQualification
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode qualification: %v %s", err, body)
	}
	return out
}

func TestServedControlPlaneSocketRefusesWorkloadIssuanceByDefaultA85(t *testing.T) {
	h, client, socket := servedSPIFFEWorkloadClient(t, false)
	md := metadata.Pairs(spiffeSecurityHeader())
	ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), md), 10*time.Second)
	defer cancel()

	stream, err := client.FetchX509SVID(ctx, &workloadpb.X509SVIDRequest{})
	if err != nil {
		t.Fatalf("FetchX509SVID open: %v", err)
	}
	_, err = stream.Recv()
	st, _ := status.FromError(err)
	if err == nil || st.Code() != codes.PermissionDenied || !strings.Contains(st.Message(), "--workload-api-socket") || !strings.Contains(st.Message(), "serve_local_workloads") {
		t.Fatalf("control-plane FetchX509SVID = %v, want PermissionDenied naming the host socket and the switch", err)
	}
	_, err = client.FetchJWTSVID(ctx, &workloadpb.JWTSVIDRequest{Audience: []string{"api.served.test"}})
	if st, _ := status.FromError(err); err == nil || st.Code() != codes.PermissionDenied || !strings.Contains(st.Message(), "--workload-api-socket") {
		t.Fatalf("control-plane FetchJWTSVID = %v, want PermissionDenied naming the host socket", err)
	}
	// Validators still get bundles from this socket: refusing issuance is not
	// turning the trust domain off.
	bundles, err := client.FetchX509Bundles(ctx, &workloadpb.X509BundlesRequest{})
	if err != nil {
		t.Fatalf("FetchX509Bundles open: %v", err)
	}
	if resp, err := bundles.Recv(); err != nil || len(resp.GetBundles()["served.test"]) == 0 {
		t.Fatalf("FetchX509Bundles on the control-plane socket = %v %v, want the served.test bundle", resp.GetBundles(), err)
	}
	jwtBundles, err := client.FetchJWTBundles(ctx, &workloadpb.JWTBundlesRequest{})
	if err != nil {
		t.Fatalf("FetchJWTBundles open: %v", err)
	}
	if resp, err := jwtBundles.Recv(); err != nil || len(resp.GetBundles()) == 0 {
		t.Fatalf("FetchJWTBundles on the control-plane socket = %v %v, want a bundle", resp.GetBundles(), err)
	}
	if h.hasEvent(t, "spiffe.svid.issued") {
		t.Fatal("the control-plane socket minted an SVID with serve_local_workloads off")
	}
	// The operator still sees who dials the old path.
	expectLocalSocketUse(t, h, "x509_refused", "serve_local_workloads is off")
	expectLocalSocketUse(t, h, "jwt_refused", "serve_local_workloads is off")
	qualification := servedSPIFFEQualificationA85(t, h)
	if qualification.LocalWorkloadsServed || !qualification.LocalSocketDeprecated || qualification.SocketURI != "unix://"+socket {
		t.Fatalf("qualification = %+v, want local_workloads_served=false on the control-plane socket", qualification)
	}
	if !qualification.Ready {
		t.Fatalf("qualification not ready with issuance refused by default: blockers=%v", qualification.Blockers)
	}
	var named bool
	for _, op := range qualification.SupportedOperations {
		if op == "FetchX509SVID" {
			named = true
		}
	}
	if named {
		t.Fatalf("supported_operations %v still advertises FetchX509SVID on a socket that refuses it", qualification.SupportedOperations)
	}
}

func TestServedControlPlaneSocketServesWorkloadsOnlyWhenOptedInA85(t *testing.T) {
	h, client, _ := servedSPIFFEWorkloadClient(t, true)
	md := metadata.Pairs(spiffeSecurityHeader())
	ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), md), 10*time.Second)
	defer cancel()
	stream, err := client.FetchX509SVID(ctx, &workloadpb.X509SVIDRequest{})
	if err != nil {
		t.Fatalf("FetchX509SVID open: %v", err)
	}
	resp, err := stream.Recv()
	if err != nil || len(resp.GetSvids()) == 0 {
		t.Fatalf("opted-in control-plane FetchX509SVID = %v %v, want an SVID", resp, err)
	}
	if !h.hasEvent(t, "spiffe.workload_api.local_socket_used") {
		t.Fatal("an opted-in local issuance left no local_socket_used record")
	}
	qualification := servedSPIFFEQualificationA85(t, h)
	if !qualification.LocalWorkloadsServed || !qualification.LocalSocketDeprecated {
		t.Fatalf("qualification = %+v, want local_workloads_served=true when opted in", qualification)
	}
}
