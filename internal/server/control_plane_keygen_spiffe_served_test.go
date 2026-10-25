// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/protocols/spiffe/workloadpb"
	"trstctl.com/trstctl/internal/store"
)

// Owner decision 2026-10-24: the compatibility Workload API socket generates
// each X.509-SVID key in the control plane, so the tenant's switch governs it
// too, even where serve_local_workloads keeps the socket issuing. With it off
// an X.509-SVID is refused before its key exists, naming the host agent's
// socket; a JWT-SVID carries no key and is still issued.
func TestServedKeygenOffRefusesCompatibilitySocketX509SVIDs(t *testing.T) {
	h, client, _ := servedSPIFFEWorkloadClient(t, true)
	setKeygen := func(enabled bool) {
		t.Helper()
		if _, err := h.srv.orch.SetControlPlaneKeygen(t.Context(), servedTestTenant, projections.ControlPlaneKeygenSet{
			Enabled: enabled, Source: store.ControlPlaneKeygenSourceOperator, Reason: "compatibility socket check", SetBy: "ops@example.test",
		}); err != nil {
			t.Fatal(err)
		}
	}
	fetchX509 := func() error {
		t.Helper()
		ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), metadata.Pairs(spiffeSecurityHeader())), 10*time.Second)
		defer cancel()
		stream, err := client.FetchX509SVID(ctx, &workloadpb.X509SVIDRequest{})
		if err != nil {
			return err
		}
		resp, err := stream.Recv()
		if err == nil && len(resp.GetSvids()) == 0 {
			t.Fatal("an X509-SVID response carried no SVID")
		}
		return err
	}
	setKeygen(false)
	err := fetchX509()
	st, _ := status.FromError(err)
	if err == nil || st.Code() != codes.PermissionDenied || !strings.Contains(st.Message(), "control-plane key generation is off") ||
		!strings.Contains(st.Message(), "--workload-api-socket") {
		t.Fatalf("FetchX509SVID with the switch off = %v, want PermissionDenied naming the switch and the host socket", err)
	}
	if h.hasEvent(t, "spiffe.svid.issued") {
		t.Fatal("the socket minted an SVID with control-plane key generation off")
	}
	if !h.hasEvent(t, "spiffe.workload_api.local_socket_used") {
		t.Fatal("the refused fetch left no spiffe.workload_api.local_socket_used record")
	}
	ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), metadata.Pairs(spiffeSecurityHeader())), 10*time.Second)
	defer cancel()
	if resp, err := client.FetchJWTSVID(ctx, &workloadpb.JWTSVIDRequest{Audience: []string{"api.served.test"}}); err != nil || len(resp.GetSvids()) == 0 {
		t.Fatalf("FetchJWTSVID with the switch off = %v %v, want a JWT-SVID (it carries no key)", resp, err)
	}
	setKeygen(true)
	if err := fetchX509(); err != nil {
		t.Fatalf("FetchX509SVID with the switch back on: %v", err)
	}
}
