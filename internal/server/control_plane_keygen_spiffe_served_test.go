// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/events"
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
	// The record says what happened and why (the lab replay found refusals
	// recorded as "this SVID was issued").
	expectLocalSocketUse(t, h, "x509_refused", "control-plane key generation is off")
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

// expectLocalSocketUse finds a spiffe.workload_api.local_socket_used record of
// the given type whose detail gives the reason, and fails if any refusal
// record claims that an SVID was issued.
func expectLocalSocketUse(t *testing.T, h *servedHarness, kind, why string) {
	t.Helper()
	found := false
	if err := h.log.Replay(context.Background(), 0, func(e events.Event) error {
		if e.Type != "spiffe.workload_api.local_socket_used" || e.TenantID != h.tenant {
			return nil
		}
		var use struct {
			Type   string `json:"type"`
			Detail string `json:"detail"`
		}
		if err := json.Unmarshal(e.Data, &use); err != nil {
			return err
		}
		if strings.HasSuffix(use.Type, "_refused") && strings.Contains(use.Detail, "was issued") {
			t.Errorf("the %s record says an SVID was issued: %s", use.Type, use.Detail)
		}
		if use.Type == kind && strings.Contains(use.Detail, why) {
			found = true
		}
		return nil
	}); err != nil {
		t.Fatalf("replay events: %v", err)
	}
	if !found {
		t.Fatalf("no %s local-socket record saying %q", kind, why)
	}
}
