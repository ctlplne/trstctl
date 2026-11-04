// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/cli/evaluate"
	"trstctl.com/trstctl/internal/config"
)

// A249: `trstctl evaluate --journeys workload` passes against a served
// control plane's Workload API socket — a real X.509-SVID chained to the
// served CA, a JWT-SVID verified against the served JWT bundle, and the
// socket's own validation refusing the token for another audience — and its
// forced failure is reported as a failure.
func TestServedEvaluateWorkloadJourneyA249(t *testing.T) {
	socketDir, err := os.MkdirTemp("", "trstctl-a249-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "w.sock")
	h := newOperatingServedHarness(t, config.Protocols{
		SPIFFE: config.SPIFFEProtocol{
			Enabled: true, TenantID: servedTestTenant, TrustDomain: "served.test", SocketPath: socket,
			// The control plane's own socket issues to local workloads only
			// when opted in (A85), as a lab does.
			ServeLocalWorkloads: true,
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); h.srv.RunSPIFFE(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	waitForSocket(t, socket, 5*time.Second)

	// The workload journey calls no API route; the command still needs an
	// operator token, so it gets a read-only one.
	token := seedScopedToken(t, h.store, h.tenant, "certs:read")
	run := func(force string) evaluate.Pack {
		t.Helper()
		pack, err := evaluate.Evaluate(t.Context(), evaluate.Options{
			Server: h.ts.URL, Token: token, HTTPClient: h.ts.Client(),
			Journeys: []string{evaluate.JourneyWorkload}, WorkloadSocket: "unix://" + socket, ForceFailure: force,
			Timeout: time.Minute,
		})
		if err != nil {
			t.Fatal(err)
		}
		return pack
	}
	statuses := func(steps []evaluate.Step) string {
		out := make([]string, 0, len(steps))
		for _, s := range steps {
			out = append(out, s.Name+"="+string(s.Status)+" ("+s.Detail+")")
		}
		return strings.Join(out, "\n")
	}

	pack := run("")
	if pack.Verdict != evaluate.StatusPass || len(pack.Journeys) != 1 || pack.Journeys[0].Verdict != evaluate.StatusPass {
		t.Fatalf("the workload journey against the served socket: %s\n%s", pack.Verdict, statuses(pack.Journeys[0].Steps))
	}
	if id := pack.Journeys[0].Steps[0].Evidence["spiffe_id"]; !strings.HasPrefix(id, "spiffe://served.test/") {
		t.Fatalf("SPIFFE ID = %q, want one in the served trust domain", id)
	}
	if !h.hasEvent(t, "spiffe.svid.issued") {
		t.Fatal("the journey's SVIDs were not recorded as spiffe.svid.issued")
	}

	forced := run(evaluate.JourneyWorkload)
	steps := forced.Journeys[0].Steps
	if forced.Verdict != evaluate.StatusFail || len(steps) != 3 || steps[2].Status != evaluate.StatusFail ||
		steps[0].Status != evaluate.StatusPass || steps[1].Status != evaluate.StatusPass ||
		!strings.Contains(steps[2].Detail, "refused it") {
		t.Fatalf("a forced workload failure: %s\n%s", forced.Verdict, statuses(steps))
	}
}
