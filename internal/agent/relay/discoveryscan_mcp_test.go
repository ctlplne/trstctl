// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"trstctl.com/trstctl/internal/discovery/mcpprobe"
	"trstctl.com/trstctl/internal/discovery/segmentscan"
)

// TestTheRelaySweepFindsMCPEndpointsOnlyWhereTheSweepMayGoP7 (A20, A22): a
// network sweep with the MCP probe on finds an MCP server on its target, and its
// report validates; without the sweep's loopback permission the same target is not
// approved and is never contacted.
func TestTheRelaySweepFindsMCPEndpointsOnlyWhereTheSweepMayGoP7(t *testing.T) {
	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path != "/mcp" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"issues","version":"1.0.0"}}}`)
	}))
	defer srv.Close()
	target := strings.TrimPrefix(srv.URL, "http://")
	intent := DiscoveryScanIntent{ID: "run-1", SourceID: "source-1", Execution: segmentscan.ExecutionRelay, Mode: DiscoveryModeTLS,
		RequiredAgentRole: segmentscan.RequiredRoleNetwork, Targets: []string{target}, AllowLoopback: true,
		MCP: true, MCPSchemes: []string{"http"}}
	report, err := Sweep(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.MCPFindings) != 1 || report.MCPFindings[0].Target != target || report.MCPFindings[0].Observation.Auth != mcpprobe.AuthNone {
		t.Fatalf("MCP findings = %+v", report.MCPFindings)
	}
	if err := segmentscan.ValidateReport(intent, report); err != nil {
		t.Fatalf("the sweep's report does not validate: %v", err)
	}

	before := requests.Load()
	intent.AllowLoopback = false
	report, err = Sweep(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.MCPFindings) != 0 || requests.Load() != before {
		t.Fatalf("an unapproved target was probed: findings=%+v requests=%d->%d", report.MCPFindings, before, requests.Load())
	}
}

// TestTheRelaySweepSendsNothingOverAnUnverifiedTLSConnectionP7 (A22): an MCP
// server on HTTPS under a private CA is never sent the probe while the sweep does
// not trust that CA (the handshake fails before any request); with the operator's
// CA bundle in the source the same server is found.
func TestTheRelaySweepSendsNothingOverAnUnverifiedTLSConnectionP7(t *testing.T) {
	var requests atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path != "/mcp" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"vault-tools","version":"3.0.0"}}}`)
	}))
	defer srv.Close()
	target := strings.TrimPrefix(srv.URL, "https://")
	intent := DiscoveryScanIntent{ID: "run-2", SourceID: "source-2", Execution: segmentscan.ExecutionRelay, Mode: DiscoveryModeTLS,
		RequiredAgentRole: segmentscan.RequiredRoleNetwork, Targets: []string{target}, AllowLoopback: true,
		MCP: true, MCPSchemes: []string{"https"}}
	report, err := Sweep(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.MCPFindings) != 0 || requests.Load() != 0 {
		t.Fatalf("an unverified server was sent the probe: findings=%+v requests=%d", report.MCPFindings, requests.Load())
	}
	intent.MCPCAPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	report, err = Sweep(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.MCPFindings) != 1 || report.MCPFindings[0].Observation.ServerName != "vault-tools" ||
		report.MCPFindings[0].Observation.Endpoint != srv.URL+"/mcp" {
		t.Fatalf("with the operator CA = %+v", report.MCPFindings)
	}
	if err := segmentscan.ValidateReport(intent, report); err != nil {
		t.Fatalf("the sweep's report does not validate: %v", err)
	}
}
