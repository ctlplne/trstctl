// SPDX-License-Identifier: BUSL-1.1

package segmentscan

import (
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/discovery/mcpprobe"
)

// TestNetworkSourcesTurnOnTheMCPProbeExplicitlyP7: a network source probes for MCP
// endpoints only when it says mcp: true (https alone by default); mcp_schemes
// without mcp, an unknown scheme, and MCP on an SSH source are refused.
func TestNetworkSourcesTurnOnTheMCPProbeExplicitlyP7(t *testing.T) {
	resolve := func(kind, cfg string) (Intent, error) { return Resolve(kind, json.RawMessage(cfg)) }
	if in, err := resolve("network", `{"targets":["10.42.0.10:443"],"segment":"lab"}`); err != nil || in.MCP || in.MCPSchemes != nil {
		t.Fatalf("a plain network source = %+v, %v", in, err)
	}
	if in, err := resolve("network", `{"targets":["10.42.0.10:443"],"segment":"lab","mcp":true}`); err != nil || !in.MCP || strings.Join(in.MCPSchemes, ",") != "https" {
		t.Fatalf("mcp on = %+v, %v", in, err)
	}
	if in, err := resolve("network", `{"targets":["10.42.0.10:8080"],"segment":"lab","mcp":true,"mcp_schemes":["HTTPS","http","https"]}`); err != nil ||
		strings.Join(in.MCPSchemes, ",") != "https,http" {
		t.Fatalf("schemes = %+v, %v", in, err)
	}
	for name, cfg := range map[string]string{
		"schemes without mcp": `{"targets":["10.42.0.10:443"],"segment":"lab","mcp_schemes":["https"]}`,
		"unknown scheme":      `{"targets":["10.42.0.10:443"],"segment":"lab","mcp":true,"mcp_schemes":["ftp"]}`,
	} {
		if _, err := resolve("network", cfg); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := resolve("ssh", `{"targets":["10.42.0.10:22"],"segment":"lab","mcp":true}`); err == nil {
		t.Error("an SSH source turned on the MCP probe")
	}
}

// TestReportsCarryOnlyMCPFindingsTheCommandAskedForP7: an MCP finding must name an
// assigned target once, sit on that target's host and port under a scheme the
// command allows, use a known transport and authorization, and carry the
// fingerprint of exactly what it observed; a sweep that did not ask for MCP, or a
// dry run, carries none.
func TestReportsCarryOnlyMCPFindingsTheCommandAskedForP7(t *testing.T) {
	intent := Intent{Execution: ExecutionRelay, Mode: ModeTLS, RequiredAgentRole: RequiredRoleNetwork,
		Targets: []string{"10.42.0.10:8080", "10.42.0.11:8080"}, MCP: true, MCPSchemes: []string{"http"}}
	obs := mcpprobe.Observation{Endpoint: "http://10.42.0.10:8080/mcp", Transport: "streamable-http", Auth: mcpprobe.AuthNone,
		ProtocolVersion: "2025-06-18", ServerName: "issues", ServerVersion: "1.0.0"}
	good := MCPFinding{Target: "10.42.0.10:8080", Fingerprint: obs.Fingerprint(), Observation: obs}
	report := func(findings ...MCPFinding) Report {
		return Report{Mode: ModeTLS, Findings: []Finding{}, Targets: 2, Failed: 2, MCPFindings: findings}
	}
	if err := ValidateReport(intent, report(good)); err != nil {
		t.Fatalf("a valid MCP finding was refused: %v", err)
	}
	mutate := func(f func(*MCPFinding)) MCPFinding {
		c := good
		c.Observation.AuthorizationServers = append([]string(nil), good.Observation.AuthorizationServers...)
		f(&c)
		return c
	}
	for name, bad := range map[string]Report{
		"unassigned target": report(mutate(func(f *MCPFinding) { f.Target = "10.42.0.99:8080" })),
		"repeated target":   report(good, good),
		"endpoint elsewhere": report(mutate(func(f *MCPFinding) {
			f.Observation.Endpoint = "http://10.42.0.11:8080/mcp"
			f.Fingerprint = f.Observation.Fingerprint()
		})),
		"scheme not allowed": report(mutate(func(f *MCPFinding) {
			f.Observation.Endpoint = "https://10.42.0.10:8080/mcp"
			f.Fingerprint = f.Observation.Fingerprint()
		})),
		"unknown auth": report(mutate(func(f *MCPFinding) {
			f.Observation.Auth = "maybe"
			f.Fingerprint = f.Observation.Fingerprint()
		})),
		"fingerprint not over the observation": report(mutate(func(f *MCPFinding) { f.Observation.ServerVersion = "9.9.9" })),
	} {
		if err := ValidateReport(intent, bad); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	notAsked := intent
	notAsked.MCP, notAsked.MCPSchemes = false, nil
	if err := ValidateReport(notAsked, report(good)); err == nil {
		t.Error("MCP findings the command did not ask for were accepted")
	}
	dry := intent
	dry.DryRun = true
	if err := ValidateReport(dry, Report{Mode: ModeTLS, Findings: []Finding{}, Targets: 2, Failed: 2, MCPFindings: []MCPFinding{good}}); err == nil {
		t.Error("a dry run carried MCP findings")
	}
}

// TestAnMCPCABundleNeedsTheProbeAndACertificateP7: a source's CA bundle for the
// MCP probe is carried to the relay only with mcp on, bounded, and holding at least
// one certificate.
func TestAnMCPCABundleNeedsTheProbeAndACertificateP7(t *testing.T) {
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	der, err := crypto.SelfSignedCACert(key, "Internal MCP CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	bundle := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	cfg := func(extra map[string]any) json.RawMessage {
		m := map[string]any{"targets": []string{"10.42.0.10:443"}, "segment": "lab"}
		for k, v := range extra {
			m[k] = v
		}
		raw, _ := json.Marshal(m)
		return raw
	}
	in, err := Resolve("network", cfg(map[string]any{"mcp": true, "mcp_ca_pem": bundle}))
	if err != nil || in.MCPCAPEM != bundle {
		t.Fatalf("a CA bundle = %v", err)
	}
	for name, extra := range map[string]map[string]any{
		"without mcp":    {"mcp_ca_pem": bundle},
		"no certificate": {"mcp": true, "mcp_ca_pem": "-----BEGIN NOTHING-----\nAA==\n-----END NOTHING-----\n"},
		"too large":      {"mcp": true, "mcp_ca_pem": strings.Repeat(bundle, 64<<10/len(bundle)+1)},
	} {
		if _, err := Resolve("network", cfg(extra)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
