// SPDX-License-Identifier: MPL-2.0

package segmentscan_test

import (
	"encoding/json"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/discovery/segmentscan"
)

func TestResolveProducesStableBoundedRelayCommand(t *testing.T) {
	intent, err := segmentscan.Resolve("network", json.RawMessage(`{
		"targets":["192.0.2.2:443","192.0.2.1:443","192.0.2.2:443"],
		"segment":"dmz","relay_agent_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if intent.Execution != segmentscan.ExecutionRelay || intent.Mode != segmentscan.ModeTLS ||
		intent.RequiredAgentRole != segmentscan.RequiredRoleNetwork || intent.Segment != "dmz" {
		t.Fatalf("binding = %+v", intent)
	}
	if got := strings.Join(intent.Targets, ","); got != "192.0.2.1:443,192.0.2.2:443" {
		t.Fatalf("stable targets = %q", got)
	}
}

func TestResolveRejectsUnboundAndOversizedCommands(t *testing.T) {
	if _, err := segmentscan.Resolve("ssh", json.RawMessage(`{"targets":["192.0.2.1:22"]}`)); err == nil {
		t.Fatal("unbound segment was accepted")
	}
	if _, err := segmentscan.Resolve("network", json.RawMessage(`{"segment":"dmz","cidr":"10.0.0.0/8","ports":[443]}`)); err == nil {
		t.Fatal("oversized CIDR command was accepted")
	}
}

func TestValidateReportBindsModeTargetsCountsAndMetadata(t *testing.T) {
	intent := segmentscan.Intent{
		Execution: segmentscan.ExecutionRelay, Mode: segmentscan.ModeTLS,
		Targets: []string{"192.0.2.1:443"}, Segment: "dmz",
		RequiredAgentRole: segmentscan.RequiredRoleNetwork,
	}
	valid := segmentscan.Report{
		Mode: segmentscan.ModeTLS, Targets: 1, Discovered: 1,
		Findings: []segmentscan.Finding{{Address: "192.0.2.1:443", Fingerprint: strings.Repeat("a", 64)}},
	}
	if err := segmentscan.ValidateReport(intent, valid); err != nil {
		t.Fatal(err)
	}
	bad := valid
	bad.Findings = append(bad.Findings, segmentscan.Finding{Address: "192.0.2.99:443", Fingerprint: "other"})
	bad.Discovered = 2
	if err := segmentscan.ValidateReport(intent, bad); err == nil {
		t.Fatal("unassigned finding was accepted")
	}
	bad = valid
	bad.Mode = segmentscan.ModeSSH
	if err := segmentscan.ValidateReport(intent, bad); err == nil {
		t.Fatal("wrong-mode report was accepted")
	}
	bad = valid
	bad.Failed = 1
	if err := segmentscan.ValidateReport(intent, bad); err == nil {
		t.Fatal("incoherent outcome counts were accepted")
	}
}
