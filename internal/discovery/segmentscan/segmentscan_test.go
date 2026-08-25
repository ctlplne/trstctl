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

func TestResolveNormalizesRangesAndAppliesExactExclusions(t *testing.T) {
	intent, err := segmentscan.Resolve("network", json.RawMessage(`{
		"targets":["api.example.test:443","api.example.test:8443"],
		"ranges":["192.0.2.10-192.0.2.12"],
		"ports":[443,8443],
		"exclude_targets":["api.example.test:8443","192.0.2.11"],
		"exclude_cidrs":["192.0.2.12/32"],
		"exclude_ports":[8443],
		"segment":"edge"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(intent.Targets, ","); got != "192.0.2.10:443,api.example.test:443" {
		t.Fatalf("normalized included targets = %q", got)
	}
	if intent.ExcludedTargets != 6 || len(intent.AppliedExclusions) == 0 {
		t.Fatalf("exclusion evidence = %+v", intent)
	}
}

func TestResolveRejectsUnboundedRangeAndInvalidExclusion(t *testing.T) {
	if _, err := segmentscan.Resolve("network", json.RawMessage(`{
		"ranges":["192.0.2.1-192.0.42.1"],"ports":[443],"segment":"edge"
	}`)); err == nil || !strings.Contains(err.Error(), "maximum") {
		t.Fatalf("oversized explicit range error = %v", err)
	}
	if _, err := segmentscan.Resolve("network", json.RawMessage(`{
		"targets":["192.0.2.1:443"],"exclude_cidrs":["not-a-cidr"],"segment":"edge"
	}`)); err == nil || !strings.Contains(err.Error(), "exclude_cidrs") {
		t.Fatalf("invalid exclusion error = %v", err)
	}
}

func TestValidateDeclaredSegmentContainsEveryNormalizedTarget(t *testing.T) {
	intent, err := segmentscan.Resolve("network", json.RawMessage(`{
		"targets":["api.example.test:443"],"cidrs":["192.0.2.0/30"],"ports":[443],"segment":"edge"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := segmentscan.ValidateDeclaredSegment(intent, []string{"api.example.test", "192.0.2.0/30"}); err != nil {
		t.Fatal(err)
	}
	if err := segmentscan.ValidateDeclaredSegment(intent, []string{"api.example.test", "198.51.100.0/24"}); err == nil || !strings.Contains(err.Error(), "outside declared segment") {
		t.Fatalf("out-of-scope target error = %v", err)
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
