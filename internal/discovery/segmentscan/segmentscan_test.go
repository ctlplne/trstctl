// SPDX-License-Identifier: BUSL-1.1

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

func TestValidateReportBindsTargetResultsToTheCommandAndCounts(t *testing.T) {
	intent := segmentscan.Intent{
		Execution: segmentscan.ExecutionRelay, RequiredAgentRole: segmentscan.RequiredRoleNetwork, Mode: segmentscan.ModeTLS,
		Targets: []string{"10.20.0.1:443", "10.20.0.2:443", "10.20.0.3:5432"},
	}
	good := segmentscan.Report{
		Mode: segmentscan.ModeTLS, Targets: 3, Discovered: 1, Failed: 1, Blocked: 1,
		Findings: []segmentscan.Finding{{Address: "10.20.0.1:443", Fingerprint: "sha256:aa"}},
		TargetResults: []segmentscan.TargetResult{
			{Target: "10.20.0.1:443", Status: segmentscan.TargetSucceeded},
			{Target: "10.20.0.2:443", Status: segmentscan.TargetBlocked, Error: "reserved IP blocked by SSRF guard"},
			{Target: "10.20.0.3:5432", Status: segmentscan.TargetFailed, Error: "tlsprobe: handshake 10.20.0.3:5432: EOF"},
		},
	}
	if err := segmentscan.ValidateReport(intent, good); err != nil {
		t.Fatalf("valid per-target report rejected: %v", err)
	}
	status, reason := segmentscan.Status(good)
	if status != "partial" {
		t.Fatalf("status = %q, want partial", status)
	}
	for _, want := range []string{"10.20.0.3:5432 failed (tlsprobe: handshake 10.20.0.3:5432: EOF)", "10.20.0.2:443 blocked"} {
		if !strings.Contains(reason, want) {
			t.Fatalf("reason %q does not name %q", reason, want)
		}
	}
	if strings.Contains(reason, "10.20.0.1:443") {
		t.Fatalf("reason %q names a target that succeeded", reason)
	}

	bad := []struct {
		name   string
		mutate func(r *segmentscan.Report)
	}{
		{"unassigned target", func(r *segmentscan.Report) { r.TargetResults[0].Target = "10.99.0.1:443" }},
		{"repeated target", func(r *segmentscan.Report) { r.TargetResults[1].Target = "10.20.0.1:443" }},
		{"unknown status", func(r *segmentscan.Report) { r.TargetResults[2].Status = "exploded" }},
		{"success with error", func(r *segmentscan.Report) { r.TargetResults[0].Error = "but also broken" }},
		{"counts disagree", func(r *segmentscan.Report) { r.TargetResults[2].Status = segmentscan.TargetBlocked }},
		{"partial coverage", func(r *segmentscan.Report) { r.TargetResults = r.TargetResults[:2] }},
	}
	for _, tc := range bad {
		r := good
		r.TargetResults = append([]segmentscan.TargetResult(nil), good.TargetResults...)
		tc.mutate(&r)
		if err := segmentscan.ValidateReport(intent, r); err == nil {
			t.Errorf("%s: report accepted", tc.name)
		}
	}

	legacy := good
	legacy.TargetResults = nil
	if err := segmentscan.ValidateReport(intent, legacy); err != nil {
		t.Fatalf("report without per-target outcomes (older relay) rejected: %v", err)
	}
	if _, reason := segmentscan.Status(legacy); strings.Contains(reason, ":") {
		t.Fatalf("legacy reason %q should not pretend to name targets", reason)
	}
}
