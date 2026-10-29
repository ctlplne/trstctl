// SPDX-License-Identifier: LicenseRef-trstctl-EE
package governance

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/discovery/adcs"
	"trstctl.com/trstctl/internal/projections"
)

func TestADCSComplianceEvidencePreservesPartialEndpointPage(t *testing.T) {
	options := &adcs.EndpointProbeOptions{Enabled: true, DNSSuffixes: []string{"corp.example"}}
	intent := adcs.InventoryIntent{EndpointProbe: options}
	inventory := adcs.Inventory{Templates: []adcs.Template{{Name: "User", EKUs: []string{adcs.EKUClientAuth}}}}
	for index := range 7 {
		inventory.EnrollmentServices = append(inventory.EnrollmentServices, adcs.EnrollmentService{Name: fmt.Sprintf("CA%02d", index), DNSName: fmt.Sprintf("ca%02d.corp.example", index), AgentRestrictions: adcs.EnrollmentAgentRestrictions{State: adcs.EvidenceUnobserved, Source: "fixture"}})
	}
	page, err := adcs.PlanEnrollmentEndpointProbes(intent, inventory.EnrollmentServices)
	if err != nil {
		t.Fatal(err)
	}
	inventory.EndpointProbePage = &page
	for index := range inventory.EnrollmentServices {
		service := &inventory.EnrollmentServices[index]
		service.EndpointProbe = page.ServiceCoverage(service.Name)
		for _, target := range page.Targets {
			if target.EnrollmentService == service.Name {
				service.Endpoints = append(service.Endpoints, adcs.EnrollmentEndpoint{Kind: target.Kind, URL: target.URL, Source: target.Source, State: adcs.EndpointNotChecked, NotCheckedReason: "deadline_or_cancellation", ExtendedProtection: adcs.EvidenceUnobserved})
			}
		}
	}
	observed := adcs.InventoryObserved{RunID: "run", SourceID: "source", Domain: "CORP", AgentID: "agent", AgentName: "relay", DirectoryVerified: true, EndpointProbe: options, EndpointProbePage: &page, Templates: inventory.Templates, EnrollmentServices: inventory.EnrollmentServices, Findings: adcs.Findings(inventory)}
	if err := observed.Validate(); err != nil {
		t.Fatal(err)
	}
	wire, _ := json.Marshal(observed)
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	evidence, err := buildADCSComplianceEvidence("tenant", []audit.Record{{TenantID: "tenant", ID: "event", Type: projections.EventADCSInventoryObserved, Time: now, Data: wire}}, EvidenceWindow{From: now.Add(-time.Hour), Through: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence.Observations) != 1 {
		t.Fatal("partial observation disappeared")
	}
	facts := evidence.Observations[0]
	if facts.Inventory.EndpointProbePage == nil || facts.Inventory.EndpointProbePage.Complete || facts.Inventory.EndpointProbePage.TotalTargets != 28 || facts.Inventory.EndpointProbePage.NextOffset != 24 {
		t.Fatal("compliance export lost its partial-page boundary")
	}
	if facts.Inventory.EnrollmentServices[6].EndpointProbe.State != "not_in_page" {
		t.Fatal("export invented last-service assessment")
	}
	found := false
	for _, finding := range facts.Findings {
		if finding.ID == "ADCS-ENDPOINT-PROBE-INCOMPLETE" {
			found = true
		}
	}
	if !found {
		t.Fatal("partial compliance evidence appears clean")
	}
}
