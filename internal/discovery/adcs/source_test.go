// SPDX-License-Identifier: MPL-2.0

package adcs_test

import (
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/discovery/adcs"
)

func TestEnrollmentEndpointIntentIsStrictAndCanonicalAUD37(t *testing.T) {
	raw := json.RawMessage(`{
		"url":"ldaps://dc.corp.example",
		"configuration_dn":"CN=Configuration,DC=corp,DC=example",
		"bind_dn":"CN=relay,DC=corp,DC=example",
		"password_ref":"secret://adcs/bind",
		"allow_private_endpoint":true,
		"private_egress_cidrs":["10.42.8.0/24"],
		"enrollment_endpoints":[
			{"enrollment_service":"CORP-CA","kind":"web_enrollment","url":"https://ca.corp.example/certsrv/"},
			{"enrollment_service":"CORP-CA","kind":"ndes","url":"https://ca.corp.example/certsrv/mscep/"}
		]
	}`)
	intent, err := adcs.ResolveInventoryIntent(raw)
	if err != nil {
		t.Fatalf("resolve intent: %v", err)
	}
	if len(intent.EnrollmentEndpoints) != 2 || intent.EnrollmentEndpoints[0].Kind != adcs.EndpointNDES || intent.EnrollmentEndpoints[1].Kind != adcs.EndpointWebEnrollment {
		t.Fatalf("canonical endpoints = %+v", intent.EnrollmentEndpoints)
	}
	if !intent.AllowPrivateEndpoint || len(intent.PrivateEgressCIDRs) != 1 || intent.PrivateEgressCIDRs[0] != "10.42.8.0/24" {
		t.Fatalf("private egress boundary = allow %t, CIDRs %v", intent.AllowPrivateEndpoint, intent.PrivateEgressCIDRs)
	}
	if prefixes, err := intent.PrivateEgressPrefixes(); err != nil || len(prefixes) != 1 || prefixes[0].String() != "10.42.8.0/24" {
		t.Fatalf("private egress prefixes = %v, %v", prefixes, err)
	}

	bad := json.RawMessage(`{"url":"ldaps://dc.corp.example","configuration_dn":"CN=Configuration,DC=x","bind_dn":"CN=relay","password_ref":"secret://bind","enrollment_endpoints":[{"enrollment_service":"CA","kind":"ndes","url":"https://user:pass@ca.example/certsrv/mscep/"}]}`)
	if _, err := adcs.ResolveInventoryIntent(bad); err == nil {
		t.Fatal("endpoint URL credentials were accepted")
	}

	badBoundaries := []json.RawMessage{
		json.RawMessage(`{"url":"ldaps://dc.corp.example","configuration_dn":"CN=Configuration,DC=x","bind_dn":"CN=relay","password_ref":"secret://bind","private_egress_cidrs":["10.0.0.0/8"],"enrollment_endpoints":[{"enrollment_service":"CA","kind":"ndes","url":"https://ca.example/certsrv/mscep/"}]}`),
		json.RawMessage(`{"url":"ldaps://dc.corp.example","configuration_dn":"CN=Configuration,DC=x","bind_dn":"CN=relay","password_ref":"secret://bind","allow_private_endpoint":true,"enrollment_endpoints":[{"enrollment_service":"CA","kind":"ndes","url":"https://ca.example/certsrv/mscep/"}]}`),
		json.RawMessage(`{"url":"ldaps://dc.corp.example","configuration_dn":"CN=Configuration,DC=x","bind_dn":"CN=relay","password_ref":"secret://bind","allow_private_endpoint":true,"private_egress_cidrs":["169.254.0.0/16"],"enrollment_endpoints":[{"enrollment_service":"CA","kind":"ndes","url":"https://ca.example/certsrv/mscep/"}]}`),
	}
	for i, raw := range badBoundaries {
		if _, err := adcs.ResolveInventoryIntent(raw); err == nil {
			t.Fatalf("unsafe private egress boundary %d was accepted", i)
		}
	}
}

func TestInventoryReportCannotInventOrOmitPostureAUD37(t *testing.T) {
	intent := adcs.InventoryIntent{
		ID: "run", SourceID: "source", JobKind: adcs.JobKind, Execution: adcs.ExecutionRelay,
		RequiredAgentRole:   adcs.RequiredRoleNetwork,
		EnrollmentEndpoints: []adcs.EnrollmentEndpointTarget{{EnrollmentService: "CORP-CA", Kind: adcs.EndpointNDESAdmin, URL: "https://ca.example/certsrv/mscep_admin/"}},
	}
	inv := adcs.Inventory{
		Templates: []adcs.Template{{Name: "User", EKUs: []string{adcs.EKUClientAuth}, ExportableKey: true}},
		EnrollmentServices: []adcs.EnrollmentService{{
			Name:              "CORP-CA",
			AgentRestrictions: adcs.EnrollmentAgentRestrictions{State: adcs.EvidenceUnobserved, Source: "requires_windows_relay"},
			Endpoints:         []adcs.EnrollmentEndpoint{{Kind: adcs.EndpointNDESAdmin, URL: "https://ca.example/certsrv/mscep_admin/", State: adcs.EndpointAuthenticationNeeded, HTTPStatus: 401, TLSVerified: true, ExtendedProtection: adcs.EvidenceUnobserved}},
		}},
	}
	report := adcs.InventoryReport{Status: "succeeded", DirectoryVerified: true, Inventory: inv, Findings: adcs.Findings(inv)}
	if err := adcs.ValidateInventoryReport(intent, report); err != nil {
		t.Fatalf("valid report rejected: %v", err)
	}
	report.Findings = nil
	if err := adcs.ValidateInventoryReport(intent, report); err == nil {
		t.Fatal("report omitted recomputed findings")
	}
	report.Findings = adcs.Findings(inv)
	report.Inventory.EnrollmentServices[0].Endpoints = nil
	if err := adcs.ValidateInventoryReport(intent, report); err == nil {
		t.Fatal("report omitted configured live endpoint")
	}
}
